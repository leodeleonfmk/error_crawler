"""Async same-site crawler that reports broken links and page-loading errors.

Usable standalone (see cli.py) or from a web layer via the on_progress,
cancel_event and url_validator hooks.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, Union
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

from app.models import (
    CrawlOptions,
    CrawlResult,
    CrawlStats,
    Issue,
    IssueType,
    LinkKind,
    RedirectHop,
)

log = logging.getLogger(__name__)

ProgressCallback = Callable[[CrawlStats], Union[None, Awaitable[None]]]
UrlValidator = Callable[[str], Union[bool, Awaitable[bool]]]

DEFAULT_PORTS = {"http": 80, "https": 443}
TRACKING_PARAMS = {"gclid", "fbclid", "msclkid", "mc_cid", "mc_eid"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_BODY_BYTES = 5 * 1024 * 1024  # don't hold huge pages in 512 MB of RAM
MAX_LINK_TEXT = 200


# --- URL helpers -------------------------------------------------------------


def normalize_url(url: str, base: Optional[str] = None) -> Optional[str]:
    """Resolve and clean a URL, or return None if it isn't crawlable http(s).

    Resolves relative URLs against `base`, strips the fragment, user info and
    default port, lowercases scheme and host, and drops tracking parameters.
    """
    try:
        url = urljoin(base, url.strip()) if base is not None else url.strip()
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        return None  # mailto:, tel:, javascript:, data:, ftp:, ...
    host = (parts.hostname or "").rstrip(".")  # .hostname is already lowercase
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"  # IPv6
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", _strip_tracking(parts.query), ""))


def _strip_tracking(query: str) -> str:
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if not _is_tracking(k)]
    return query if len(kept) == len(pairs) else urlencode(kept)


def _is_tracking(param: str) -> bool:
    param = param.lower()
    return param.startswith("utm_") or param in TRACKING_PARAMS


def site_host(host: str) -> str:
    """Host with any leading 'www.' removed, so www and non-www compare equal."""
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def is_same_site(url: str, root_host: str) -> bool:
    host = urlsplit(url).hostname or ""
    return bool(host) and site_host(host) == site_host(root_host)


def url_key(url: str) -> str:
    """Dedupe key: treats www/non-www and trailing-slash variants as one URL."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme, site_host(parts.netloc), path, parts.query, ""))


# --- HTML parsing ------------------------------------------------------------


@dataclass
class FoundLink:
    url: str
    text: str
    tag: str  # "a" or "img"


def extract_links(
    html: Union[str, bytes],
    base_url: str,
    include_images: bool = False,
    encoding: Optional[str] = None,
) -> list[FoundLink]:
    """Return normalized http(s) links from <a href> (and <img src> if asked)."""
    soup = BeautifulSoup(html, "html.parser", from_encoding=encoding if isinstance(html, bytes) else None)
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_url = urljoin(base_url, base_tag["href"])

    links = []
    for a in soup.find_all("a", href=True):
        url = normalize_url(a["href"], base_url)
        if url:
            links.append(FoundLink(url, _link_text(a), "a"))
    if include_images:
        for img in soup.find_all("img", src=True):
            url = normalize_url(img["src"], base_url)
            if url:
                links.append(FoundLink(url, _clean(img.get("alt", "")), "img"))
    return links


def _link_text(a) -> str:
    text = _clean(a.get_text(" ", strip=True))
    if not text:
        img = a.find("img", alt=True)
        text = _clean(img["alt"] if img else a.get("aria-label") or a.get("title") or "")
    return text


def _clean(text: str) -> str:
    return " ".join(text.split())[:MAX_LINK_TEXT]


# --- Error classification ----------------------------------------------------


def classify_status(status_code: int) -> Optional[IssueType]:
    if 400 <= status_code < 500:
        return IssueType.HTTP_4XX
    if status_code >= 500:
        return IssueType.HTTP_5XX
    return None


def classify_exception(exc: BaseException) -> IssueType:
    if isinstance(exc, httpx.TimeoutException):
        return IssueType.TIMEOUT
    if isinstance(exc, httpx.TooManyRedirects):
        return IssueType.TOO_MANY_REDIRECTS
    # httpx wraps the low-level error; walk the cause chain to find it.
    seen = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, socket.gaierror):
            return IssueType.DNS_ERROR
        if isinstance(cur, ssl.SSLError):
            return IssueType.SSL_ERROR
        cur = cur.__cause__ or cur.__context__
    # Fall back to message matching (backends don't always chain the cause).
    msg = str(exc).lower()
    if any(s in msg for s in ("getaddrinfo", "name or service not known", "nodename nor servname", "name resolution")):
        return IssueType.DNS_ERROR
    if "ssl" in msg or "certificate" in msg:
        return IssueType.SSL_ERROR
    return IssueType.CONNECTION_ERROR


# --- Crawler -----------------------------------------------------------------


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: Optional[int] = None
    redirects: list[RedirectHop] = field(default_factory=list)  # redirect responses only
    elapsed_ms: float = 0.0
    content_type: str = ""
    body: Optional[bytes] = None
    encoding: Optional[str] = None
    issue_type: Optional[IssueType] = None  # set for transport errors / blocked
    error: str = ""


@dataclass
class _Task:
    url: str
    key: str
    kind: LinkKind


@dataclass
class _Occurrence:
    found_on: Optional[str]
    text: str


class Crawler:
    def __init__(
        self,
        start_url: str,
        options: Optional[CrawlOptions] = None,
        *,
        on_progress: Optional[ProgressCallback] = None,
        cancel_event: Optional[asyncio.Event] = None,
        url_validator: Optional[UrlValidator] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if "://" not in start_url:
            start_url = "https://" + start_url
        normalized = normalize_url(start_url)
        if not normalized:
            raise ValueError(f"Not a crawlable http(s) URL: {start_url!r}")
        self.start_url = normalized
        self.root_host = urlsplit(normalized).hostname or ""
        self.options = options or CrawlOptions()
        self.on_progress = on_progress
        self.cancel_event = cancel_event
        self.url_validator = url_validator
        self._transport = transport

        self.issues: list[Issue] = []
        self.pages_crawled = 0
        self.links_checked = 0
        self.errors_found = 0
        self.warnings_found = 0
        self.robots_skipped = 0
        self.page_limit_reached = False
        self._pages_queued = 0
        self._current_url = ""
        # key -> issue template (None = OK) once checked; key -> occurrences while pending.
        self._outcomes: dict[str, Optional[Issue]] = {}
        self._pending: dict[str, list[_Occurrence]] = {}
        self._robots: Optional[RobotFileParser] = None

    @property
    def cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()

    async def run(self) -> CrawlResult:
        started = time.monotonic()
        self._queue: asyncio.Queue[_Task] = asyncio.Queue()
        self._sem = asyncio.Semaphore(self.options.concurrency)
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=self.options.timeout,
            headers={"User-Agent": self.options.user_agent},
            follow_redirects=False,  # followed manually to record chains and validate each hop
        ) as client:
            self._client = client
            if not self.cancelled:
                await self._load_robots()
            self._discover(FoundLink(self.start_url, "", "a"), found_on=None)
            workers = [asyncio.create_task(self._worker()) for _ in range(self.options.concurrency)]
            waiters = [asyncio.ensure_future(self._queue.join())]
            if self.cancel_event is not None:
                waiters.append(asyncio.ensure_future(self.cancel_event.wait()))
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            for task in workers + waiters:
                task.cancel()
            await asyncio.gather(*workers, *waiters, return_exceptions=True)

        return CrawlResult(
            start_url=self.start_url,
            pages_crawled=self.pages_crawled,
            links_checked=self.links_checked,
            errors_found=self.errors_found,
            warnings_found=self.warnings_found,
            duration_s=round(time.monotonic() - started, 2),
            cancelled=self.cancelled,
            page_limit_reached=self.page_limit_reached,
            robots_skipped=self.robots_skipped,
            issues=list(self.issues),
        )

    # --- discovery / bookkeeping ---

    def _discover(self, link: FoundLink, found_on: Optional[str]) -> None:
        same_site = is_same_site(link.url, self.root_host)
        if link.tag == "img":
            kind = LinkKind.IMAGE
        elif same_site:
            kind = LinkKind.PAGE
        else:
            kind = LinkKind.EXTERNAL
        if not same_site and not self.options.check_external:
            return

        key = url_key(link.url)
        occurrence = _Occurrence(found_on, link.text)
        if key in self._outcomes:
            self._record(self._outcomes[key], occurrence)
            return
        if key in self._pending:
            self._pending[key].append(occurrence)
            return

        if kind == LinkKind.PAGE:
            if self._robots is not None and not self._robots.can_fetch(self.options.user_agent, link.url):
                self.robots_skipped += 1
                self._outcomes[key] = None
                return
            if self._pages_queued >= self.options.max_pages:
                self.page_limit_reached = True
                return
            self._pages_queued += 1

        self._pending[key] = [occurrence]
        self._queue.put_nowait(_Task(link.url, key, kind))

    def _resolve(self, key: str, outcome: Optional[Issue]) -> None:
        self._outcomes[key] = outcome
        for occurrence in self._pending.pop(key, []):
            self._record(outcome, occurrence)

    def _record(self, outcome: Optional[Issue], occurrence: _Occurrence) -> None:
        if outcome is None:
            return
        issue = Issue(**{**outcome.__dict__, "found_on": occurrence.found_on, "link_text": occurrence.text})
        self.issues.append(issue)
        if issue.is_warning:
            self.warnings_found += 1
        else:
            self.errors_found += 1

    # --- workers ---

    async def _worker(self) -> None:
        while True:
            task = await self._queue.get()
            try:
                if not self.cancelled:
                    await self._process(task)
                    await self._report_progress()
            except Exception:
                log.exception("Unexpected error processing %s", task.url)
                self._resolve(task.key, None)
            finally:
                self._queue.task_done()

    async def _process(self, task: _Task) -> None:
        self._current_url = task.url
        if task.kind == LinkKind.PAGE:
            result = await self._fetch(task.url, "GET", read_body=True)
            self.pages_crawled += 1
            if result.body is not None and self._claim_final_url(task, result.final_url):
                links = extract_links(result.body, result.final_url, self.options.check_images, result.encoding)
                for link in links:
                    self._discover(link, found_on=result.final_url)
        else:
            result = await self._fetch(task.url, "HEAD")
            if result.status_code in (405, 501):
                result = await self._fetch(task.url, "GET")
        self.links_checked += 1
        self._resolve(task.key, self._to_issue(result, task.kind))

    def _claim_final_url(self, task: _Task, final_url: str) -> bool:
        """After a redirect, mark the target as seen. False if it was already crawled."""
        if not is_same_site(final_url, self.root_host):
            return False  # redirected off-site; don't crawl someone else's page
        final_key = url_key(final_url)
        if final_key == task.key:
            return True
        if final_key in self._outcomes or final_key in self._pending:
            return False
        self._outcomes[final_key] = None
        return True

    async def _report_progress(self) -> None:
        if self.on_progress is None:
            return
        stats = CrawlStats(
            pages_crawled=self.pages_crawled,
            links_checked=self.links_checked,
            errors_found=self.errors_found,
            warnings_found=self.warnings_found,
            queued=self._queue.qsize(),
            current_url=self._current_url,
            latest_issue=self.issues[-1] if self.issues else None,
        )
        ret = self.on_progress(stats)
        if inspect.isawaitable(ret):
            await ret

    # --- HTTP ---

    async def _is_allowed(self, url: str) -> bool:
        if self.url_validator is None:
            return True
        try:
            ok = self.url_validator(url)
            if inspect.isawaitable(ok):
                ok = await ok
            return bool(ok)
        except Exception:
            log.exception("url_validator raised for %s; blocking", url)
            return False  # fail closed: the validator is a security hook

    async def _fetch(self, url: str, method: str, read_body: bool = False, html_only: bool = True) -> FetchResult:
        """Request `url`, following redirects manually (validating each hop)."""
        result = FetchResult(url=url, final_url=url)
        current = url
        elapsed = 0.0  # request time only, excluding semaphore waits and the delay
        try:
            while True:
                if not await self._is_allowed(current):
                    result.issue_type = IssueType.BLOCKED
                    result.error = "Blocked by URL validator"
                    return result
                async with self._sem:
                    started = time.perf_counter()
                    try:
                        async with self._client.stream(method, current) as resp:
                            location = resp.headers.get("location")
                            if resp.status_code in REDIRECT_STATUSES and location:
                                result.redirects.append(RedirectHop(current, resp.status_code))
                                if len(result.redirects) > self.options.max_redirects:
                                    result.issue_type = IssueType.TOO_MANY_REDIRECTS
                                    result.error = f"More than {self.options.max_redirects} redirects"
                                    return result
                                current = normalize_url(location, current) or urljoin(current, location)
                                result.final_url = current
                                continue
                            result.status_code = resp.status_code
                            result.content_type = resp.headers.get("content-type", "")
                            result.encoding = resp.charset_encoding
                            wants_body = read_body and resp.is_success
                            if html_only:
                                wants_body = wants_body and "html" in result.content_type.lower()
                            if wants_body:
                                result.body = await _read_capped(resp)
                            return result
                    finally:
                        elapsed += time.perf_counter() - started
                        if self.options.delay:
                            await asyncio.sleep(self.options.delay)
        except httpx.HTTPError as exc:
            result.issue_type = classify_exception(exc)
            result.error = str(exc) or type(exc).__name__
            return result
        finally:
            result.elapsed_ms = round(elapsed * 1000, 1)

    def _to_issue(self, result: FetchResult, kind: LinkKind) -> Optional[Issue]:
        issue_type = result.issue_type
        error = result.error
        if issue_type is None and result.status_code is not None:
            issue_type = classify_status(result.status_code)
            if issue_type:
                error = f"{result.status_code} {httpx.codes.get_reason_phrase(result.status_code)}".strip()
        if issue_type is None and len(result.redirects) >= 2:
            issue_type = IssueType.REDIRECT_CHAIN
            error = f"{len(result.redirects)} redirects before reaching the final URL"
        if issue_type is None:
            return None
        chain = list(result.redirects)
        if chain:
            chain.append(RedirectHop(result.final_url, result.status_code))
        return Issue(
            url=result.url,
            issue_type=issue_type,
            kind=kind,
            found_on=None,
            status_code=result.status_code,
            error=error,
            response_time_ms=result.elapsed_ms,
            redirect_chain=chain,
        )

    async def _load_robots(self) -> None:
        """Fetch robots.txt for the start host. Missing or unreachable = allow all."""
        parts = urlsplit(self.start_url)
        robots_url = urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))
        result = await self._fetch(robots_url, "GET", read_body=True, html_only=False)
        if result.body is None:
            return
        parser = RobotFileParser(robots_url)
        parser.parse(result.body.decode(result.encoding or "utf-8", errors="replace").splitlines())
        self._robots = parser


async def _read_capped(resp: httpx.Response) -> bytes:
    chunks, size = [], 0
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:MAX_BODY_BYTES]


async def crawl(start_url: str, options: Optional[CrawlOptions] = None, **hooks) -> CrawlResult:
    """Convenience wrapper: `await crawl(url, options, on_progress=..., cancel_event=...)`."""
    return await Crawler(start_url, options, **hooks).run()
