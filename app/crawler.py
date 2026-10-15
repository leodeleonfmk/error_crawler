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
import zlib
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
from app.security import BLOCKED_MESSAGE, BlockedAddressError, make_guarded_transport

log = logging.getLogger(__name__)

ProgressCallback = Callable[[CrawlStats], Union[None, Awaitable[None]]]
UrlValidator = Callable[[str], Union[bool, Awaitable[bool]]]

DEFAULT_PORTS = {"http": 80, "https": 443}
TRACKING_PARAMS = {"gclid", "fbclid", "msclkid", "mc_cid", "mc_eid"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_BODY_BYTES = 2 * 1024 * 1024  # decoded bytes; don't hold huge pages in 512 MB of RAM
HTML_TYPES = {"text/html", "application/xhtml+xml"}
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
        if isinstance(cur, BlockedAddressError):
            return IssueType.BLOCKED
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
    truncated: bool = False


@dataclass
class _Hop:
    """One HTTP exchange (a single redirect hop)."""

    status_code: int
    location: Optional[str] = None
    content_type: str = ""
    encoding: Optional[str] = None
    body: Optional[bytes] = None
    truncated: bool = False


class _NoLimit:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


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
        self.pages_truncated = 0
        self.url_cap_reached = False
        self.link_cap_pages = 0
        self.external_cap_reached = False
        self._external_queued = 0
        self._host_slots: dict[str, asyncio.Semaphore] = {}
        self._pages_queued = 0
        self._current_url = ""
        self._issues_reported = 0  # how many issues on_progress has delivered
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
            # Every connection goes through the SSRF guard unless a test injects a transport.
            transport=self._transport if self._transport is not None else make_guarded_transport(),
            timeout=self.options.timeout,
            # gzip/deflate only: bodies are decompressed by _read_capped, which knows no others.
            headers={"User-Agent": self.options.user_agent, "Accept-Encoding": "gzip, deflate"},
            follow_redirects=False,  # followed manually to record chains and validate each hop
            trust_env=False,  # proxy env vars must not bypass the guard
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
            pages_truncated=self.pages_truncated,
            url_cap_reached=self.url_cap_reached,
            link_cap_pages=self.link_cap_pages,
            external_cap_reached=self.external_cap_reached,
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

        if len(self._outcomes) + len(self._pending) >= self.options.max_urls:
            self.url_cap_reached = True
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
        elif not same_site:
            if self._external_queued >= self.options.max_external:
                self.external_cap_reached = True
                return
            self._external_queued += 1

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
            if result.truncated:
                self.pages_truncated += 1
            if result.body is not None and self._claim_final_url(task, result.final_url):
                links = extract_links(result.body, result.final_url, self.options.check_images, result.encoding)
                if len(links) > self.options.max_links_per_page:
                    self.link_cap_pages += 1
                    links = links[: self.options.max_links_per_page]
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
            new_issues=self.issues[self._issues_reported :],
        )
        self._issues_reported = len(self.issues)
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

    def _host_slot(self, url: str):
        """Politeness: at most per_host_concurrency requests at once to any other host."""
        host = (urlsplit(url).hostname or "").lower()
        if not host or is_same_site(url, self.root_host):
            return _NoLimit()
        slot = self._host_slots.get(host)
        if slot is None:
            slot = self._host_slots[host] = asyncio.Semaphore(self.options.per_host_concurrency)
        return slot

    async def _fetch(self, url: str, method: str, read_body: bool = False, html_only: bool = True) -> FetchResult:
        """Request `url`, following redirects manually (validating each hop)."""
        result = FetchResult(url=url, final_url=url)
        current = url
        elapsed = 0.0  # request time only, excluding semaphore waits and the delay
        try:
            while True:
                if not await self._is_allowed(current):
                    result.issue_type = IssueType.BLOCKED
                    result.error = BLOCKED_MESSAGE
                    return result
                async with self._host_slot(current), self._sem:
                    started = time.perf_counter()
                    try:
                        # One overall deadline per hop (connect, headers and body), so a
                        # server dripping a byte at a time can't hold a worker forever.
                        hop = await asyncio.wait_for(
                            self._request_once(method, current, read_body, html_only), self.options.timeout
                        )
                    finally:
                        elapsed += time.perf_counter() - started
                        if self.options.delay:
                            await asyncio.sleep(self.options.delay)
                if hop.location is not None:
                    result.redirects.append(RedirectHop(current, hop.status_code))
                    if len(result.redirects) > self.options.max_redirects:
                        result.issue_type = IssueType.TOO_MANY_REDIRECTS
                        result.error = f"More than {self.options.max_redirects} redirects"
                        return result
                    current = normalize_url(hop.location, current) or urljoin(current, hop.location)
                    result.final_url = current
                    continue
                result.status_code = hop.status_code
                result.content_type = hop.content_type
                result.encoding = hop.encoding
                result.body = hop.body
                result.truncated = hop.truncated
                return result
        except asyncio.TimeoutError:
            result.issue_type = IssueType.TIMEOUT
            result.error = f"No complete response within {self.options.timeout:g}s"
            return result
        except httpx.HTTPError as exc:
            result.issue_type = classify_exception(exc)
            # Blocked errors get the generic message; never leak resolved addresses.
            result.error = BLOCKED_MESSAGE if result.issue_type == IssueType.BLOCKED else (str(exc) or type(exc).__name__)
            return result
        finally:
            result.elapsed_ms = round(elapsed * 1000, 1)

    async def _request_once(self, method: str, url: str, read_body: bool, html_only: bool) -> _Hop:
        async with self._client.stream(method, url) as resp:
            location = resp.headers.get("location")
            if resp.status_code in REDIRECT_STATUSES and location:
                return _Hop(resp.status_code, location=location)
            hop = _Hop(resp.status_code, content_type=resp.headers.get("content-type", ""), encoding=resp.charset_encoding)
            # Status-only checks (external links, images, HEAD fallbacks) never read a body.
            if read_body and resp.is_success and (not html_only or _is_html(hop.content_type)):
                hop.body, hop.truncated = await _read_capped(resp)
            return hop

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


def _is_html(content_type: str) -> bool:
    return content_type.split(";", 1)[0].strip().lower() in HTML_TYPES


async def _read_capped(resp: httpx.Response) -> tuple:
    """Return (body, truncated), never holding more than MAX_BODY_BYTES decoded.

    Decompresses the raw stream ourselves with zlib's max_length so a small
    gzip/deflate bomb can't expand past the cap in one chunk (httpx's own
    decoder inflates each chunk fully). Unknown encodings return (None, False).
    """
    if resp.is_stream_consumed:
        # Responses built from in-memory content (tests, mocks) arrive already read and decoded.
        return resp.content[:MAX_BODY_BYTES], len(resp.content) > MAX_BODY_BYTES
    encoding = resp.headers.get("content-encoding", "").strip().lower()
    if encoding in ("", "identity"):
        decoder = None
    elif encoding in ("gzip", "x-gzip"):
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decoder = zlib.decompressobj()
    else:
        return None, False

    body = bytearray()
    try:
        async for chunk in resp.aiter_raw():
            room = MAX_BODY_BYTES + 1 - len(body)  # one extra byte tells us we overflowed
            body += decoder.decompress(chunk, room) if decoder else chunk[:room]
            if len(body) > MAX_BODY_BYTES:
                return bytes(body[:MAX_BODY_BYTES]), True
    except zlib.error:
        return (bytes(body) if body else None), False
    return bytes(body), False


async def crawl(start_url: str, options: Optional[CrawlOptions] = None, **hooks) -> CrawlResult:
    """Convenience wrapper: `await crawl(url, options, on_progress=..., cancel_event=...)`."""
    return await Crawler(start_url, options, **hooks).run()
