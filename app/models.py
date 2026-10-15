"""Result and option types for the crawler."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

MAX_PAGES_HARD_CAP = 500
USER_AGENT = "SiteLinkChecker/1.0"
ROBOTS_TOKEN = "SiteLinkChecker"  # what robots.txt rules and site allowlists should match


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def default_user_agent() -> str:
    """Crawler convention (as Googlebot does): Mozilla-compatible prefix, our token, contact URL.
    Deliberately not a browser UA: we identify ourselves honestly."""
    contact = os.environ.get("CONTACT_URL", "").strip()
    return f"Mozilla/5.0 (compatible; {USER_AGENT}; +{contact})" if contact else f"Mozilla/5.0 (compatible; {USER_AGENT})"


class LinkKind(str, Enum):
    PAGE = "page"  # same-site link, crawled
    EXTERNAL = "external"  # other site, status check only
    IMAGE = "image"  # <img src>, status check only


class IssueType(str, Enum):
    HTTP_4XX = "http_4xx"
    HTTP_5XX = "http_5xx"
    TIMEOUT = "timeout"
    DNS_ERROR = "dns_error"
    SSL_ERROR = "ssl_error"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    CONNECTION_ERROR = "connection_error"
    REDIRECT_CHAIN = "redirect_chain"  # 2+ hops; works, but worth fixing
    BLOCKED = "blocked"  # rejected by url_validator, never requested
    BLOCKED_BY_SITE = "blocked_by_site"  # external site refused automated checks (WAF/bot protection)

    @property
    def is_warning(self) -> bool:
        return self in (IssueType.REDIRECT_CHAIN, IssueType.BLOCKED, IssueType.BLOCKED_BY_SITE)


@dataclass
class RedirectHop:
    url: str
    status_code: Optional[int]


@dataclass
class Issue:
    url: str
    issue_type: IssueType
    kind: LinkKind
    found_on: Optional[str]  # None for the start URL
    link_text: str = ""
    status_code: Optional[int] = None
    error: str = ""
    response_time_ms: Optional[float] = None
    # Every hop including the final response, e.g. [a 301, b 302, c 200].
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    # Allowlisted headers from 4xx/5xx (and challenge) responses, for diagnosing blocks.
    response_headers: dict[str, str] = field(default_factory=dict)
    protection_hint: Optional[str] = None  # cloudflare, akamai, sucuri, datadome, unknown

    @property
    def is_warning(self) -> bool:
        return self.issue_type.is_warning

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CrawlOptions:
    max_pages: int = 100
    check_external: bool = True
    check_images: bool = False
    concurrency: int = 5
    timeout: float = 10.0
    delay: float = 0.25  # seconds each worker waits after a request
    max_redirects: int = 5
    user_agent: str = field(default_factory=default_user_agent)
    # Resource caps (not user-settable through the API; env-configurable).
    max_urls: int = field(default_factory=lambda: _env_int("MAX_URLS_PER_JOB", 5000))
    max_links_per_page: int = field(default_factory=lambda: _env_int("MAX_LINKS_PER_PAGE", 2000))
    max_external: int = field(default_factory=lambda: _env_int("MAX_EXTERNAL_PER_JOB", 300))
    per_host_concurrency: int = field(default_factory=lambda: _env_int("PER_HOST_CONCURRENCY", 2))

    def __post_init__(self) -> None:
        self.max_pages = max(1, min(int(self.max_pages), MAX_PAGES_HARD_CAP))
        self.concurrency = max(1, int(self.concurrency))
        self.max_redirects = max(0, min(int(self.max_redirects), 5))
        self.delay = max(0.0, float(self.delay))
        self.per_host_concurrency = max(1, int(self.per_host_concurrency))


@dataclass
class CrawlStats:
    """Snapshot passed to on_progress after each URL is processed."""

    pages_crawled: int
    links_checked: int
    errors_found: int
    warnings_found: int
    queued: int
    current_url: str
    new_issues: list[Issue] = field(default_factory=list)  # all issues since the previous callback


@dataclass
class CrawlResult:
    start_url: str
    pages_crawled: int
    links_checked: int
    errors_found: int
    warnings_found: int
    duration_s: float
    cancelled: bool = False
    page_limit_reached: bool = False
    robots_skipped: int = 0
    pages_truncated: int = 0  # HTML bodies cut off at the size cap
    url_cap_reached: bool = False
    link_cap_pages: int = 0  # pages with more links than we parse
    external_cap_reached: bool = False
    start_blocked: bool = False  # the start page itself was refused (401/403/429/challenge)
    start_protection_hint: Optional[str] = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def counts_by_type(self) -> dict[str, int]:
        return dict(Counter(i.issue_type.value for i in self.issues))

    def to_dict(self) -> dict:
        data = asdict(self)
        data["counts_by_type"] = self.counts_by_type
        return data
