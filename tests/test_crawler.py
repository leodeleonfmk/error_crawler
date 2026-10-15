"""End-to-end crawler tests against a fake site served by httpx.MockTransport."""

import asyncio
import socket

import httpx

from app.crawler import Crawler
from app.models import CrawlOptions, IssueType, LinkKind


def page(*hrefs, extra=""):
    links = "".join(f'<a href="{h}">link to {h}</a>' for h in hrefs)
    return f"<html><body>{links}{extra}</body></html>"


class FakeSite:
    """Maps full URLs to (status, headers, body) and records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append((request.method, url))
        route = self.routes.get(url)
        if route is None:
            return httpx.Response(404, text="not found")
        if isinstance(route, Exception):
            raise route
        if callable(route):
            return route(request)
        status, headers, body = route
        headers = {"content-type": "text/html; charset=utf-8", **headers}
        return httpx.Response(status, headers=headers, text=body)

    def urls(self, method=None):
        return [u for m, u in self.requests if method is None or m == method]


def run(site, start="https://example.com/", **kwargs):
    opts = kwargs.pop("options", None) or CrawlOptions(delay=0)
    crawler = Crawler(start, opts, transport=httpx.MockTransport(site), **kwargs)
    return asyncio.run(crawler.run())


def ok(body):
    return (200, {}, body)


def redirect(to, status=301):
    return (status, {"location": to}, "")


def test_finds_broken_internal_link_with_context():
    site = FakeSite({
        "https://example.com/": ok(page("/a", "/missing")),
        "https://example.com/a": ok(page("/", "/missing")),
    })
    result = run(site)
    assert result.pages_crawled == 3
    broken = [i for i in result.issues if i.issue_type == IssueType.HTTP_4XX]
    # One issue per page the broken link appears on; the URL is fetched once.
    assert sorted(i.found_on for i in broken) == ["https://example.com/", "https://example.com/a"]
    assert all(i.url == "https://example.com/missing" and i.status_code == 404 for i in broken)
    assert broken[0].link_text == "link to /missing"
    assert broken[0].response_time_ms is not None
    assert site.urls().count("https://example.com/missing") == 1


def test_never_loops_and_dedupes_variants():
    site = FakeSite({
        "https://example.com/": ok(page("/a", "/a/", "https://www.example.com/a", "/a#x", "/")),
        "https://example.com/a": ok(page("/", "/a")),
    })
    result = run(site)
    assert result.issues == []
    assert result.pages_crawled == 2
    assert site.urls("GET").count("https://example.com/a") == 1


def test_external_links_use_head_and_are_not_crawled():
    site = FakeSite({
        "https://example.com/": ok(page("https://other.org/ok", "https://other.org/gone", "https://other.org/nohead")),
        "https://other.org/ok": ok(page("https://other.org/deeper")),
        "https://other.org/gone": (410, {}, ""),
        "https://other.org/nohead": lambda r: httpx.Response(405 if r.method == "HEAD" else 200),
    })
    result = run(site)
    assert ("HEAD", "https://other.org/ok") in site.requests
    assert ("GET", "https://other.org/nohead") in site.requests  # 405 fallback
    assert "https://other.org/deeper" not in site.urls()
    assert [(i.url, i.kind) for i in result.issues] == [("https://other.org/gone", LinkKind.EXTERNAL)]


def test_check_external_false_skips_other_sites():
    site = FakeSite({"https://example.com/": ok(page("https://other.org/gone"))})
    result = run(site, options=CrawlOptions(delay=0, check_external=False))
    assert result.issues == []
    assert "https://other.org/gone" not in site.urls()


def test_images_checked_only_when_enabled():
    site = FakeSite({"https://example.com/": ok(page(extra='<img src="/broken.png" alt="Logo">'))})
    assert run(site).issues == []
    result = run(site, options=CrawlOptions(delay=0, check_images=True))
    assert [(i.url, i.kind, i.link_text) for i in result.issues] == [
        ("https://example.com/broken.png", LinkKind.IMAGE, "Logo")
    ]


def test_redirect_chain_recorded_and_flagged():
    site = FakeSite({
        "https://example.com/": ok(page("/old", "/moved")),
        "https://example.com/old": redirect("/older"),
        "https://example.com/older": redirect("https://www.example.com/new", 302),
        "https://www.example.com/new": ok(page()),
        "https://example.com/moved": redirect("/new"),  # single hop: fine
        "https://example.com/new": ok(page()),
    })
    result = run(site)
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.issue_type == IssueType.REDIRECT_CHAIN
    assert issue.is_warning
    assert [(h.url, h.status_code) for h in issue.redirect_chain] == [
        ("https://example.com/old", 301),
        ("https://example.com/older", 302),
        ("https://www.example.com/new", 200),
    ]


def test_too_many_redirects():
    site = FakeSite({
        "https://example.com/": ok(page("/loop")),
        "https://example.com/loop": redirect("/loop2"),
        "https://example.com/loop2": redirect("/loop"),
    })
    result = run(site, options=CrawlOptions(delay=0, max_redirects=5))
    [issue] = result.issues
    assert issue.issue_type == IssueType.TOO_MANY_REDIRECTS
    assert len(issue.redirect_chain) == 7  # 6 redirects + final hop


def test_transport_errors_are_classified():
    req = httpx.Request("GET", "https://x")
    dns = httpx.ConnectError("boom", request=req)
    dns.__cause__ = socket.gaierror(8, "nodename nor servname provided")
    site = FakeSite({
        "https://example.com/": ok(page("/slow", "/err", "https://nope.invalid/")),
        "https://example.com/slow": httpx.ReadTimeout("timed out", request=req),
        "https://example.com/err": (503, {}, ""),
        "https://nope.invalid/": dns,
    })
    types = {i.url: i.issue_type for i in run(site).issues}
    assert types == {
        "https://example.com/slow": IssueType.TIMEOUT,
        "https://example.com/err": IssueType.HTTP_5XX,
        "https://nope.invalid/": IssueType.DNS_ERROR,
    }


def test_respects_robots_txt():
    site = FakeSite({
        "https://example.com/robots.txt": (200, {"content-type": "text/plain"}, "User-agent: *\nDisallow: /private\n"),
        "https://example.com/": ok(page("/private/x", "/public")),
        "https://example.com/public": ok(page()),
    })
    result = run(site)
    assert "https://example.com/private/x" not in site.urls()
    assert result.robots_skipped == 1
    assert result.pages_crawled == 2


def test_max_pages_limit():
    routes = {f"https://example.com/p{i}": ok(page(f"/p{i + 1}")) for i in range(20)}
    routes["https://example.com/"] = ok(page("/p0"))
    result = run(FakeSite(routes), options=CrawlOptions(delay=0, max_pages=5))
    assert result.pages_crawled == 5
    assert result.page_limit_reached


def test_url_validator_blocks_requests():
    site = FakeSite({
        "https://example.com/": ok(page("http://169.254.169.254/latest", "https://other.org/")),
        "https://other.org/": ok(""),
    })
    seen = []

    def validator(url):
        seen.append(url)
        return "169.254" not in url

    result = run(site, url_validator=validator)
    assert "http://169.254.169.254/latest" not in site.urls()
    assert "https://example.com/robots.txt" in seen  # called before every request
    [issue] = result.issues
    assert issue.issue_type == IssueType.BLOCKED


def test_url_validator_checked_on_each_redirect_hop():
    site = FakeSite({
        "https://example.com/": ok(page("https://other.org/r")),
        "https://other.org/r": redirect("http://127.0.0.1/admin"),
    })
    result = run(site, url_validator=lambda u: "127.0.0.1" not in u)
    assert "http://127.0.0.1/admin" not in site.urls()
    assert result.issues[0].issue_type == IssueType.BLOCKED


def test_progress_callback_and_cancel():
    routes = {f"https://example.com/p{i}": ok(page(f"/p{i + 1}")) for i in range(50)}
    routes["https://example.com/"] = ok(page("/p0", "/missing"))
    calls = []

    async def main():
        cancel = asyncio.Event()

        async def on_progress(stats):  # async callbacks are supported too
            calls.append(stats)
            if stats.pages_crawled >= 5:
                cancel.set()

        crawler = Crawler("https://example.com/", CrawlOptions(delay=0, concurrency=1),
                          transport=httpx.MockTransport(FakeSite(routes)),
                          on_progress=on_progress, cancel_event=cancel)
        return await crawler.run()

    result = asyncio.run(main())
    assert result.cancelled
    assert result.pages_crawled < 10
    assert calls[0].current_url == "https://example.com/"
    assert any(c.latest_issue and c.latest_issue.status_code == 404 for c in calls)
    assert calls[-1].errors_found == 1
