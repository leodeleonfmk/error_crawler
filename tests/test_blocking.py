"""Sites that block automated checks: classification, diagnostics, start-page failures."""

import asyncio
import csv
import io
import re

import httpx
import pytest

from app.crawler import BLOCKED_BY_SITE_MESSAGE, Crawler, diagnostic_headers, protection_hint
from app.jobs import JobManager, JobStatus
from app.models import CrawlOptions, IssueType
from app.reports import build_csv, build_html
from test_reports import make_job

START = "https://example.com/"
CF = {"server": "cloudflare", "cf-ray": "8d1f2a3b4c5d6e7f-SJC"}


class Body(httpx.AsyncByteStream):
    def __init__(self, data=b""):
        self.data, self.read = data, False

    async def __aiter__(self):
        self.read = True
        yield self.data


def site(routes, requested=None, streams=None):
    async def handler(request):
        url = str(request.url)
        if requested is not None:
            requested.append((request.method, url, dict(request.headers)))
        status, headers, body = routes.get(url, (404, {}, ""))
        stream = Body(body.encode() if isinstance(body, str) else body)
        if streams is not None:
            streams.append(stream)
        return httpx.Response(status, headers={"content-type": "text/html", **headers}, stream=stream)
    return httpx.MockTransport(handler)


def page(*hrefs):
    return "".join(f'<a href="{h}">link {h}</a>' for h in hrefs)


def crawl(routes, **kwargs):
    crawler = Crawler(START, CrawlOptions(delay=0), transport=site(routes, **kwargs))
    return asyncio.run(crawler.run())


# --- diagnostics -----------------------------------------------------------------


def test_diagnostic_headers_are_allowlisted_and_truncated():
    headers = httpx.Headers([
        ("Server", "cloudflare"), ("CF-RAY", "abc-SJC"), ("cf-mitigated", "challenge"),
        ("Set-Cookie", "session=secret"), ("X-Akamai-Request-ID", "1"), ("x-akamai-session-info", "2"),
        ("Via", "1.1 varnish"), ("Retry-After", "120"), ("X-Internal-Debug", "do-not-copy"),
        ("x-datadome", "protected"), ("x-sucuri-id", "1234"), ("Content-Type", "text/html"),
        ("x-akamai-big", "x" * 5000),
    ])
    out = diagnostic_headers(headers)
    assert set(out) == {"server", "cf-ray", "cf-mitigated", "x-akamai-request-id", "x-akamai-session-info",
                        "via", "retry-after", "x-datadome", "x-sucuri-id", "x-akamai-big"}
    assert len(out["x-akamai-big"]) == 200
    assert "set-cookie" not in out and "x-internal-debug" not in out


def test_diagnostic_headers_capped():
    many = httpx.Headers([(f"x-akamai-h{i}", "v") for i in range(50)])
    assert len(diagnostic_headers(many)) == 12


@pytest.mark.parametrize("headers, hint", [
    ({"cf-ray": "1"}, "cloudflare"),
    ({"server": "cloudflare"}, "cloudflare"),
    ({"cf-mitigated": "challenge"}, "cloudflare"),
    ({"x-akamai-request-id": "1"}, "akamai"),
    ({"server": "AkamaiGHost"}, "akamai"),
    ({"x-sucuri-id": "1"}, "sucuri"),
    ({"server": "Sucuri/Cloudproxy"}, "sucuri"),
    ({"x-datadome": "protected"}, "datadome"),
    ({"server": "nginx"}, "unknown"),
    ({}, "unknown"),
])
def test_protection_hint(headers, hint):
    assert protection_hint(headers) == hint


# --- classification ----------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 403, 429, 999])
def test_external_blocking_statuses_are_warnings(status):
    routes = {
        START: (200, {}, page("https://other.test/x")),
        "https://other.test/x": (status, CF, ""),
    }
    [issue] = crawl(routes).issues
    assert issue.issue_type == IssueType.BLOCKED_BY_SITE
    assert issue.is_warning
    assert issue.error == BLOCKED_BY_SITE_MESSAGE
    assert issue.status_code == status
    assert issue.protection_hint == "cloudflare"
    assert issue.response_headers == CF


def test_cf_mitigated_challenge_is_blocked_even_with_200():
    routes = {
        START: (200, {}, page("https://other.test/challenge")),
        "https://other.test/challenge": (200, {"cf-mitigated": "challenge"}, ""),
    }
    [issue] = crawl(routes).issues
    assert issue.issue_type == IssueType.BLOCKED_BY_SITE


@pytest.mark.parametrize("status, expected", [(404, IssueType.HTTP_4XX), (410, IssueType.HTTP_4XX),
                                              (500, IssueType.HTTP_5XX), (503, IssueType.HTTP_5XX)])
def test_real_external_failures_stay_errors(status, expected):
    routes = {START: (200, {}, page("https://other.test/x")), "https://other.test/x": (status, CF, "")}
    [issue] = crawl(routes).issues
    assert issue.issue_type == expected and not issue.is_warning
    assert issue.protection_hint == "cloudflare"  # diagnostics still recorded


def test_internal_403_after_start_page_stays_an_error():
    routes = {START: (200, {}, page("/members")), "https://example.com/members": (403, CF, "")}
    result = crawl(routes)
    [issue] = result.issues
    assert issue.issue_type == IssueType.HTTP_4XX and issue.status_code == 403
    assert not result.start_blocked


def test_diagnostics_never_read_error_bodies():
    streams = []
    routes = {START: (200, {}, page("https://other.test/x", "/gone")),
              "https://other.test/x": (403, CF, "<html>challenge page</html>")}
    crawl(routes, streams=streams)
    assert sum(s.read for s in streams) == 1  # only the start page body was read


def test_request_headers_are_honest_and_complete(monkeypatch):
    monkeypatch.setenv("CONTACT_URL", "https://example.org/bot")
    requested = []
    crawl({START: (200, {}, page("https://other.test/x")), "https://other.test/x": (200, {}, "")}, requested=requested)
    for _, _, headers in requested:
        assert headers["user-agent"] == "Mozilla/5.0 (compatible; SiteLinkChecker/1.0; +https://example.org/bot)"
        assert "Chrome" not in headers["user-agent"] and "Safari" not in headers["user-agent"]
        assert headers["accept"].startswith("text/html")
        assert headers["accept-language"].startswith("en")
        assert headers["accept-encoding"] == "gzip, deflate"


def test_robots_rules_for_our_token_still_apply():
    routes = {
        "https://example.com/robots.txt": (200, {"content-type": "text/plain"},
                                           "User-agent: SiteLinkChecker\nDisallow: /private\n"),
        START: (200, {}, page("/private/a", "/public")),
        "https://example.com/public": (200, {}, ""),
    }
    requested = []
    result = crawl(routes, requested=requested)
    assert "https://example.com/private/a" not in [u for _, u, _ in requested]
    assert result.robots_skipped == 1


# --- start page blocked ------------------------------------------------------------------


@pytest.mark.parametrize("status, headers", [(403, CF), (401, {}), (429, {"retry-after": "60"}),
                                             (200, {"cf-mitigated": "challenge"})])
def test_blocked_start_page_is_flagged(status, headers):
    result = crawl({START: (status, headers, "")})
    assert result.start_blocked
    assert result.start_protection_hint == ("cloudflare" if "cf-ray" in headers or "cf-mitigated" in headers else "unknown")


def test_blocked_start_page_after_redirect_is_flagged():
    result = crawl({
        "https://example.com/": (301, {"location": "https://www.example.com/"}, ""),
        "https://www.example.com/": (403, {"x-sucuri-id": "1"}, ""),
    })
    assert result.start_blocked and result.start_protection_hint == "sucuri"


def test_missing_start_page_is_not_treated_as_blocked():
    result = crawl({START: (404, {}, "")})
    assert not result.start_blocked


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_job_with_blocked_start_page_fails_with_guidance(anyio_backend):
    def crawl_fn(url, options, **hooks):
        hooks.pop("url_validator", None)
        return Crawler(url, CrawlOptions(delay=0), transport=site({START: (403, CF, "")}), **hooks).run()

    manager = JobManager(crawl_fn=crawl_fn)
    await manager.start()
    try:
        job = manager.submit(START, CrawlOptions())
        for _ in range(200):
            if job.status.finished:
                break
            await asyncio.sleep(0.01)
    finally:
        await manager.stop()
    assert job.status == JobStatus.FAILED
    assert "Cloudflare" in job.error_message and "“SiteLinkChecker”" in job.error_message
    assert "fixed IP" in job.error_message
    assert job.result.start_blocked and job.issues  # diagnostics kept


# --- reports and escaping ------------------------------------------------------------------

EVIL = {"server": '<script>alert(1)</script>', "via": '"><img src=x onerror=alert(2)>', "retry-after": "=HYPERLINK(1)"}


def evil_job():
    from test_reports import issue
    blocked = issue("https://other.test/x", IssueType.BLOCKED_BY_SITE, 403,
                    error=BLOCKED_BY_SITE_MESSAGE, response_headers=EVIL, protection_hint="unknown")
    cf = issue("https://cf.test/x", IssueType.BLOCKED_BY_SITE, 403,
               error=BLOCKED_BY_SITE_MESSAGE, response_headers=CF, protection_hint="cloudflare")
    return make_job([blocked, cf])


def test_html_report_escapes_header_values_and_shows_hint():
    html = build_html(evil_job())
    assert re.search(r"<(script|img)\b", html, re.I) is None
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Blocked by site · 403" in html and "Protected by Cloudflare" in html
    assert BLOCKED_BY_SITE_MESSAGE.replace("'", "&#x27;") in html


def test_csv_has_blocked_rows_as_warnings_and_neutralizes_header_values():
    rows = list(csv.DictReader(io.StringIO(build_csv(evil_job())[1:])))
    assert {r["type"] for r in rows} == {"blocked_by_site"}
    assert {r["severity"] for r in rows} == {"warning"}
    evil_row = next(r for r in rows if r["broken_url"] == "https://other.test/x")
    assert "<script>alert(1)</script>" in evil_row["response_headers"]  # CSV is data, not HTML
    assert next(r for r in rows if r["broken_url"] == "https://cf.test/x")["protection_hint"] == "cloudflare"
    assert not any(cell.startswith(("=", "+", "-", "@")) for r in rows for cell in r.values())
