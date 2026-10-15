"""Crawler resource limits: body caps, decompression bombs, URL/link/external caps,
per-host concurrency and the overall per-request deadline."""

import asyncio
import gzip
import time
import tracemalloc

import httpx
import pytest

from app.crawler import MAX_BODY_BYTES, Crawler
from app.models import CrawlOptions, IssueType, default_user_agent

START = "https://example.com/"


class ChunkStream(httpx.AsyncByteStream):
    """A streamed body that records whether anyone read it."""

    def __init__(self, chunks, delay=0.0):
        self.chunks = chunks
        self.delay = delay
        self.read = False

    async def __aiter__(self):
        self.read = True
        for chunk in self.chunks:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self):
        pass


def html(body, **headers):
    return {"status": 200, "headers": {"content-type": "text/html; charset=utf-8", **headers}, "body": body}


def make_handler(routes, requested):
    async def handler(request):
        url = str(request.url)
        requested.append((request.method, url))
        route = routes.get(url)
        if route is None:
            return httpx.Response(200 if "ok" in url else 404, headers={"content-type": "text/html"}, text="")
        if callable(route):
            route = await route(request)
            if isinstance(route, httpx.Response):
                return route
        body = route["body"]
        stream = body if isinstance(body, httpx.AsyncByteStream) else ChunkStream([body.encode() if isinstance(body, str) else body])
        return httpx.Response(route["status"], headers=route["headers"], stream=stream)

    return handler


def crawl(routes, **opts):
    requested = []
    options = CrawlOptions(delay=0, **opts)
    crawler = Crawler(START, options, transport=httpx.MockTransport(make_handler(routes, requested)))
    return asyncio.run(crawler.run()), requested


def links(*hrefs):
    return "".join(f'<a href="{h}">x</a>' for h in hrefs)


# --- body caps -----------------------------------------------------------------


def test_oversized_html_is_truncated_at_2mb():
    filler = "<p>" + "x" * 1000 + "</p>"
    big = links("/early") + filler * (3 * 1024) + links("/late")  # ~3 MB, /late beyond the cap
    chunks = [big[i:i + 65536].encode() for i in range(0, len(big), 65536)]
    result, requested = crawl({START: html(ChunkStream(chunks))})
    urls = [u for _, u in requested]
    assert "https://example.com/early" in urls
    assert "https://example.com/late" not in urls
    assert result.pages_truncated == 1
    assert result.errors_found == 1  # /early 404s; truncation itself is not an error


def test_gzip_bomb_is_capped_without_inflating():
    bomb = gzip.compress(b" " * (200 * 1024 * 1024), compresslevel=9)  # 200 MB -> ~200 KB
    assert len(bomb) < 1024 * 1024
    chunks = [bomb[i:i + 65536] for i in range(0, len(bomb), 65536)]
    routes = {START: html(ChunkStream(chunks), **{"content-encoding": "gzip"})}
    tracemalloc.start()
    result, _ = crawl(routes)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert result.pages_truncated == 1
    assert peak < 6 * MAX_BODY_BYTES, f"peak {peak / 1e6:.0f} MB: body was inflated past the cap"


def test_deflate_body_is_decoded():
    import zlib
    body = zlib.compress(links("/inflated").encode())
    result, requested = crawl({START: html(ChunkStream([body]), **{"content-encoding": "deflate"})})
    assert ("GET", "https://example.com/inflated") in requested


def test_unknown_encoding_is_not_parsed():
    result, requested = crawl({START: html(ChunkStream([b"\x00\x01garbage"]), **{"content-encoding": "br"})})
    assert [u for _, u in requested if "robots" not in u] == [START]


@pytest.mark.parametrize("ctype", ["application/json", "text/plain", "image/svg+xml", "text/html-sandboxed"])
def test_non_html_content_is_not_parsed(ctype):
    routes = {START: {"status": 200, "headers": {"content-type": ctype}, "body": links("/hidden")}}
    _, requested = crawl(routes)
    assert "https://example.com/hidden" not in [u for _, u in requested]


def test_xhtml_is_parsed():
    routes = {START: {"status": 200, "headers": {"content-type": "application/xhtml+xml"}, "body": links("/xhtml")}}
    _, requested = crawl(routes)
    assert ("GET", "https://example.com/xhtml") in requested


def test_status_only_checks_read_no_body():
    streams = {}

    def tracked(name, status, method_status=None):
        async def route(request):
            stream = ChunkStream([b"<html>" + b"x" * 100000])
            streams[(name, request.method)] = stream
            code = method_status.get(request.method, status) if method_status else status
            return httpx.Response(code, headers={"content-type": "text/html"}, stream=stream)
        return route

    routes = {
        START: html(links("https://other.test/ok", "https://other.test/nohead") + '<img src="/pic.png">'),
        "https://other.test/ok": tracked("ok", 200),
        "https://other.test/nohead": tracked("nohead", 200, {"HEAD": 405}),
        "https://example.com/pic.png": tracked("img", 200),
    }
    _, requested = crawl(routes, check_images=True)
    assert ("GET", "https://other.test/nohead") in requested  # the HEAD fallback happened
    assert set(streams) >= {("ok", "HEAD"), ("nohead", "HEAD"), ("nohead", "GET"), ("img", "HEAD")}
    assert not any(s.read for s in streams.values())


# --- caps ------------------------------------------------------------------------


def test_unique_url_cap():
    routes = {START: html(links(*[f"/p{i}" for i in range(50)]))}
    result, _ = crawl(routes, max_urls=10)
    assert result.url_cap_reached
    assert result.links_checked <= 10


def test_links_per_page_cap():
    routes = {START: html(links(*[f"/p{i}" for i in range(20)]))}
    result, requested = crawl(routes, max_links_per_page=5)
    assert result.link_cap_pages == 1
    assert len([u for _, u in requested if "/p" in u]) == 5


def test_external_url_cap():
    routes = {START: html(links(*[f"https://ext{i}.test/ok" for i in range(10)]))}
    result, requested = crawl(routes, max_external=3)
    assert result.external_cap_reached
    assert len([u for _, u in requested if "ext" in u]) == 3


def test_per_host_concurrency():
    in_flight, peak = {}, {}

    async def slow(request):
        host = request.url.host
        in_flight[host] = in_flight.get(host, 0) + 1
        peak[host] = max(peak.get(host, 0), in_flight[host])
        await asyncio.sleep(0.05)
        in_flight[host] -= 1
        return httpx.Response(200)

    routes = {START: html(links(*[f"https://busy.test/ok{i}" for i in range(12)], *[f"https://other.test/ok{i}" for i in range(4)]))}
    for i in range(12):
        routes[f"https://busy.test/ok{i}"] = slow
    for i in range(4):
        routes[f"https://other.test/ok{i}"] = slow
    crawl(routes, concurrency=8, per_host_concurrency=2)
    assert peak["busy.test"] == 2
    assert peak["other.test"] == 2


# --- deadline / identity ---------------------------------------------------------


def test_overall_deadline_stops_slow_drip():
    routes = {
        START: html(links("/drip")),
        "https://example.com/drip": html(ChunkStream([b"<"] * 1000, delay=0.2)),
    }
    started = time.monotonic()
    result, _ = crawl(routes, timeout=1)
    assert time.monotonic() - started < 4
    [issue] = [i for i in result.issues if i.url.endswith("/drip")]
    assert issue.issue_type == IssueType.TIMEOUT


def test_user_agent_contact_url(monkeypatch):
    monkeypatch.delenv("CONTACT_URL", raising=False)
    assert default_user_agent() == "Mozilla/5.0 (compatible; SiteLinkChecker/1.0)"
    monkeypatch.setenv("CONTACT_URL", "https://example.org/bot")
    assert default_user_agent() == "Mozilla/5.0 (compatible; SiteLinkChecker/1.0; +https://example.org/bot)"
    seen = []

    async def record(request):
        seen.append(request.headers["user-agent"])
        return httpx.Response(200, headers={"content-type": "text/html"}, text="")

    crawl({START: record})
    assert seen and all(ua == "Mozilla/5.0 (compatible; SiteLinkChecker/1.0; +https://example.org/bot)" for ua in seen)


def test_redirects_capped_at_five():
    assert CrawlOptions(max_redirects=50).max_redirects == 5
