"""Abuse limits and general API hardening."""

import asyncio

import httpx
import pytest
from starlette.requests import Request

from app import ratelimit
from app.jobs import JobManager
from app.main import create_app
from app.ratelimit import RateLimits, SlidingWindow, client_ip
from test_api import FakeCrawl, wait_for_status

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def allow_private_hosts(monkeypatch):
    # Fake hostnames (a.test); SSRF rules are covered in test_security.py.
    monkeypatch.setenv("ALLOW_PRIVATE_HOSTS", "1")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# --- SlidingWindow ---------------------------------------------------------------


def test_window_allows_limit_then_blocks_until_oldest_expires():
    clock = Clock()
    window = SlidingWindow(3, 10, clock)
    for _ in range(3):
        assert window.hit("ip") is None
        clock.now += 1
    assert window.hit("ip") == pytest.approx(7)  # oldest event (t=1000) expires at 1010; now 1003
    clock.now = 1010.01
    assert window.hit("ip") is None
    assert window.hit("other") is None  # keys are independent


def test_window_cleanup_drops_stale_keys():
    clock = Clock()
    window = SlidingWindow(5, 10, clock)
    for i in range(100):
        window.hit(f"ip{i}")
    clock.now += 11
    window.hit("fresh")
    assert window.cleanup() == 100
    assert len(window) == 1


def test_window_key_ceiling(monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_TRACKED_KEYS", 5)
    window = SlidingWindow(5, 10, Clock())
    for i in range(50):
        window.hit(f"ip{i}")
    assert len(window) <= 5


# --- client_ip ---------------------------------------------------------------------


def make_request(peer="10.0.0.1", xff=None):
    headers = [(b"x-forwarded-for", v.encode()) for v in ([xff] if isinstance(xff, str) else (xff or []))]
    return Request({"type": "http", "headers": headers, "client": (peer, 1234), "method": "GET", "path": "/"})


def test_client_ip_ignores_xff_by_default():
    assert client_ip(make_request(xff="1.2.3.4"), hops=0) == "10.0.0.1"


def test_client_ip_one_trusted_hop_takes_rightmost():
    assert client_ip(make_request(xff="203.0.113.7"), hops=1) == "203.0.113.7"
    # A client can prepend anything; only the entry our proxy appended counts.
    assert client_ip(make_request(xff="6.6.6.6, 203.0.113.7"), hops=1) == "203.0.113.7"
    assert client_ip(make_request(xff=["6.6.6.6", "203.0.113.7"]), hops=1) == "203.0.113.7"


def test_client_ip_two_hops_and_missing_header():
    assert client_ip(make_request(xff="6.6.6.6, 198.51.100.2, 10.1.1.1"), hops=2) == "198.51.100.2"
    assert client_ip(make_request(xff="198.51.100.2"), hops=2) == "10.0.0.1"  # too short: use the peer
    assert client_ip(make_request(), hops=1) == "10.0.0.1"


def test_trusted_proxy_hops_env(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    assert client_ip(make_request(xff="6.6.6.6, 203.0.113.7")) == "203.0.113.7"
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "nonsense")
    assert client_ip(make_request(xff="203.0.113.7")) == "10.0.0.1"


# --- API limits ---------------------------------------------------------------------

LOOSE = dict(jobs_per_hour=1000, active_jobs_per_ip=1000, active_jobs_per_domain=1000, api_per_minute=10_000)


@pytest.fixture
async def make_env(monkeypatch):
    managers = []

    async def make(proxy_hops=0, **limits):
        monkeypatch.setenv("TRUSTED_PROXY_HOPS", str(proxy_hops))
        fake = FakeCrawl()
        manager = JobManager(crawl_fn=fake)
        app = create_app(manager, RateLimits(**{**LOOSE, **limits}))
        await manager.start()
        managers.append(manager)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                   base_url="http://test")
        return client, app, fake

    yield make
    for manager in managers:
        await manager.stop()


async def post(client, url, ip=None):
    headers = {"x-forwarded-for": ip} if ip else {}
    return await client.post("/api/jobs", json={"url": url}, headers=headers)


async def test_jobs_per_hour(make_env):
    client, _, fake = await make_env(jobs_per_hour=2)
    for site in ("a.test", "b.test"):
        job = (await post(client, f"https://{site}/")).json()
        fake.release(f"https://{site}/")
        await wait_for_status(client, job["id"], "done")
    resp = await post(client, "https://c.test/")
    assert resp.status_code == 429
    assert resp.json() == {"error": "You've started a lot of scans lately. Try again in about 60 minutes."}
    assert 3500 <= int(resp.headers["retry-after"]) <= 3600


async def test_rejected_requests_do_not_use_up_the_hourly_quota(make_env):
    client, _, _ = await make_env(jobs_per_hour=1)
    for _ in range(3):
        assert (await post(client, "not a url")).status_code == 422
    assert (await post(client, "https://a.test/")).status_code == 201


async def test_active_jobs_per_ip(make_env):
    client, _, fake = await make_env(active_jobs_per_ip=2)
    first = (await post(client, "https://a.test/")).json()
    assert (await post(client, "https://b.test/")).status_code == 201
    resp = await post(client, "https://c.test/")
    assert resp.status_code == 429
    assert "already have scans running" in resp.json()["error"]
    assert resp.headers["retry-after"] == "60"
    await wait_for_status(client, first["id"], "running")
    fake.release("https://a.test/")
    await wait_for_status(client, first["id"], "done")
    assert (await post(client, "https://c.test/")).status_code == 201


async def test_active_jobs_per_domain_across_users(make_env):
    client, _, _ = await make_env(proxy_hops=1, active_jobs_per_domain=1)
    assert (await post(client, "https://a.test/page", ip="198.51.100.1")).status_code == 201
    for variant in ("https://a.test/", "https://WWW.a.test/other", "http://a.test:8080/"):
        resp = await post(client, variant, ip="198.51.100.2")  # a different user
        assert resp.status_code == 429
        assert resp.json() == {"error": "That site is already being scanned. Try again in a few minutes."}
        assert resp.headers["retry-after"] == "120"
    assert (await post(client, "https://b.test/", ip="198.51.100.2")).status_code == 201


async def test_api_requests_per_minute(make_env):
    client, _, _ = await make_env(api_per_minute=5)
    for _ in range(5):
        assert (await client.get("/api/jobs/nope")).status_code == 404
    resp = await client.get("/api/jobs/nope")
    assert resp.status_code == 429
    assert set(resp.json()) == {"error"}
    assert 1 <= int(resp.headers["retry-after"]) <= 60
    page = await client.get("/report/nope")
    assert page.status_code == 429 and page.headers["content-type"].startswith("text/html")
    assert (await client.get("/")).status_code == 200  # the page itself isn't limited
    assert (await client.get("/health")).status_code == 200


async def test_spoofed_xff_does_not_dodge_the_limit(make_env):
    client, _, _ = await make_env(proxy_hops=1, api_per_minute=3)
    for i in range(3):
        await client.get("/api/jobs/nope", headers={"x-forwarded-for": f"6.6.6.{i}, 198.51.100.9"})
    resp = await client.get("/api/jobs/nope", headers={"x-forwarded-for": "7.7.7.7, 198.51.100.9"})
    assert resp.status_code == 429


async def test_normal_polling_is_not_limited(make_env):
    client, _, _ = await make_env(api_per_minute=120)
    job = (await post(client, "https://a.test/")).json()
    for since in range(90):  # 90 polls inside a minute, more than the 1/s frontend makes
        assert (await client.get(f"/api/jobs/{job['id']}?since={since}")).status_code == 200


async def test_body_size_limit(make_env):
    client, _, _ = await make_env()
    big = {"url": "https://a.test/", "padding": "x" * 5000}
    resp = await client.post("/api/jobs", json=big)
    assert resp.status_code == 413 and resp.json() == {"error": "That request is too large."}

    async def chunked():
        yield b'{"url": "https://a.test/", "padding": "'
        for _ in range(10):
            yield b"x" * 1000
        yield b'"}'

    resp = await client.post("/api/jobs", content=chunked(), headers={"content-type": "application/json"})
    assert resp.status_code == 413
    assert (await client.post("/api/jobs", json={"url": "https://a.test/"})).status_code == 201


# --- general hardening ----------------------------------------------------------------


async def test_security_headers_everywhere(make_env):
    client, _, fake = await make_env()
    job = (await post(client, "https://a.test/")).json()
    await wait_for_status(client, job["id"], "running")
    fake.release("https://a.test/")
    await wait_for_status(client, job["id"], "done")
    for path in ("/", "/health", f"/api/jobs/{job['id']}", "/api/jobs/nope", "/no-such-page", f"/report/{job['id']}"):
        resp = await client.get(path)
        assert resp.headers["x-content-type-options"] == "nosniff", path
        assert resp.headers["referrer-policy"] == "no-referrer", path
        assert resp.headers["x-frame-options"] == "DENY", path
    assert "content-security-policy" not in (await client.get("/")).headers  # Tailwind CDN + Google Fonts
    assert "default-src 'none'" in (await client.get(f"/report/{job['id']}")).headers["content-security-policy"]


async def test_unexpected_errors_are_generic(make_env):
    client, app, _ = await make_env()

    @app.get("/api/boom")
    async def boom():
        raise RuntimeError("secret internal detail /etc/passwd")

    resp = await client.get("/api/boom")
    assert resp.status_code == 500
    assert resp.json() == {"error": "Something went wrong"}
    assert "secret" not in resp.text and "Traceback" not in resp.text


async def test_job_ids_are_unguessable_and_not_listed(make_env):
    client, _, _ = await make_env()
    ids = {(await post(client, f"https://s{i}.test/")).json()["id"] for i in range(5)}
    assert len(ids) == 5 and all(len(i) >= 11 for i in ids)  # >= 64 bits of base64url
    listing = await client.get("/api/jobs")
    assert listing.status_code == 405
    assert not any(i in listing.text for i in ids)
