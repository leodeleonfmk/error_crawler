"""API + JobManager tests. A fake crawl function stands in for the real crawler."""

import asyncio
import re
from datetime import timedelta

import httpx
import pytest

from app.jobs import JobManager, JobStatus, _now
from app.main import create_app
from app.ratelimit import RateLimits
from app.models import CrawlResult, CrawlStats, Issue, IssueType, LinkKind

pytestmark = pytest.mark.anyio

# These tests exercise job behavior, not abuse limits (see test_ratelimit.py).
NO_LIMITS = RateLimits(jobs_per_hour=10_000, active_jobs_per_ip=10_000,
                       active_jobs_per_domain=10_000, api_per_minute=100_000)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def allow_private_hosts(monkeypatch):
    # Fake hostnames like a.test; SSRF rules are covered in test_security.py.
    monkeypatch.setenv("ALLOW_PRIVATE_HOSTS", "1")


class FakeCrawl:
    """Reports 2 issues, then blocks until release(url) or cancel, then reports 1 more.

    URLs containing "crash" raise instead.
    """

    def __init__(self):
        self.gates = {}
        self.started = []

    def gate(self, url):
        return self.gates.setdefault(url, asyncio.Event())

    def release(self, url):
        self.gate(url).set()

    async def __call__(self, url, options, *, on_progress, cancel_event, url_validator):
        self.started.append(url)
        if "crash" in url:
            raise RuntimeError("boom")
        issues = []

        def report(n):
            new = [
                Issue(url=f"{url}broken{len(issues) + k}", issue_type=IssueType.HTTP_4XX,
                      kind=LinkKind.PAGE, found_on=url, status_code=404)
                for k in range(n)
            ]
            issues.extend(new)
            on_progress(CrawlStats(pages_crawled=len(issues), links_checked=len(issues),
                                   errors_found=len(issues), warnings_found=0, queued=0,
                                   current_url=url, new_issues=new))

        report(2)
        waiters = [asyncio.ensure_future(self.gate(url).wait()), asyncio.ensure_future(cancel_event.wait())]
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        for w in waiters:
            w.cancel()
        cancelled = cancel_event.is_set()
        if not cancelled:
            report(1)
        return CrawlResult(start_url=url, pages_crawled=len(issues), links_checked=len(issues),
                           errors_found=len(issues), warnings_found=0, duration_s=0.1,
                           cancelled=cancelled, issues=list(issues))


@pytest.fixture
async def env():
    fake = FakeCrawl()
    manager = JobManager(crawl_fn=fake)
    app = create_app(manager, NO_LIMITS)
    await manager.start()  # ASGITransport doesn't run the lifespan handler
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client, manager, fake
    await manager.stop()


async def create(client, url, **opts):
    return await client.post("/api/jobs", json={"url": url, **opts})


async def wait_for_status(client, job_id, status):
    for _ in range(300):
        data = (await client.get(f"/api/jobs/{job_id}")).json()
        if data["status"] == status:
            return data
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {status}; last: {data}")


async def test_job_lifecycle(env):
    client, _, fake = env
    resp = await create(client, "https://a.test/")
    assert resp.status_code == 201
    job = resp.json()
    assert job["status"] == "queued" and job["queue_position"] == 1
    assert len(job["id"]) == 12  # 72 bits from secrets.token_urlsafe

    running = await wait_for_status(client, job["id"], "running")
    assert running["queue_position"] is None
    assert running["started_at"] is not None
    assert len(running["issues"]) == 2  # appended live
    assert running["stats"]["current_url"] == "https://a.test/"

    fake.release("https://a.test/")
    done = await wait_for_status(client, job["id"], "done")
    assert len(done["issues"]) == 3
    assert done["stats"]["errors_found"] == 3
    assert done["stats"]["current_url"] == ""
    assert done["finished_at"] is not None
    assert done["summary"]["counts_by_type"] == {"http_4xx": 3}
    assert done["options"] == {"max_pages": 100, "check_external": True, "check_images": False}


async def test_queue_order_and_positions(env):
    client, _, fake = env
    a = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, a, "running")
    b = (await create(client, "https://b.test/")).json()
    c = (await create(client, "https://c.test/")).json()
    assert (b["queue_position"], c["queue_position"]) == (1, 2)

    fake.release("https://a.test/")
    await wait_for_status(client, b["id"], "running")
    assert (await client.get(f"/api/jobs/{c['id']}")).json()["queue_position"] == 1
    fake.release("https://b.test/")
    fake.release("https://c.test/")
    await wait_for_status(client, c["id"], "done")
    assert fake.started == ["https://a.test/", "https://b.test/", "https://c.test/"]


async def test_queue_full_rejected(env):
    client, _, _ = env
    a = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, a, "running")  # running job doesn't count toward the limit
    for i in range(5):
        assert (await create(client, f"https://q{i}.test/")).status_code == 201
    resp = await create(client, "https://overflow.test/")
    assert resp.status_code == 429
    assert "queue is full" in resp.json()["error"]


async def test_cancel_queued_job(env):
    client, _, fake = env
    a = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, a, "running")
    b = (await create(client, "https://b.test/")).json()["id"]
    c = (await create(client, "https://c.test/")).json()["id"]

    resp = await client.post(f"/api/jobs/{b}/cancel")
    assert resp.json()["status"] == "cancelled"
    assert resp.json()["queue_position"] is None
    assert (await client.get(f"/api/jobs/{c}")).json()["queue_position"] == 1

    fake.release("https://a.test/")
    fake.release("https://c.test/")
    await wait_for_status(client, c, "done")
    assert "https://b.test/" not in fake.started


async def test_cancel_running_job_keeps_partial_results(env):
    client, _, _ = env
    a = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, a, "running")
    await client.post(f"/api/jobs/{a}/cancel")
    data = await wait_for_status(client, a, "cancelled")
    assert len(data["issues"]) == 2
    assert data["summary"] is not None
    assert data["finished_at"] is not None


async def test_failed_job_does_not_kill_worker(env):
    client, _, fake = env
    bad = (await create(client, "https://crash.test/")).json()["id"]
    good = (await create(client, "https://good.test/")).json()["id"]
    failed = await wait_for_status(client, bad, "failed")
    assert "failed unexpectedly" in failed["error_message"]
    assert "boom" not in failed["error_message"]  # no internals leaked
    await wait_for_status(client, good, "running")
    fake.release("https://good.test/")
    await wait_for_status(client, good, "done")


async def test_since_pagination(env):
    client, _, fake = env
    a = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, a, "running")
    fake.release("https://a.test/")
    await wait_for_status(client, a, "done")

    async def page(since):
        return (await client.get(f"/api/jobs/{a}", params={"since": since})).json()

    first = await page(0)
    assert len(first["issues"]) == 3 and first["next_since"] == 3
    rest = await page(2)
    assert [i["url"] for i in rest["issues"]] == ["https://a.test/broken2"]
    assert rest["next_since"] == 3
    assert (await page(3))["issues"] == []
    assert (await page(99))["next_since"] == 3
    bad = await client.get(f"/api/jobs/{a}", params={"since": -1})
    assert bad.status_code == 422 and "error" in bad.json()


@pytest.mark.parametrize("url", ["", "   ", "not a url", "mailto:a@b.com", "http://", "https://exa mple.com/"])
async def test_rejects_malformed_urls(env, url):
    client, _, _ = env
    resp = await create(client, url)
    assert resp.status_code == 422
    assert "valid http(s) URL" in resp.json()["error"]


@pytest.mark.parametrize("url", ["ftp://example.com/", "file:///etc/passwd", "http://user:pw@example.com/"])
async def test_rejects_disallowed_urls_generically(env, url):
    client, _, _ = env
    resp = await create(client, url)
    assert resp.status_code == 400
    assert resp.json() == {"error": "This address isn't allowed."}


async def test_missing_scheme_defaults_to_https(env):
    client, manager, _ = env
    job_id = (await create(client, "Example.com/path")).json()["id"]
    assert manager.get(job_id).url == "https://example.com/path"


@pytest.mark.parametrize("given, expected", [(0, 1), (-5, 1), (250, 250), (10_000, 500)])
async def test_max_pages_clamped(env, given, expected):
    client, manager, _ = env
    job_id = (await create(client, "https://a.test/", max_pages=given)).json()["id"]
    assert manager.get(job_id).options.max_pages == expected


async def test_validation_error_shape(env):
    client, _, _ = env
    resp = await client.post("/api/jobs", json={"max_pages": "lots"})
    assert resp.status_code == 422
    assert set(resp.json()) == {"error"}
    assert "url: Field required" in resp.json()["error"]


async def test_unknown_job_and_route(env):
    client, _, _ = env
    resp = await client.get("/api/jobs/nope")
    assert resp.status_code == 404
    assert "restarts" in resp.json()["error"]
    assert (await client.post("/api/jobs/nope/cancel")).status_code == 404
    assert (await client.get("/no/such/route")).json() == {"error": "Not Found"}


async def test_health_and_index(env):
    client, _, _ = env
    assert (await client.get("/health")).json() == {"status": "ok"}
    resp = await client.get("/")
    assert resp.status_code == 200 and "<title>Link Checker" in resp.text


async def test_safety_timeout_cancels_with_partial_results():
    manager = JobManager(crawl_fn=FakeCrawl(), job_timeout_s=0.05)
    await manager.start()
    try:
        job = manager.submit("https://slow.test/", options=None)
        for _ in range(100):
            if job.status.finished:
                break
            await asyncio.sleep(0.01)
        assert job.status == JobStatus.CANCELLED
        assert "time limit" in job.error_message
        assert len(job.issues) == 2
    finally:
        await manager.stop()


async def test_cleanup_removes_old_finished_jobs():
    manager = JobManager(crawl_fn=FakeCrawl())
    old = manager.submit("https://old.test/", options=None)
    recent = manager.submit("https://recent.test/", options=None)
    waiting = manager.submit("https://waiting.test/", options=None)
    for job in (old, recent):
        manager.cancel(job)
    old.finished_at = _now() - timedelta(hours=25)
    assert manager.cleanup() == 1
    assert set(manager.jobs) == {recent.id, waiting.id}


# --- Reports ---

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


async def finished_job(client, fake, url="https://a.test/"):
    job_id = (await create(client, url)).json()["id"]
    running = await wait_for_status(client, job_id, "running")
    fake.release(running["url"])  # the API stores the normalized URL
    await wait_for_status(client, job_id, "done")
    return job_id


def assert_report_headers(resp):
    assert resp.headers["content-security-policy"] == REPORT_CSP
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-robots-tag"] == "noindex"
    assert resp.headers["referrer-policy"] == "no-referrer"


async def test_csv_download(env):
    client, _, fake = env
    job_id = await finished_job(client, fake)
    resp = await client.get(f"/api/jobs/{job_id}/report.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(r'attachment; filename="link-check_a\.test_\d{4}-\d{2}-\d{2}\.csv"',
                        resp.headers["content-disposition"])
    assert resp.content.startswith(b"\xef\xbb\xbf")
    assert resp.text.count("\n") == 1 + 3  # header + 3 issues


async def test_html_download_and_share_page(env):
    client, _, fake = env
    job_id = await finished_job(client, fake)
    download = await client.get(f"/api/jobs/{job_id}/report.html")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/html")
    assert download.headers["content-disposition"].startswith('attachment; filename="link-check_a.test_')
    assert_report_headers(download)

    page = await client.get(f"/report/{job_id}")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in page.headers
    assert_report_headers(page)
    assert "https://a.test/broken2" in page.text


async def test_reports_for_cancelled_job(env):
    client, _, _ = env
    job_id = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, job_id, "running")
    await client.post(f"/api/jobs/{job_id}/cancel")
    await wait_for_status(client, job_id, "cancelled")
    assert (await client.get(f"/api/jobs/{job_id}/report.csv")).status_code == 200
    page = await client.get(f"/report/{job_id}")
    assert page.status_code == 200 and "Partial results" in page.text


async def test_reports_not_ready_while_running(env):
    client, _, _ = env
    job_id = (await create(client, "https://a.test/")).json()["id"]
    await wait_for_status(client, job_id, "running")
    for path in ("report.csv", "report.html"):
        resp = await client.get(f"/api/jobs/{job_id}/{path}")
        assert resp.status_code == 409
        assert "still running" in resp.json()["error"]
    page = await client.get(f"/report/{job_id}")
    assert page.status_code == 409
    assert page.headers["content-type"].startswith("text/html")
    assert f'href="/#/job/{job_id}"' in page.text
    assert_report_headers(page)


async def test_reports_for_failed_job(env):
    client, _, _ = env
    job_id = (await create(client, "https://crash.test/")).json()["id"]
    await wait_for_status(client, job_id, "failed")
    assert (await client.get(f"/api/jobs/{job_id}/report.csv")).status_code == 409
    assert (await client.get(f"/report/{job_id}")).status_code == 409


async def test_reports_unknown_job(env):
    client, _, _ = env
    for path in ("report.csv", "report.html"):
        resp = await client.get(f"/api/jobs/nope/{path}")
        assert resp.status_code == 404 and "restarts" in resp.json()["error"]
    page = await client.get("/report/nope")
    assert page.status_code == 404
    assert page.headers["content-type"].startswith("text/html")
    assert "24 hours" in page.text and "restarts" in page.text
    assert_report_headers(page)


async def test_report_filename_sanitized(env):
    client, _, fake = env
    job_id = await finished_job(client, fake, url="https://Sub_Domain.a.test:8443/x")
    disposition = (await client.get(f"/api/jobs/{job_id}/report.csv")).headers["content-disposition"]
    filename = re.search(r'filename="([^"]+)"', disposition).group(1)
    assert re.fullmatch(r"[a-z0-9._-]+", filename)
    assert filename.startswith("link-check_sub_domain.a.test_")  # uppercase and port dropped


@pytest.mark.parametrize("path", [
    "/static/img/FMK%20Logo%20Horizontal-2026-Yellow.png",
    "/static/img/FMK%20Logomark%20Alt-2026-Pink.png",
])
async def test_logos_are_served(env, path):
    client, _, _ = env
    resp = await client.get(path)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content.startswith(b"\x89PNG")
    assert resp.headers["x-content-type-options"] == "nosniff"


async def test_index_references_existing_logos(env):
    client, _, _ = env
    page = (await client.get("/")).text
    srcs = set(re.findall(r'(?:src|href)="(/static/[^"]+)"', page))
    assert len(srcs) == 2
    for src in srcs:
        assert (await client.get(src)).status_code == 200, src


async def test_cleanup_caps_number_of_finished_jobs():
    manager = JobManager(crawl_fn=FakeCrawl(), max_finished_jobs=3)
    jobs = []
    for i in range(6):
        job = manager.submit(f"https://s{i}.test/", options=None)
        jobs.append(job)
        if i < 5:
            manager.cancel(job)
            job.finished_at = _now() - timedelta(minutes=10 - i)  # job 0 is the oldest
    assert manager.cleanup() == 2
    assert set(manager.jobs) == {jobs[2].id, jobs[3].id, jobs[4].id, jobs[5].id}  # newest 3 + the queued one

