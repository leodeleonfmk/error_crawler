"""End-to-end browser tests for the web UI and reports.

Not part of the default run. Run with:  pytest -m e2e
Set E2E_SCREENSHOTS=<dir> to save screenshots.
"""

import csv
import io
import json
import re
import time
import urllib.error
import urllib.request

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect  # noqa: E402

pytestmark = pytest.mark.e2e

DESKTOP = {"width": 1280, "height": 900}
MOBILE = {"width": 390, "height": 844}
XSS_NEEDLES = [
    "<script>window.__xss=1",
    'onerror="window.__xss=2',
    "onerror=window.__xss=3",
    "<b onmouseover=window.__xss=4>",
]


# --- helpers -------------------------------------------------------------------


def api(base, method, path, body=None):
    """Returns (status, parsed JSON or raw text)."""
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw.decode("utf-8", "replace")


def wait_status(base, job_id, status, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if api(base, "GET", f"/api/jobs/{job_id}?since=999999")[1].get("status") == status:
            return
        time.sleep(0.3)
    raise AssertionError(f"{job_id} never reached {status}")


class Watched:
    """A page that records dialogs and JS errors so tests can assert on them."""

    def __init__(self, browser, scheme="light", viewport=DESKTOP, **ctx_kwargs):
        self.context = browser.new_context(color_scheme=scheme, viewport=viewport, **ctx_kwargs)
        self.page = self.context.new_page()
        self.dialogs, self.js_errors = [], []
        self.page.on("dialog", lambda d: (self.dialogs.append(d.message), d.dismiss()))
        self.page.on("pageerror", lambda e: self.js_errors.append(str(e)))

    def assert_clean(self):
        assert self.dialogs == [], f"dialogs opened: {self.dialogs}"
        assert self.js_errors == [], f"JS errors: {self.js_errors}"
        assert self.page.evaluate("window.__xss") is None, "an injected payload executed"

    def close(self):
        self.context.close()


@pytest.fixture
def watched(browser):
    pages = []

    def make(**kwargs):
        w = Watched(browser, **kwargs)
        pages.append(w)
        return w

    yield make
    for w in pages:
        w.close()


def screen(page, name, timeout=30000):
    page.wait_for_selector(f'[data-screen="{name}"]:not([hidden])', timeout=timeout)


def start_scan(page, base, url, max_pages="100", images=False, external=True):
    page.goto(base)
    page.click("#options summary")
    page.click(f"label[for=mp-{max_pages}]")
    if page.is_checked("#opt-images") != images:
        page.click("#opt-images")
    if page.is_checked("#opt-external") != external:
        page.click("#opt-external")
    page.fill("#url-input", url)
    page.click("#scan-btn")


def assert_no_live_payloads(page):
    # Our own logo is the only legitimate image; anything else would be injected.
    assert page.evaluate("document.querySelectorAll('main img:not([src^=\"/static/img/\"]), main script:not([src])').length") == 0
    assert page.evaluate("Array.from(document.querySelectorAll('main img')).every(i => !i.hasAttribute('onerror'))")
    hrefs = page.evaluate("Array.from(document.querySelectorAll('main a')).map(a => a.getAttribute('href'))")
    # crawled links must be http(s); the rest are the app's own (downloads, in-page #/job links)
    assert all(h.startswith(("http://", "https://", "/api/", "#")) for h in hrefs), hrefs
    assert not any(h.lower().startswith(("javascript:", "data:")) for h in hrefs)


# --- tests ---------------------------------------------------------------------


def test_logos_load_without_errors(servers, watched, screenshot):
    for scheme in ("light", "dark"):
        for label, vp in (("desktop", DESKTOP), ("mobile", MOBILE)):
            w = watched(scheme=scheme, viewport=vp, device_scale_factor=2)
            failed = []
            w.page.on("response", lambda r: r.status >= 400 and failed.append(f"{r.status} {r.url}"))
            w.page.goto(servers.app)
            w.page.wait_for_load_state("networkidle")
            header_logo = w.page.locator("#home-link img")
            assert header_logo.get_attribute("alt") == "Fly More Kites"
            assert w.page.evaluate("document.querySelector('#home-link img').naturalWidth") > 1000  # high-DPI source
            box = header_logo.bounding_box()
            assert 32 <= box["height"] <= 44, box
            screenshot(w.page, f"logo-header-{scheme}-{label}", full_page=False)

            w.page.evaluate("renderWaking('https://example.com')")
            pink = w.page.locator('[data-screen="waiting"] img')
            assert pink.get_attribute("alt") == "" and pink.get_attribute("aria-hidden") == "true"
            w.page.wait_for_function("document.querySelector('[data-screen=waiting] img').complete")
            assert w.page.evaluate("document.querySelector('[data-screen=waiting] img').naturalWidth") > 0
            w.page.wait_for_timeout(400)  # let the screen transition finish
            screenshot(w.page, f"logo-waiting-{scheme}-{label}", full_page=False)
            assert failed == [], failed
            w.assert_clean()


def test_logo_link_keeps_running_scan_resumable(servers, watched):
    page = watched().page
    start_scan(page, servers.app, servers.big, max_pages="500", external=False)
    screen(page, "running", timeout=15000)
    job_id = page.url.split("#/job/")[1]
    page.click("#home-link")
    screen(page, "start")
    assert "#/job/" not in page.url
    expect(page.locator("#resume-banner")).to_contain_text("is still going")
    page.click("#resume-link")
    screen(page, "running", timeout=15000)
    assert page.url.endswith(f"#/job/{job_id}")
    page.click("#home-link")
    page.go_back()
    screen(page, "running", timeout=15000)
    page.click("#running-cancel")
    screen(page, "results", timeout=15000)


def test_start_screen_and_validation(servers, watched, screenshot):
    for scheme in ("light", "dark"):
        for label, vp in (("desktop", DESKTOP), ("mobile", MOBILE)):
            w = watched(scheme=scheme, viewport=vp)
            w.page.goto(servers.app)
            if label == "desktop":
                w.page.click("#options summary")
            screenshot(w.page, f"start-{scheme}-{label}")
            w.assert_clean()

    page = watched().page
    page.goto(servers.app)
    page.click("#scan-btn")
    expect(page.locator("#url-error")).to_contain_text("Enter a website address")
    page.fill("#url-input", "ftp://example.com")
    page.click("#scan-btn")
    expect(page.locator("#url-error")).to_contain_text("Only http")


def test_scan_results_reports_and_xss(servers, watched, screenshot, tmp_path):
    w = watched(accept_downloads=True)
    w.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=servers.app)
    page = w.page
    start_scan(page, servers.app, servers.site, max_pages="250", images=True)
    page.wait_for_url(re.compile(r"#/job/"))
    job_id = page.url.split("#/job/")[1]
    screen(page, "results", timeout=60000)

    # Results UI: every hostile payload is visible text, nothing executed
    for toggle in page.query_selector_all(".issue-toggle"):
        toggle.click()
    page.hover("text=<b onmouseover")
    body = page.inner_text("main")
    for needle in XSS_NEEDLES:
        assert needle in body
    assert_no_live_payloads(page)
    w.assert_clean()
    assert "broken links on 127.0.0.1" in page.inner_text("#results-title")
    screenshot(page, "results-light-desktop")

    # Filters and search
    page.click("#filter-chips >> text=DNS")
    assert page.locator(".issue-toggle").count() == 1
    page.click("#filter-chips >> text=All")
    page.fill("#search", "xss")
    assert page.locator(".issue-toggle").count() == 4
    page.fill("#search", "")

    # Download CSV through the real button
    with page.expect_download() as info:
        page.click("#download-csv")
    download = info.value
    assert re.fullmatch(r"link-check_127\.0\.0\.1_\d{4}-\d{2}-\d{2}\.csv", download.suggested_filename)
    csv_path = tmp_path / download.suggested_filename
    download.save_as(csv_path)
    raw = csv_path.read_text(encoding="utf-8")
    assert raw.startswith("﻿")
    rows = list(csv.DictReader(io.StringIO(raw[1:])))
    _, job = api(servers.app, "GET", f"/api/jobs/{job_id}")
    assert len(rows) == len(job["issues"])
    by_url = {r["broken_url"]: r for r in rows}
    assert by_url[f"{servers.site}/missing.html"]["status_code"] == "404"
    assert by_url[f"{servers.site}/xss1"]["link_text"] == "<script>window.__xss=1;alert(1)</script>"
    assert by_url[f"{servers.site}/formula"]["link_text"].startswith("'=HYPERLINK(")
    assert by_url["https://no-such-host.invalid/"]["type"] == "dns_error"

    # Download the HTML report, then open the downloaded file itself
    with page.expect_download() as info:
        page.click("#download-html")
    html_path = tmp_path / info.value.suggested_filename
    info.value.save_as(html_path)
    html = html_path.read_text(encoding="utf-8")
    assert html_path.suffix == ".html"
    assert re.search(r"<(script|img|iframe)\b", html, re.I) is None
    assert "&lt;script&gt;window.__xss=1" in html
    offline = watched()
    offline.page.goto(html_path.as_uri())
    offline.page.hover("text=<b onmouseover")
    offline.assert_clean()

    # Copy share link: clipboard API path
    page.click("[data-action=copy-share]")
    expect(page.locator("#toast")).to_contain_text("Link copied. Temporary")
    share_url = page.evaluate("navigator.clipboard.readText()")
    assert share_url == f"{servers.app}/report/{job_id}"
    screenshot(page, "results-toast", full_page=False)

    # Copy share link: fallback path when there's no clipboard API
    fallback = watched()
    fallback.page.add_init_script("Object.defineProperty(navigator, 'clipboard', { value: undefined })")
    fallback.page.goto(f"{servers.app}/#/job/{job_id}")
    screen(fallback.page, "results")
    fallback.page.click("[data-action=copy-share]")
    expect(fallback.page.locator("#toast")).to_contain_text("Link copied")

    # The shareable report page, in all four layouts
    for scheme in ("light", "dark"):
        for label, vp in (("desktop", DESKTOP), ("mobile", MOBILE)):
            r = watched(scheme=scheme, viewport=vp)
            response = r.page.goto(share_url)
            assert response.status == 200
            assert "default-src 'none'" in response.headers["content-security-policy"]
            assert response.headers["x-robots-tag"] == "noindex"
            text = r.page.inner_text("body")
            for needle in XSS_NEEDLES:
                assert needle in text
            r.page.hover("text=<b onmouseover")
            r.assert_clean()
            assert r.page.evaluate("document.querySelectorAll('script, img').length") == 0
            screenshot(r.page, f"report-{scheme}-{label}")

    # Results in the other layouts, reached through the hash URL (refresh-safe)
    for scheme, vp, name in (("dark", DESKTOP, "dark-desktop"), ("light", MOBILE, "light-mobile"), ("dark", MOBILE, "dark-mobile")):
        r = watched(scheme=scheme, viewport=vp)
        r.page.goto(f"{servers.app}/#/job/{job_id}")
        screen(r.page, "results")
        screenshot(r.page, f"results-{name}")
        r.assert_clean()


def test_long_scan_reload_queue_and_cancel(servers, watched, screenshot):
    w = watched()
    page = w.page
    start_scan(page, servers.app, servers.big, max_pages="500", external=False)
    screen(page, "running", timeout=15000)
    job_id = page.url.split("#/job/")[1]
    page.wait_for_timeout(3000)
    screenshot(page, "running-light-desktop")

    # The share page explains the report isn't ready yet
    status, _ = api(servers.app, "GET", f"/api/jobs/{job_id}/report.csv")
    assert status == 409
    live = watched()
    response = live.page.goto(f"{servers.app}/report/{job_id}")
    assert response.status == 409
    assert live.page.get_attribute("a.btn", "href") == f"/#/job/{job_id}"

    # Reload mid-scan resumes polling with the feed refilled
    before = int(page.inner_text("#run-pages").replace(",", ""))
    page.reload()
    screen(page, "running", timeout=15000)
    page.wait_for_timeout(1500)
    assert int(page.inner_text("#run-pages").replace(",", "")) >= before
    assert 0 < page.locator("#feed li").count() <= 50

    for scheme, vp, name in (("dark", DESKTOP, "dark-desktop"), ("light", MOBILE, "light-mobile"), ("dark", MOBILE, "dark-mobile")):
        r = watched(scheme=scheme, viewport=vp)
        r.page.goto(page.url)
        screen(r.page, "running")
        r.page.wait_for_timeout(1000)
        screenshot(r.page, f"running-{name}")

    # A second scan waits in line and can be cancelled
    q = watched().page
    start_scan(q, servers.app, servers.site)
    q.wait_for_selector("text=in line", timeout=10000)
    assert "#1 in line" in q.inner_text("#waiting-title")
    screenshot(q, "queued-light-desktop")
    q.click("#waiting-actions button")
    q.wait_for_selector("text=Scan cancelled", timeout=10000)

    # Cancel the running scan: "Stopping…", then partial results with working downloads
    page.click("#running-cancel")
    assert "STOPPING" in page.inner_text("#running-cancel").upper()
    screen(page, "results", timeout=15000)
    assert page.is_visible("#cancelled-banner")
    assert page.get_attribute("#download-csv", "href") == f"/api/jobs/{job_id}/report.csv"
    status, _ = api(servers.app, "GET", f"/api/jobs/{job_id}/report.csv")
    assert status == 200
    screenshot(page, "results-cancelled")
    w.assert_clean()


def test_not_found_and_expired_report(servers, watched):
    page = watched().page
    page.goto(f"{servers.app}/#/job/doesnotexist")
    page.wait_for_selector("text=couldn’t find that scan")
    page.goto(f"{servers.app}/#/job/%3Cscript%3E")
    page.reload()
    page.wait_for_selector("text=couldn’t find that scan")
    page.click('button:has-text("Start a new scan")')
    screen(page, "start")

    response = page.goto(f"{servers.app}/report/doesnotexist")
    assert response.status == 404
    assert "24 hours" in page.inner_text("body")


def test_queue_full_message(servers, watched):
    _, running = api(servers.app, "POST", "/api/jobs", {"url": servers.big, "max_pages": 500, "check_external": False})
    try:
        wait_status(servers.app, running["id"], "running")
        queued = [api(servers.app, "POST", "/api/jobs", {"url": servers.site})[1]["id"] for _ in range(5)]
        page = watched().page
        page.goto(servers.app)
        page.fill("#url-input", servers.site)
        page.click("#scan-btn")
        expect(page.locator("#form-error")).to_contain_text("queue is full")
    finally:
        for job_id in locals().get("queued", []) + [running["id"]]:
            api(servers.app, "POST", f"/api/jobs/{job_id}/cancel")


def test_waking_up_messages(servers, watched):
    _, job = api(servers.app, "POST", "/api/jobs", {"url": servers.site, "check_external": False})
    wait_status(servers.app, job["id"], "done")

    slow = watched(scheme="dark").page
    slow.add_init_script("""
      const realFetch = window.fetch; let first = true;
      window.fetch = (...args) => {
        if (!first) return realFetch(...args);
        first = false;
        return new Promise(r => setTimeout(r, 6000)).then(() => realFetch(...args));
      };
    """)
    slow.goto(f"{servers.app}/#/job/{job['id']}")
    slow.wait_for_selector("text=Waking up the server", timeout=8000)
    screen(slow, "results", timeout=20000)

    flaky = watched().page
    calls = {"n": 0}

    def fail_once(route):
        calls["n"] += 1
        route.abort() if calls["n"] == 1 else route.continue_()

    flaky.route("**/api/jobs/*", fail_once)
    flaky.goto(f"{servers.app}/#/job/{job['id']}")
    flaky.wait_for_selector("text=Waking up the server", timeout=3000)
    screen(flaky, "results", timeout=10000)


def test_reduced_motion(servers, browser):
    _, job = api(servers.app, "POST", "/api/jobs", {"url": servers.site, "check_external": False})
    wait_status(servers.app, job["id"], "done")
    ctx = browser.new_context(reduced_motion="reduce")
    try:
        page = ctx.new_page()
        page.goto(f"{servers.app}/#/job/{job['id']}")
        screen(page, "results")
        page.click("[data-action=copy-share]")
        assert page.evaluate("document.getAnimations().length") == 0
        page.evaluate("renderWaking('https://example.com')")
        assert page.is_visible('[data-screen="waiting"] img.kite-float')  # logo stays, just doesn't float
        assert page.evaluate("document.getAnimations().length") == 0
    finally:
        ctx.close()


def test_rate_limited_poll_keeps_the_scan_view(servers, watched):
    _, job = api(servers.app, "POST", "/api/jobs", {"url": servers.site, "check_external": False})
    wait_status(servers.app, job["id"], "done")
    w = watched()
    page = w.page
    calls = {"n": 0}

    def limited(route):
        calls["n"] += 1
        if calls["n"] <= 2:
            route.fulfill(status=429, headers={"retry-after": "1", "content-type": "application/json"},
                          body='{"error": "You\'re making requests very quickly."}')
        else:
            route.continue_()

    page.route("**/api/jobs/*?since=*", limited)
    page.goto(f"{servers.app}/#/job/{job['id']}")
    page.wait_for_selector("text=Lots of traffic right now", timeout=5000)
    assert not page.is_visible('[data-screen="failed"]')
    screen(page, "results", timeout=10000)
    assert calls["n"] >= 3
    w.assert_clean()


def test_rate_limit_message_on_start(servers, watched):
    page = watched().page

    def limited(route):
        route.fulfill(status=429, headers={"retry-after": "3600", "content-type": "application/json"},
                      body='{"error": "You\'ve started a lot of scans lately. Try again in about 60 minutes."}')

    page.route("**/api/jobs", limited)
    page.goto(servers.app)
    page.fill("#url-input", servers.site)
    page.click("#scan-btn")
    expect(page.locator("#form-error")).to_have_text(
        "You've started a lot of scans lately. Try again in about 60 minutes.")
    screen(page, "start")

