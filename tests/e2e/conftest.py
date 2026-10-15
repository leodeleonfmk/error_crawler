"""Fixtures for the browser tests: real uvicorn + two local test sites + Chrome.

Run with:  pytest -m e2e
"""

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SITE_DIR = Path(__file__).resolve().parent / "fixtures" / "site"
BIG_SITE_PAGES = 500


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(url: str, timeout: float = 20) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"{url} did not come up")


def _write_big_site(directory: Path) -> None:
    """A 500-page chain where every page also links to one missing page: a slow crawl."""
    (directory / "index.html").write_text('<a href="/p0.html">start</a>')
    for i in range(BIG_SITE_PAGES):
        (directory / f"p{i}.html").write_text(
            f'<a href="/p{i + 1}.html">next</a> <a href="/p{i + 2}.html">skip</a> <a href="/gone{i}.html">gone</a>'
        )


@pytest.fixture(scope="session")
def servers(tmp_path_factory):
    big_dir = tmp_path_factory.mktemp("bigsite")
    _write_big_site(big_dir)
    site_port, big_port, app_port = _free_port(), _free_port(), _free_port()
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    procs = [
        subprocess.Popen([sys.executable, "-m", "http.server", str(site_port), "--bind", "127.0.0.1", "-d", str(SITE_DIR)], **quiet),
        subprocess.Popen([sys.executable, "-m", "http.server", str(big_port), "--bind", "127.0.0.1", "-d", str(big_dir)], **quiet),
        subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(app_port)], cwd=ROOT, **quiet),
    ]
    try:
        ns = SimpleNamespace(
            app=f"http://127.0.0.1:{app_port}",
            site=f"http://127.0.0.1:{site_port}",
            big=f"http://127.0.0.1:{big_port}",
        )
        for url in (ns.site, ns.big, ns.app + "/health"):
            _wait_for(url)
        yield ns
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            proc.wait(timeout=10)


@pytest.fixture(scope="session")
def browser():
    # Uses installed Google Chrome by default. Set PLAYWRIGHT_CHANNEL="" to use
    # Playwright's bundled Chromium (after `playwright install chromium`).
    sync_api = pytest.importorskip("playwright.sync_api")
    channel = os.environ.get("PLAYWRIGHT_CHANNEL", "chrome") or None
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(channel=channel)
        yield browser
        browser.close()


@pytest.fixture
def screenshot():
    """shot(page, name): saves to $E2E_SCREENSHOTS if set, otherwise does nothing."""
    out = os.environ.get("E2E_SCREENSHOTS")

    def shot(page, name, full_page=True):
        if out:
            Path(out).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(out) / f"{name}.png"), full_page=full_page)

    return shot
