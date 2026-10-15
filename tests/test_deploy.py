"""Deployment config guards and production-readiness checks."""

import logging
import re
import shlex
from pathlib import Path

import httpx
import pytest

from app.jobs import JobManager
from app.main import create_app
from app.ratelimit import RateLimits
from test_api import FakeCrawl

ROOT = Path(__file__).resolve().parent.parent
RENDER_YAML = (ROOT / "render.yaml").read_text()


# --- render.yaml -------------------------------------------------------------------


def start_command() -> list:
    match = re.search(r"^\s*startCommand:\s*(.+)$", RENDER_YAML, re.M)
    assert match, "render.yaml needs a startCommand"
    return shlex.split(match.group(1))


def test_render_yaml_never_enables_private_hosts():
    assert "ALLOW_PRIVATE_HOSTS" not in RENDER_YAML, "the SSRF escape hatch must never be in deploy config"


def test_render_yaml_runs_one_worker_without_proxy_headers():
    cmd = start_command()
    assert cmd[:2] == ["uvicorn", "app.main:app"]
    assert cmd.count("--workers") == 1 and cmd[cmd.index("--workers") + 1] == "1", "in-memory state needs exactly 1 worker"
    assert not any(c.startswith("--workers=") for c in cmd)
    assert "--no-proxy-headers" in cmd, "TRUSTED_PROXY_HOPS must be the only X-Forwarded-For logic"
    assert "--reload" not in cmd and "--proxy-headers" not in cmd


def test_render_yaml_basics():
    for line in ("runtime: python", "plan: free", "healthCheckPath: /health",
                 "buildCommand: pip install -r requirements.txt"):
        assert line in RENDER_YAML
    assert re.search(r"key: TRUSTED_PROXY_HOPS\s+value: \"1\"", RENDER_YAML)
    assert re.search(r"key: CONTACT_URL\s+sync: false", RENDER_YAML)


def test_python_version_pinned_consistently():
    file_version = (ROOT / ".python-version").read_text().strip()
    yaml_version = re.search(r"key: PYTHON_VERSION\s+value: (\S+)", RENDER_YAML).group(1)
    assert re.fullmatch(r"3\.\d+\.\d+", yaml_version), "Render needs a full x.y.z PYTHON_VERSION"
    assert yaml_version == file_version


# --- app behavior in production --------------------------------------------------------


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_HOSTS", raising=False)
    manager = JobManager(crawl_fn=FakeCrawl())
    app = create_app(manager, RateLimits(api_per_minute=3))
    await manager.start()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c
    await manager.stop()


@pytest.mark.anyio
async def test_health_is_cheap_and_never_rate_limited(client):
    for _ in range(4):
        await client.get("/api/jobs/nope")
    assert (await client.get("/api/jobs/nope")).status_code == 429  # limiter is active...
    for _ in range(50):
        resp = await client.get("/health")  # ...but /health is exempt
        assert resp.status_code == 200 and resp.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_startup_and_client_ip_log_lines(monkeypatch, caplog):
    monkeypatch.delenv("ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.setenv("RENDER_GIT_COMMIT", "0123456789abcdef0123")
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    app = create_app(JobManager(crawl_fn=FakeCrawl()))
    caplog.set_level(logging.INFO)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
            for i in range(5):
                await c.get("/health", headers={"x-forwarded-for": f"6.6.6.6, 203.0.113.{i}"})
    messages = [r.getMessage() for r in caplog.records]
    assert "Starting Link Checker (commit 0123456789ab)" in messages
    assert any(m.startswith("TRUSTED_PROXY_HOPS=1") for m in messages)
    ip_lines = [m for m in messages if m.startswith("Client IP check")]
    assert len(ip_lines) == 3  # first 3 requests only
    assert "resolved=203.0.113.0" in ip_lines[0] and "6.6.6.6, 203.0.113.0" in ip_lines[0]
    assert not any("ALLOW_PRIVATE_HOSTS" in m for m in messages)


@pytest.mark.anyio
async def test_startup_warns_loudly_when_private_hosts_allowed(monkeypatch, caplog):
    monkeypatch.setenv("ALLOW_PRIVATE_HOSTS", "1")
    app = create_app(JobManager(crawl_fn=FakeCrawl()))
    caplog.set_level(logging.INFO)
    async with app.router.lifespan_context(app):
        pass
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "ALLOW_PRIVATE_HOSTS=1" in r.getMessage()]
    assert warnings
