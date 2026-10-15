"""FastAPI app: wraps the crawler as background jobs. Run with a single worker:

    uvicorn app.main:app --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException

from app.crawler import normalize_url, site_host
from app.jobs import Job, JobManager, JobStatus, QueueFullError
from app.models import MAX_PAGES_HARD_CAP, CrawlOptions
from app.ratelimit import (
    RateLimits,
    SlidingWindow,
    client_ip,
    minutes_text,
    retry_after_header,
    trusted_proxy_hops,
)
from app.reports import build_csv, build_html, build_message_page, report_filename
from app.security import NOT_ALLOWED_MESSAGE, log_startup_warnings

log = logging.getLogger(__name__)
if not logging.getLogger().handlers:  # uvicorn only configures its own loggers
    # stdout at INFO so Render's log viewer shows startup and client-IP lines.
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(levelname)s:     %(name)s - %(message)s")
logging.getLogger("app").setLevel(logging.INFO)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
JOB_NOT_FOUND = (
    "Job not found. Reports are kept for 24 hours and can be lost when the server restarts; "
    "please start a new check."
)
REPORT_STATUSES = (JobStatus.DONE, JobStatus.CANCELLED)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
RATE_LIMIT_CLEANUP_S = 300
CLIENT_IP_LOG_COUNT = 3
# The HTML report contains attacker-controlled text; lock it down even though it's escaped.
REPORT_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex",
    "Referrer-Policy": "no-referrer",
}


class JobCreate(BaseModel):
    url: str = Field(max_length=2048)
    max_pages: int = 100
    check_external: bool = True
    check_images: bool = False

    @field_validator("url")
    @classmethod
    def check_url(cls, value: str) -> str:
        """Syntax only. Policy (schemes, userinfo, hosts, ports) is the URL validator's job,
        so the raw value is returned un-normalized for it to inspect."""
        value = value.strip()
        if not value:
            raise ValueError("Enter a valid http(s) URL, e.g. https://example.com")
        if "://" not in value:
            if re.match(r"[a-z][a-z0-9+.-]*:(?!\d)", value, re.I):  # mailto:, javascript:, ... (not host:port)
                raise ValueError("Enter a valid http(s) URL, e.g. https://example.com")
            value = "https://" + value
        try:
            parts = urlsplit(value)
            parts.port
        except ValueError:
            raise ValueError("Enter a valid http(s) URL, e.g. https://example.com")
        if parts.scheme.lower() not in ("http", "https"):
            return value  # rejected by the validator with the generic "not allowed" message
        host = parts.hostname or ""
        if not (re.fullmatch(r"[\w.-]+", host) or ":" in host):  # ":" = IPv6 literal
            raise ValueError("Enter a valid http(s) URL, e.g. https://example.com")
        return value

    @field_validator("max_pages")
    @classmethod
    def clamp_max_pages(cls, value: int) -> int:
        return max(1, min(value, MAX_PAGES_HARD_CAP))


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def job_payload(manager: JobManager, job: Job, since: int = 0) -> dict:
    issues = job.issues[since:]
    payload = {
        "id": job.id,
        "url": job.url,
        "status": job.status.value,
        "queue_position": manager.queue_position(job),
        "options": {
            "max_pages": job.options.max_pages,
            "check_external": job.options.check_external,
            "check_images": job.options.check_images,
        },
        "stats": dict(job.stats),
        "created_at": _iso(job.created_at),
        "started_at": _iso(job.started_at),
        "finished_at": _iso(job.finished_at),
        "error_message": job.error_message,
        "summary": None,
        "issues": [i.to_dict() for i in issues],
        "next_since": len(job.issues),
    }
    if job.result is not None:
        r = job.result
        payload["summary"] = {
            "duration_s": r.duration_s,
            "robots_skipped": r.robots_skipped,
            "page_limit_reached": r.page_limit_reached,
            "pages_truncated": r.pages_truncated,
            "url_cap_reached": r.url_cap_reached,
            "link_cap_pages": r.link_cap_pages,
            "external_cap_reached": r.external_cap_reached,
            "counts_by_type": r.counts_by_type,
        }
    return payload


def _error(status_code: int, message: str, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code, headers=headers)


def too_many(message: str, retry_after_s: float) -> HTTPException:
    return HTTPException(429, message, headers=retry_after_header(retry_after_s))


class BodySizeLimit:
    """Reject request bodies over max_bytes on the given POST paths with 413.

    Checks Content-Length up front and also counts streamed (chunked) bodies.
    """

    def __init__(self, app, max_bytes: int, paths: tuple) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.paths = paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in self.paths:
            return await self.app(scope, receive, send)
        length = dict(scope["headers"]).get(b"content-length", b"")
        if length.isdigit() and int(length) > self.max_bytes:
            return await self._reject(scope, receive, send)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(413, "That request is too large.")
            return message

        await self.app(scope, limited_receive, send)

    async def _reject(self, scope, receive, send):
        response = _error(413, "That request is too large.", SECURITY_HEADERS)
        await response(scope, receive, send)


def create_app(manager: Optional[JobManager] = None, limits: Optional[RateLimits] = None) -> FastAPI:
    manager = manager or JobManager()
    limits = limits or RateLimits.from_env()
    hops = trusted_proxy_hops()
    api_window = SlidingWindow(limits.api_per_minute, 60)
    jobs_window = SlidingWindow(limits.jobs_per_hour, 3600)
    ip_logs_left = [CLIENT_IP_LOG_COUNT]

    async def cleanup_rate_limits():
        while True:
            await asyncio.sleep(RATE_LIMIT_CLEANUP_S)
            api_window.cleanup()
            jobs_window.cleanup()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        commit = os.environ.get("RENDER_GIT_COMMIT", "")
        log.info("Starting Link Checker (commit %s)", commit[:12] if commit else "unknown")
        log_startup_warnings()
        log.info("TRUSTED_PROXY_HOPS=%d (client IP = %s)", hops,
                 "socket peer" if hops == 0 else f"X-Forwarded-For entry {hops} from the right")
        log.info("Rate limits: %s", limits)
        await manager.start()
        cleanup_task = asyncio.create_task(cleanup_rate_limits())
        yield
        cleanup_task.cancel()
        await manager.stop()

    app = FastAPI(title="Site Link Checker", lifespan=lifespan)
    app.state.jobs = manager
    app.state.rate_windows = {"api": api_window, "jobs": jobs_window}
    app.add_middleware(BodySizeLimit, max_bytes=limits.max_body_bytes, paths=("/api/jobs",))

    @app.middleware("http")
    async def guard(request: Request, call_next):
        ip = client_ip(request, hops)
        request.state.client_ip = ip
        if ip_logs_left[0] > 0:  # lets you verify TRUSTED_PROXY_HOPS on the real host
            ip_logs_left[0] -= 1
            log.info("Client IP check: resolved=%s peer=%s x-forwarded-for=%r", ip,
                     request.client.host if request.client else None, request.headers.get("x-forwarded-for"))
        path = request.url.path
        if path.startswith(("/api/", "/report/")):
            wait = api_window.hit(ip)
            if wait is not None:
                message = "You're making requests very quickly. Please wait a moment and try again."
                headers = {**retry_after_header(wait), **SECURITY_HEADERS}
                if path.startswith("/report/"):
                    page = build_message_page("Slow down a little", message, "/", "Back to Link Checker")
                    return HTMLResponse(page, status_code=429, headers=headers)
                return _error(429, message, headers)
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return _error(exc.status_code, str(exc.detail), getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        messages = []
        for err in exc.errors():
            msg = err["msg"].removeprefix("Value error, ")
            field = ".".join(str(p) for p in err["loc"] if p not in ("body", "query", "path"))
            messages.append(f"{field}: {msg}" if field else msg)
        return _error(422, "; ".join(messages))

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        log.exception("Unhandled error on %s", request.url.path)
        return _error(500, "Something went wrong", SECURITY_HEADERS)

    def get_job_or_404(job_id: str) -> Job:
        job = manager.get(job_id)
        if job is None:
            raise HTTPException(404, JOB_NOT_FOUND)
        return job

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/api/jobs", status_code=201)
    async def create_job(body: JobCreate, request: Request):
        ip = request.state.client_ip
        wait = jobs_window.retry_after(ip)
        if wait is not None:
            raise too_many(f"You've started a lot of scans lately. Try again in about {minutes_text(wait)}.", wait)
        if manager.active_count_for_ip(ip) >= limits.active_jobs_per_ip:
            raise too_many("You already have scans running or waiting. Try again when one of them finishes.", 60)

        # Same validator the crawler uses before every request; the generic message
        # never says why (no resolved IPs, no rule names).
        url = normalize_url(body.url)
        if not url or not await manager.url_validator(body.url):
            raise HTTPException(400, NOT_ALLOWED_MESSAGE)
        if manager.active_count_for_domain(site_host(urlsplit(url).hostname or "")) >= limits.active_jobs_per_domain:
            raise too_many("That site is already being scanned. Try again in a few minutes.", 120)

        options = CrawlOptions(
            max_pages=body.max_pages,
            check_external=body.check_external,
            check_images=body.check_images,
        )
        try:
            job = manager.submit(url, options, client_ip=ip)
        except QueueFullError as exc:
            raise too_many(str(exc), 60)
        jobs_window.record(ip)
        return {"id": job.id, "status": job.status.value, "queue_position": manager.queue_position(job)}

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str, since: int = Query(0, ge=0)):
        return job_payload(manager, get_job_or_404(job_id), since)

    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job(job_id: str):
        job = manager.cancel(get_job_or_404(job_id))
        return job_payload(manager, job, since=len(job.issues))

    # --- Reports ---

    def get_report_job(job_id: str) -> Job:
        job = get_job_or_404(job_id)
        if job.status not in REPORT_STATUSES:
            if job.status == JobStatus.FAILED:
                raise HTTPException(409, "This scan failed, so there's no report.")
            raise HTTPException(409, f"The report isn't ready yet: the scan is still {job.status.value}.")
        return job

    def attachment(filename: str) -> dict:
        return {"Content-Disposition": f'attachment; filename="{filename}"'}

    @app.get("/api/jobs/{job_id}/report.csv")
    async def report_csv(job_id: str):
        job = get_report_job(job_id)
        return Response(
            build_csv(job).encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers=attachment(report_filename(job, "csv")),
        )

    @app.get("/api/jobs/{job_id}/report.html")
    async def report_html_download(job_id: str):
        job = get_report_job(job_id)
        return HTMLResponse(build_html(job), headers={**REPORT_HEADERS, **attachment(report_filename(job, "html"))})

    @app.get("/report/{job_id}", response_class=HTMLResponse, include_in_schema=False)
    async def report_page(job_id: str):
        job = manager.get(job_id)
        if job is None:
            page = build_message_page(
                "This report has expired",
                "Reports are temporary: they're deleted after 24 hours and are lost when the server restarts. "
                "Run a new scan to get a fresh one.",
                "/", "Start a new scan",
            )
            return HTMLResponse(page, status_code=404, headers=REPORT_HEADERS)
        if job.status not in REPORT_STATUSES:
            if job.status == JobStatus.FAILED:
                page = build_message_page("This scan failed", job.error_message or "There's no report for this scan.",
                                          "/", "Start a new scan")
            else:
                page = build_message_page(
                    "This scan is still in progress",
                    f"The report will be ready when the scan finishes (it's {job.status.value} now).",
                    f"/#/job/{job.id}", "Watch it live",
                )
            return HTMLResponse(page, status_code=409, headers=REPORT_HEADERS)
        return HTMLResponse(build_html(job), headers=REPORT_HEADERS)

    return app


app = create_app()
