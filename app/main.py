"""FastAPI app: wraps the crawler as background jobs. Run with a single worker:

    uvicorn app.main:app --reload
"""

from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException

from app.crawler import normalize_url
from app.jobs import Job, JobManager, QueueFullError
from app.models import MAX_PAGES_HARD_CAP, CrawlOptions
from app.security import validate_url

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
JOB_NOT_FOUND = (
    "Job not found. Reports are kept for 24 hours and can be lost when the server restarts; "
    "please start a new check."
)


class JobCreate(BaseModel):
    url: str = Field(max_length=2048)
    max_pages: int = 100
    check_external: bool = True
    check_images: bool = False

    @field_validator("url")
    @classmethod
    def check_url(cls, value: str) -> str:
        value = value.strip()
        if value and "://" not in value:
            if re.match(r"[a-z][a-z0-9+.-]*:(?!\d)", value, re.I):  # mailto:, javascript:, ... (not host:port)
                raise ValueError("Enter a valid http(s) URL, e.g. https://example.com")
            value = "https://" + value
        normalized = normalize_url(value)
        host = (urlsplit(normalized).hostname or "") if normalized else ""
        if not (re.fullmatch(r"[\w.-]+", host) or ":" in host):  # ":" = IPv6 literal
            raise ValueError("Enter a valid http(s) URL, e.g. https://example.com")
        return normalized

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
            "counts_by_type": r.counts_by_type,
        }
    return payload


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def create_app(manager: Optional[JobManager] = None) -> FastAPI:
    manager = manager or JobManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await manager.start()
        yield
        await manager.stop()

    app = FastAPI(title="Site Link Checker", lifespan=lifespan)
    app.state.jobs = manager

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return _error(exc.status_code, str(exc.detail))

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
        return _error(500, "Internal server error")

    def get_job_or_404(job_id: str) -> Job:
        job = manager.get(job_id)
        if job is None:
            raise HTTPException(404, JOB_NOT_FOUND)
        return job

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/api/jobs", status_code=201)
    async def create_job(body: JobCreate):
        if not await validate_url(body.url):
            raise HTTPException(400, "This URL can't be checked.")
        options = CrawlOptions(
            max_pages=body.max_pages,
            check_external=body.check_external,
            check_images=body.check_images,
        )
        try:
            job = manager.submit(body.url, options)
        except QueueFullError as exc:
            raise HTTPException(429, str(exc))
        return {"id": job.id, "status": job.status.value, "queue_position": manager.queue_position(job)}

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str, since: int = Query(0, ge=0)):
        return job_payload(manager, get_job_or_404(job_id), since)

    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job(job_id: str):
        job = manager.cancel(get_job_or_404(job_id))
        return job_payload(manager, job, since=len(job.issues))

    return app


app = create_app()
