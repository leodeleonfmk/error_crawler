"""In-memory background crawl jobs: one FIFO queue, one crawl at a time.

State lives in this process only (single uvicorn worker), so jobs are lost on
restart.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Awaitable, Callable, Optional
from urllib.parse import urlsplit

from app.crawler import UrlValidator, crawl, site_host
from app.models import CrawlOptions, CrawlResult, CrawlStats, Issue
from app.security import validate_url

log = logging.getLogger(__name__)

CrawlFn = Callable[..., Awaitable[CrawlResult]]

MAX_QUEUED_JOBS = 5
JOB_TIMEOUT_S = 10 * 60
# Extra time for a crawl to wind down after its cancel_event is set before we
# give up on it and cancel the task outright.
CANCEL_GRACE_S = 30
CLEANUP_INTERVAL_S = 5 * 60
JOB_RETENTION = timedelta(hours=24)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def finished(self) -> bool:
        return self in (JobStatus.DONE, JobStatus.CANCELLED, JobStatus.FAILED)


class QueueFullError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _empty_stats() -> dict:
    return {"pages_crawled": 0, "links_checked": 0, "errors_found": 0, "warnings_found": 0, "current_url": ""}


@dataclass
class Job:
    id: str
    url: str
    options: CrawlOptions
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime = field(default_factory=_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    stats: dict = field(default_factory=_empty_stats)
    issues: list[Issue] = field(default_factory=list)
    result: Optional[CrawlResult] = None
    error_message: Optional[str] = None
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    client_ip: Optional[str] = None  # for per-IP limits; never exposed by the API

    @property
    def domain(self) -> str:
        """Target site for per-domain limits: lowercase host, www stripped, port ignored."""
        return site_host(urlsplit(self.url).hostname or "")


class JobManager:
    def __init__(
        self,
        crawl_fn: CrawlFn = crawl,
        url_validator: UrlValidator = validate_url,
        max_queued: int = MAX_QUEUED_JOBS,
        job_timeout_s: float = JOB_TIMEOUT_S,
        cleanup_interval_s: float = CLEANUP_INTERVAL_S,
        retention: timedelta = JOB_RETENTION,
    ) -> None:
        self.crawl_fn = crawl_fn
        self.url_validator = url_validator
        self.max_queued = max_queued
        self.job_timeout_s = job_timeout_s
        self.cleanup_interval_s = cleanup_interval_s
        self.retention = retention
        self.jobs: dict[str, Job] = {}
        self._queue: deque[str] = deque()
        self._has_work: Optional[asyncio.Event] = None  # created in start(), inside the loop
        self._tasks: list[asyncio.Task] = []
        self._running: Optional[Job] = None

    # --- lifecycle ---

    async def start(self) -> None:
        self._has_work = asyncio.Event()
        if self._queue:
            self._has_work.set()
        self._tasks = [
            asyncio.create_task(self._worker(), name="crawl-worker"),
            asyncio.create_task(self._cleanup_loop(), name="job-cleanup"),
        ]

    async def stop(self) -> None:
        if self._running is not None:
            self._running.cancel_event.set()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    # --- public API ---

    def submit(self, url: str, options: CrawlOptions, client_ip: Optional[str] = None) -> Job:
        if len(self._queue) >= self.max_queued:
            raise QueueFullError(
                f"The queue is full ({self.max_queued} crawls waiting). Please try again in a few minutes."
            )
        job = Job(id=self._new_id(), url=url, options=options, client_ip=client_ip)
        self.jobs[job.id] = job
        self._queue.append(job.id)
        if self._has_work is not None:
            self._has_work.set()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def active_jobs(self) -> list:
        return [j for j in self.jobs.values() if j.status in (JobStatus.QUEUED, JobStatus.RUNNING)]

    def active_count_for_ip(self, client_ip: str) -> int:
        return sum(1 for j in self.active_jobs() if j.client_ip == client_ip)

    def active_count_for_domain(self, domain: str) -> int:
        return sum(1 for j in self.active_jobs() if j.domain == domain)

    def queue_position(self, job: Job) -> Optional[int]:
        """1 = next to run. None if the job isn't waiting."""
        if job.status != JobStatus.QUEUED:
            return None
        try:
            return self._queue.index(job.id) + 1
        except ValueError:
            return None

    def cancel(self, job: Job) -> Job:
        if job.status == JobStatus.QUEUED:
            try:
                self._queue.remove(job.id)
            except ValueError:
                pass
            job.status = JobStatus.CANCELLED
            job.finished_at = _now()
        elif job.status == JobStatus.RUNNING:
            job.cancel_event.set()  # crawler stops cleanly; _run records partial results
        return job

    def cleanup(self) -> int:
        cutoff = _now() - self.retention
        expired = [j.id for j in self.jobs.values() if j.finished_at and j.finished_at < cutoff]
        for job_id in expired:
            del self.jobs[job_id]
        return len(expired)

    # --- internals ---

    def _new_id(self) -> str:
        while True:
            job_id = secrets.token_urlsafe(9)  # 72 random bits, 12 url-safe chars; ids are unguessable
            if job_id not in self.jobs:
                return job_id

    async def _worker(self) -> None:
        assert self._has_work is not None
        while True:
            if not self._queue:
                self._has_work.clear()
                await self._has_work.wait()
                continue
            job = self.jobs.get(self._queue.popleft())
            if job is None or job.status != JobStatus.QUEUED:
                continue
            try:
                await self._run(job)
            except Exception:  # _run handles crawl errors; this guards bookkeeping bugs
                log.exception("Worker error on job %s", job.id)
                if not job.status.finished:
                    job.status = JobStatus.FAILED
                    job.error_message = "Something went wrong while running this crawl."
                    job.finished_at = _now()

    async def _run(self, job: Job) -> None:
        job.status = JobStatus.RUNNING
        job.started_at = _now()
        self._running = job

        def on_progress(stats: CrawlStats) -> None:
            job.stats.update(
                pages_crawled=stats.pages_crawled,
                links_checked=stats.links_checked,
                errors_found=stats.errors_found,
                warnings_found=stats.warnings_found,
                current_url=stats.current_url,
            )
            job.issues.extend(stats.new_issues)

        timed_out = False

        def on_timeout() -> None:
            nonlocal timed_out
            timed_out = True
            job.cancel_event.set()

        timer = asyncio.get_running_loop().call_later(self.job_timeout_s, on_timeout)
        try:
            result = await asyncio.wait_for(
                self.crawl_fn(
                    job.url,
                    job.options,
                    on_progress=on_progress,
                    cancel_event=job.cancel_event,
                    url_validator=self.url_validator,
                ),
                timeout=self.job_timeout_s + CANCEL_GRACE_S,
            )
        except asyncio.TimeoutError:
            log.error("Job %s ignored its cancel signal and was force-stopped", job.id)
            job.status = JobStatus.FAILED
            job.error_message = "The crawl took too long and was stopped."
        except Exception:
            log.exception("Crawl failed for job %s (%s)", job.id, job.url)
            job.status = JobStatus.FAILED
            job.error_message = "The crawl failed unexpectedly. Please try again, or try a different URL."
        else:
            job.result = result
            job.issues = list(result.issues)  # authoritative; the live list is a prefix of it
            job.stats.update(
                pages_crawled=result.pages_crawled,
                links_checked=result.links_checked,
                errors_found=result.errors_found,
                warnings_found=result.warnings_found,
            )
            if result.cancelled:
                job.status = JobStatus.CANCELLED
                if timed_out:
                    minutes = round(self.job_timeout_s / 60)
                    job.error_message = f"Stopped after the {minutes}-minute time limit. Partial results are shown."
            else:
                job.status = JobStatus.DONE
        finally:
            timer.cancel()
            job.stats["current_url"] = ""
            job.finished_at = _now()
            self._running = None

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(self.cleanup_interval_s)
            try:
                removed = self.cleanup()
                if removed:
                    log.info("Removed %d expired jobs", removed)
            except Exception:
                log.exception("Job cleanup failed")
