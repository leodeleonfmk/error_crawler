"""In-memory abuse limits. Valid only because we run a single uvicorn worker."""

from __future__ import annotations

import math
import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional

from starlette.requests import Request

MAX_TRACKED_KEYS = 50_000  # hard ceiling so a flood of distinct IPs can't exhaust memory


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class RateLimits:
    jobs_per_hour: int = 20
    active_jobs_per_ip: int = 2
    active_jobs_per_domain: int = 1
    api_per_minute: int = 120
    max_body_bytes: int = 4096

    @classmethod
    def from_env(cls) -> "RateLimits":
        return cls(
            jobs_per_hour=_env_int("RATE_LIMIT_JOBS_PER_HOUR", cls.jobs_per_hour),
            active_jobs_per_ip=_env_int("RATE_LIMIT_ACTIVE_JOBS_PER_IP", cls.active_jobs_per_ip),
            active_jobs_per_domain=_env_int("RATE_LIMIT_ACTIVE_JOBS_PER_DOMAIN", cls.active_jobs_per_domain),
            api_per_minute=_env_int("RATE_LIMIT_API_PER_MINUTE", cls.api_per_minute),
        )


def trusted_proxy_hops() -> int:
    return max(0, _env_int("TRUSTED_PROXY_HOPS", 0))


def client_ip(request: Request, hops: Optional[int] = None) -> str:
    """The client address we rate-limit on.

    hops=0: the socket peer. hops=N: the Nth X-Forwarded-For entry from the
    right, i.e. the address our Nth trusted proxy saw. The leftmost entries
    are whatever the client claimed and are never trusted.
    """
    hops = trusted_proxy_hops() if hops is None else hops
    peer = request.client.host if request.client else "unknown"
    if hops <= 0:
        return peer
    header = ",".join(request.headers.getlist("x-forwarded-for"))
    entries = [e.strip() for e in header.split(",") if e.strip()]
    if len(entries) < hops:
        return peer  # not behind the proxies we were told about; fall back to the peer
    return entries[-hops]


class SlidingWindow:
    """At most `limit` events per `window_s` per key."""

    def __init__(self, limit: int, window_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window_s = window_s
        self.clock = clock
        self._events: dict[str, deque] = {}

    def _trim(self, key: str, now: float) -> deque:
        events = self._events.get(key)
        if events is None:
            return deque()
        while events and events[0] <= now - self.window_s:
            events.popleft()
        if not events:
            del self._events[key]
        return events

    def retry_after(self, key: str) -> Optional[float]:
        """Seconds until the next event is allowed, or None if allowed now."""
        now = self.clock()
        events = self._trim(key, now)
        if len(events) < self.limit:
            return None
        return max(1.0, events[0] + self.window_s - now)

    def record(self, key: str) -> None:
        now = self.clock()
        if key not in self._events and len(self._events) >= MAX_TRACKED_KEYS:
            self.cleanup()
            while len(self._events) >= MAX_TRACKED_KEYS:  # still full: drop the oldest keys
                del self._events[next(iter(self._events))]
        self._events.setdefault(key, deque()).append(now)

    def hit(self, key: str) -> Optional[float]:
        """Check and record in one step. Returns retry-after seconds if limited."""
        wait = self.retry_after(key)
        if wait is None:
            self.record(key)
        return wait

    def cleanup(self) -> int:
        now = self.clock()
        stale = [k for k, ev in self._events.items() if not ev or ev[-1] <= now - self.window_s]
        for key in stale:
            del self._events[key]
        return len(stale)

    def __len__(self) -> int:
        return len(self._events)


def retry_after_header(seconds: float) -> dict:
    return {"Retry-After": str(max(1, math.ceil(seconds)))}


def minutes_text(seconds: float) -> str:
    minutes = max(1, math.ceil(seconds / 60))
    return "a minute" if minutes == 1 else f"{minutes} minutes"
