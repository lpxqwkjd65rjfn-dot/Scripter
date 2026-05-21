from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from dataclasses import dataclass, field


class KillswitchTripped(RuntimeError):
    """Raised when too many consecutive auth-errors observed."""


class CircuitOpen(RuntimeError):
    """Raised when provider circuit-breaker is open after repeated failures."""


@dataclass
class RateLimiter:
    """Per-provider throttle with rolling hour + day caps, jitter, error backoff."""

    min_interval_seconds: float
    max_ops_per_hour: int
    max_ops_per_day: int = 200
    jitter_pct: float = 0.35
    backoff_base_seconds: float = 30.0
    backoff_cap_seconds: float = 3600.0

    _lock: asyncio.Lock = field(default=None, init=False, repr=False)
    _last_ts: float = field(default=0.0, init=False)
    _ops_hour: deque = field(default_factory=deque, init=False)
    _ops_day: deque = field(default_factory=deque, init=False)
    _cooldown_until: float = field(default=0.0, init=False)
    _consecutive_errors: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()

    def _prune(self, now: float) -> None:
        hour_ago = now - 3600
        day_ago = now - 86400
        while self._ops_hour and self._ops_hour[0] < hour_ago:
            self._ops_hour.popleft()
        while self._ops_day and self._ops_day[0] < day_ago:
            self._ops_day.popleft()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._prune(now)

            if now < self._cooldown_until:
                wait = self._cooldown_until - now
                await asyncio.sleep(wait)
                now = time.monotonic()
                self._prune(now)

            if len(self._ops_day) >= self.max_ops_per_day:
                wait = 86400 - (now - self._ops_day[0])
                await asyncio.sleep(max(wait, 60.0))
                now = time.monotonic()
                self._prune(now)

            if len(self._ops_hour) >= self.max_ops_per_hour:
                wait = 3600 - (now - self._ops_hour[0])
                await asyncio.sleep(max(wait, 1.0))
                now = time.monotonic()
                self._prune(now)

            elapsed = now - self._last_ts
            base = self.min_interval_seconds
            jitter = base * self.jitter_pct
            needed = base + random.uniform(0.0, jitter * 2)
            if elapsed < needed:
                await asyncio.sleep(needed - elapsed)

            self._last_ts = time.monotonic()
            self._ops_hour.append(self._last_ts)
            self._ops_day.append(self._last_ts)

    def report_success(self) -> None:
        self._consecutive_errors = 0

    def report_error(self, retry_after_seconds: float | None = None) -> None:
        self._consecutive_errors += 1
        now = time.monotonic()
        if retry_after_seconds is not None and retry_after_seconds > 0:
            wait = retry_after_seconds + random.uniform(1.0, 5.0)
        else:
            backoff = self.backoff_base_seconds * (2 ** (self._consecutive_errors - 1))
            backoff = min(backoff, self.backoff_cap_seconds)
            wait = backoff + random.uniform(0.0, backoff * 0.25)
        self._cooldown_until = max(self._cooldown_until, now + wait)

    @property
    def is_cooling_down(self) -> bool:
        return time.monotonic() < self._cooldown_until

    @property
    def cooldown_remaining(self) -> float:
        return max(0.0, self._cooldown_until - time.monotonic())


class Killswitch:
    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self.count = 0
        self.tripped = False

    def auth_failed(self) -> None:
        self.count += 1
        if self.count >= self.threshold:
            self.tripped = True

    def ok(self) -> None:
        self.count = 0

    def check(self) -> None:
        if self.tripped:
            raise KillswitchTripped("Too many auth errors; aborting to protect account.")


class CircuitBreaker:
    """Trips after N consecutive provider errors (429/5xx/network)."""

    def __init__(self, failure_threshold: int = 5, reset_after_seconds: float = 1800.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_after_seconds = reset_after_seconds
        self.failures = 0
        self._opened_at: float | None = None

    def record_success(self) -> None:
        self.failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold and self._opened_at is None:
            self._opened_at = time.monotonic()

    def check(self) -> None:
        if self._opened_at is None:
            return
        if time.monotonic() - self._opened_at >= self.reset_after_seconds:
            self.failures = 0
            self._opened_at = None
            return
        remaining = self.reset_after_seconds - (time.monotonic() - self._opened_at)
        raise CircuitOpen(
            f"circuit open; cooling down {int(remaining)}s after {self.failures} failures"
        )
