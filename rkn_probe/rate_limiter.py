from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from dataclasses import dataclass


class KillswitchTripped(RuntimeError):
    """Raised when too many consecutive auth-errors observed."""


@dataclass
class RateLimiter:
    """Per-provider throttle with rolling-hour ops cap and jitter."""

    min_interval_seconds: float
    max_ops_per_hour: int
    jitter_pct: float = 0.2

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()
        self._last_ts: float = 0.0
        self._ops: deque[float] = deque()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            hour_ago = now - 3600
            while self._ops and self._ops[0] < hour_ago:
                self._ops.popleft()
            if len(self._ops) >= self.max_ops_per_hour:
                wait = 3600 - (now - self._ops[0])
                await asyncio.sleep(max(wait, 1.0))
                now = time.monotonic()

            elapsed = now - self._last_ts
            base = self.min_interval_seconds
            jitter = base * self.jitter_pct
            needed = base + random.uniform(-jitter, jitter)
            if elapsed < needed:
                await asyncio.sleep(needed - elapsed)

            self._last_ts = time.monotonic()
            self._ops.append(self._last_ts)


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
