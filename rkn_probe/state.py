from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ProbeEvent:
    ts: float
    provider: str
    ip: str
    stage: str
    ok: bool
    detail: str = ""


@dataclass
class AllocatedIp:
    provider: str
    ip: str
    external_id: str
    allocated_at: float
    associated_to: str | None = None


@dataclass
class AppState:
    events: list[ProbeEvent] = field(default_factory=list)
    allocated: list[AllocatedIp] = field(default_factory=list)
    whitelisted: list[str] = field(default_factory=list)
    daily_ops: dict[str, dict[str, int]] = field(default_factory=dict)


class StateStore:
    """Thread-safe JSON-backed state for audit & graceful shutdown."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self.state = AppState()
        if self._path.exists():
            self._load()

    @staticmethod
    def _today_key() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self.state = AppState(
                events=[ProbeEvent(**e) for e in raw.get("events", [])],
                allocated=[AllocatedIp(**a) for a in raw.get("allocated", [])],
                whitelisted=list(raw.get("whitelisted", [])),
                daily_ops=dict(raw.get("daily_ops", {})),
            )
        except Exception:
            self.state = AppState()

    def save(self) -> None:
        with self._lock:
            self._gc_daily_ops_locked()
            data: dict[str, Any] = {
                "events": [asdict(e) for e in self.state.events[-1000:]],
                "allocated": [asdict(a) for a in self.state.allocated],
                "whitelisted": self.state.whitelisted,
                "daily_ops": self.state.daily_ops,
            }
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self._path)

    def _gc_daily_ops_locked(self) -> None:
        today = self._today_key()
        keep = {today}
        self.state.daily_ops = {
            k: v for k, v in self.state.daily_ops.items() if k in keep
        }

    def add_event(self, provider: str, ip: str, stage: str, ok: bool, detail: str = "") -> None:
        with self._lock:
            self.state.events.append(
                ProbeEvent(ts=time.time(), provider=provider, ip=ip, stage=stage, ok=ok, detail=detail)
            )

    def add_allocated(self, item: AllocatedIp) -> None:
        with self._lock:
            self.state.allocated.append(item)

    def remove_allocated(self, ip: str) -> None:
        with self._lock:
            self.state.allocated = [a for a in self.state.allocated if a.ip != ip]

    def mark_whitelisted(self, ip: str) -> None:
        with self._lock:
            if ip not in self.state.whitelisted:
                self.state.whitelisted.append(ip)

    def get_today_ops(self, provider: str) -> int:
        today = self._today_key()
        with self._lock:
            return int(self.state.daily_ops.get(today, {}).get(provider, 0))

    def incr_today_ops(self, provider: str) -> int:
        today = self._today_key()
        with self._lock:
            bucket = self.state.daily_ops.setdefault(today, {})
            bucket[provider] = int(bucket.get(provider, 0)) + 1
            return bucket[provider]
