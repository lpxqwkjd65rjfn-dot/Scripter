from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class GlobalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    http_probe_path: str = "/probe"
    http_probe_marker_header: str = "X-Probe"
    http_probe_marker_value: str = "ok"
    https_probe_enabled: bool = True

    tcp_ports: list[int] = Field(default_factory=lambda: [443, 80])
    tcp_timeout_seconds: float = 6.0
    tcp_stability_attempts: int = 3
    tcp_stability_required: int = 2

    http_timeout_seconds: float = 8.0
    http_retries: int = 1

    icmp_enabled: bool = True
    icmp_count: int = 3

    latency_max_ms: float = 2000.0
    inter_stage_jitter_seconds: float = 0.3

    killswitch_consecutive_auth_errors: int = 3

    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 1800.0

    polite_user_agent: str = "rkn-probe/1.0 (+contact: owner@example.com)"

    state_file: str = "state.json"


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = False
    min_interval_seconds: float = 60.0
    max_ops_per_hour: int = 20
    max_ops_per_day: int = 120
    jitter_pct: float = 0.35
    backoff_base_seconds: float = 30.0
    backoff_cap_seconds: float = 3600.0
    post_release_cooldown_seconds: float = 5.0
    api_retry_attempts: int = 3
    api_retry_base_seconds: float = 2.0
    published_cidrs: list[str] = Field(default_factory=list)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    global_: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)


def load_config(path: str | Path) -> AppConfig:
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(raw)
