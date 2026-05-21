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
    tcp_ports: list[int] = Field(default_factory=lambda: [443, 80])
    tcp_timeout_seconds: float = 6.0
    http_timeout_seconds: float = 8.0
    icmp_enabled: bool = True
    killswitch_consecutive_auth_errors: int = 3
    state_file: str = "state.json"


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = False
    min_interval_seconds: float = 30.0
    max_ops_per_hour: int = 30
    published_cidrs: list[str] = Field(default_factory=list)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    global_: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)


def load_config(path: str | Path) -> AppConfig:
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(raw)
