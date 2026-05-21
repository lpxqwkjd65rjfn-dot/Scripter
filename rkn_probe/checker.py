from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass, field
from typing import Iterable

import httpx

from .config import GlobalConfig


@dataclass
class StageResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class CheckResult:
    ip: str
    stages: list[StageResult] = field(default_factory=list)

    @property
    def whitelisted(self) -> bool:
        critical = {"tcp", "tls", "http"}
        return all(s.ok for s in self.stages if s.name in critical) and any(
            s.name == "http" and s.ok for s in self.stages
        )


class IpChecker:
    def __init__(self, cfg: GlobalConfig) -> None:
        self.cfg = cfg

    async def check(
        self,
        ip: str,
        published_cidrs: Iterable[str] = (),
    ) -> CheckResult:
        result = CheckResult(ip=ip)

        result.stages.append(self._range_check(ip, list(published_cidrs)))

        if self.cfg.icmp_enabled:
            result.stages.append(await self._icmp(ip))

        tcp_stage = await self._tcp(ip)
        result.stages.append(tcp_stage)
        if not tcp_stage.ok:
            result.stages.append(StageResult("tls", False, "skipped: tcp failed"))
            result.stages.append(StageResult("http", False, "skipped: tcp failed"))
            return result

        result.stages.append(await self._tls(ip))
        result.stages.append(await self._http(ip))
        return result

    def _range_check(self, ip: str, cidrs: list[str]) -> StageResult:
        if not cidrs:
            return StageResult("range", True, "no cidrs configured")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            return StageResult("range", False, str(exc))
        for c in cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return StageResult("range", True, f"in {c}")
            except ValueError:
                continue
        return StageResult("range", False, "not in any published CIDR")

    async def _icmp(self, ip: str) -> StageResult:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", "1", "-w", "2000", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await proc.wait()
        return StageResult("icmp", rc == 0, f"rc={rc}")

    async def _tcp(self, ip: str) -> StageResult:
        for port in self.cfg.tcp_ports:
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.cfg.tcp_timeout_seconds)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return StageResult("tcp", True, f"port {port}")
            except (asyncio.TimeoutError, OSError):
                continue
        return StageResult("tcp", False, f"no ports open: {self.cfg.tcp_ports}")

    async def _tls(self, ip: str) -> StageResult:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            fut = asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=ip)
            reader, writer = await asyncio.wait_for(fut, timeout=self.cfg.tcp_timeout_seconds)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return StageResult("tls", True, "handshake ok")
        except Exception as exc:
            return StageResult("tls", False, f"{type(exc).__name__}: {exc}")

    async def _http(self, ip: str) -> StageResult:
        url = f"http://{ip}{self.cfg.http_probe_path}"
        try:
            async with httpx.AsyncClient(timeout=self.cfg.http_timeout_seconds, verify=False) as cli:
                r = await cli.get(url)
                marker = r.headers.get(self.cfg.http_probe_marker_header, "")
                if marker == self.cfg.http_probe_marker_value:
                    return StageResult("http", True, f"status={r.status_code}")
                return StageResult("http", False, f"marker mismatch: {marker!r}")
        except Exception as exc:
            return StageResult("http", False, f"{type(exc).__name__}: {exc}")
