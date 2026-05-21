from __future__ import annotations

import asyncio
import ipaddress
import random
import ssl
import time
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
        """An IP is considered whitelisted only when the strict critical
        set ALL pass. Range + ICMP are advisory, never sole proof."""
        critical = {"tcp_stability", "tls", "http_marker"}
        results = {s.name: s.ok for s in self.stages}
        for c in critical:
            if not results.get(c, False):
                return False
        return True


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
        await self._jitter()

        if self.cfg.icmp_enabled:
            result.stages.append(await self._icmp(ip))
            await self._jitter()

        tcp_stage, rtt_ms = await self._tcp_first_open(ip)
        result.stages.append(tcp_stage)
        if not tcp_stage.ok:
            for name in ("tcp_stability", "latency", "tls", "http_marker", "https_marker"):
                result.stages.append(StageResult(name, False, "skipped: tcp failed"))
            return result
        await self._jitter()

        result.stages.append(StageResult(
            "latency", rtt_ms <= self.cfg.latency_max_ms,
            f"first-byte rtt {rtt_ms:.0f}ms (max {self.cfg.latency_max_ms:.0f})",
        ))
        await self._jitter()

        result.stages.append(await self._tcp_stability(ip))
        await self._jitter()

        result.stages.append(await self._tls(ip))
        await self._jitter()

        result.stages.append(await self._http_marker(ip, scheme="http", port=80))
        await self._jitter()

        if self.cfg.https_probe_enabled:
            result.stages.append(await self._http_marker(ip, scheme="https", port=443))

        return result

    async def _jitter(self) -> None:
        j = max(0.0, float(self.cfg.inter_stage_jitter_seconds))
        if j > 0:
            await asyncio.sleep(random.uniform(0, j))

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
        count = max(1, int(self.cfg.icmp_count))
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", str(count), "-w", "2000", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore")
        ok = proc.returncode == 0 and ("TTL=" in text or "ttl=" in text)
        return StageResult("icmp", ok, f"rc={proc.returncode}, count={count}")

    async def _open_once(self, ip: str, port: int) -> tuple[bool, float]:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.cfg.tcp_timeout_seconds)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, (time.monotonic() - t0) * 1000.0
        except (asyncio.TimeoutError, OSError):
            return False, (time.monotonic() - t0) * 1000.0

    async def _tcp_first_open(self, ip: str) -> tuple[StageResult, float]:
        last_rtt = 0.0
        for port in self.cfg.tcp_ports:
            ok, rtt = await self._open_once(ip, port)
            last_rtt = rtt
            if ok:
                return StageResult("tcp", True, f"port {port} rtt {rtt:.0f}ms"), rtt
        return StageResult("tcp", False, f"no ports open: {self.cfg.tcp_ports}"), last_rtt

    async def _tcp_stability(self, ip: str) -> StageResult:
        attempts = max(1, int(self.cfg.tcp_stability_attempts))
        required = max(1, int(self.cfg.tcp_stability_required))
        port = self.cfg.tcp_ports[0]
        successes = 0
        details = []
        for i in range(attempts):
            ok, rtt = await self._open_once(ip, port)
            details.append(f"{'+' if ok else '-'}{rtt:.0f}ms")
            if ok:
                successes += 1
            await asyncio.sleep(random.uniform(0.2, 0.6))
        return StageResult(
            "tcp_stability",
            successes >= required,
            f"{successes}/{attempts} on :{port} [{','.join(details)}]",
        )

    async def _tls(self, ip: str) -> StageResult:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            fut = asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=ip)
            reader, writer = await asyncio.wait_for(fut, timeout=self.cfg.tcp_timeout_seconds)
            cert_present = False
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is not None:
                    cert = ssl_obj.getpeercert(binary_form=True)
                    cert_present = bool(cert)
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return StageResult(
                "tls", True,
                f"handshake ok, peer_cert={'yes' if cert_present else 'no'}",
            )
        except Exception as exc:
            return StageResult("tls", False, f"{type(exc).__name__}: {exc}")

    async def _http_marker(self, ip: str, *, scheme: str, port: int) -> StageResult:
        stage_name = "http_marker" if scheme == "http" else "https_marker"
        url = f"{scheme}://{ip}:{port}{self.cfg.http_probe_path}"
        retries = max(0, int(self.cfg.http_retries))
        last_err = ""
        for attempt in range(retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=self.cfg.http_timeout_seconds,
                    verify=False,
                    follow_redirects=False,
                    headers={"User-Agent": "rkn-probe/checker"},
                ) as cli:
                    r = await cli.get(url)
                    marker = r.headers.get(self.cfg.http_probe_marker_header, "")
                    if marker == self.cfg.http_probe_marker_value:
                        return StageResult(stage_name, True, f"status={r.status_code}")
                    last_err = f"marker mismatch: {marker!r}, status={r.status_code}"
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                await asyncio.sleep(random.uniform(0.5, 1.5))
        return StageResult(stage_name, False, last_err)
