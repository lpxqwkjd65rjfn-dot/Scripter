from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import AsyncIterator, Callable

from .checker import CheckResult, IpChecker
from .config import AppConfig
from .providers import REGISTRY, MockProvider
from .providers.base import AllocatedAddress, CloudProvider
from .rate_limiter import CircuitOpen, Killswitch, KillswitchTripped
from .state import AllocatedIp, StateStore


@dataclass
class ProbeUpdate:
    provider: str
    kind: str
    payload: dict


LogFn = Callable[[ProbeUpdate], None]


class Orchestrator:
    def __init__(self, config: AppConfig, state: StateStore, mock: bool = False) -> None:
        self.config = config
        self.state = state
        self.mock = mock
        self.checker = IpChecker(config.global_)
        self.killswitch = Killswitch(config.global_.killswitch_consecutive_auth_errors)
        self._stop = asyncio.Event()
        self._active_providers: set[str] = set()

    def stop(self) -> None:
        self._stop.set()

    def _make_provider(self, name: str) -> CloudProvider:
        cfg = self.config.providers[name]
        if self.mock:
            return MockProvider(cfg, self.killswitch, self.config.global_)
        cls = REGISTRY.get(name)
        if not cls:
            raise ValueError(f"Unknown provider: {name}")
        try:
            return cls(cfg, self.killswitch, self.config.global_)
        except TypeError:
            return cls(cfg, self.killswitch)

    async def _post_error_cooldown(self, name: str, log: LogFn, errors: int) -> None:
        base = max(5.0, float(self.config.providers[name].backoff_base_seconds))
        cap = float(self.config.providers[name].backoff_cap_seconds)
        wait = min(cap, base * (2 ** max(0, errors - 1)))
        wait += random.uniform(0, wait * 0.3)
        log(ProbeUpdate(name, "cooldown", {"seconds": int(wait), "errors": errors}))
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass

    async def run_provider(self, name: str, log: LogFn) -> AsyncIterator[ProbeUpdate]:
        if name in self._active_providers:
            log(ProbeUpdate(name, "error", {"phase": "start", "error": "already running"}))
            return
        self._active_providers.add(name)
        try:
            async for upd in self._run_provider_inner(name, log):
                yield upd
        finally:
            self._active_providers.discard(name)

    async def _run_provider_inner(self, name: str, log: LogFn) -> AsyncIterator[ProbeUpdate]:
        cfg = self.config.providers[name]
        provider = self._make_provider(name)
        consecutive_errors = 0
        async with provider:
            while not self._stop.is_set():
                try:
                    self.killswitch.check()
                except KillswitchTripped as e:
                    log(ProbeUpdate(name, "killswitch", {"detail": str(e)}))
                    return

                try:
                    provider.breaker.check()
                except CircuitOpen as e:
                    log(ProbeUpdate(name, "circuit_open", {"detail": str(e)}))
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=60)
                    except asyncio.TimeoutError:
                        pass
                    continue

                used_today = self.state.get_today_ops(name)
                if used_today >= cfg.max_ops_per_day:
                    log(ProbeUpdate(name, "daily_cap", {"used": used_today, "cap": cfg.max_ops_per_day}))
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=600)
                    except asyncio.TimeoutError:
                        pass
                    continue

                addr: AllocatedAddress | None = None
                try:
                    addr = await provider.allocate_ip()
                    self.state.incr_today_ops(name)
                except KillswitchTripped as e:
                    log(ProbeUpdate(name, "killswitch", {"detail": str(e)}))
                    return
                except CircuitOpen as e:
                    log(ProbeUpdate(name, "circuit_open", {"detail": str(e)}))
                    continue
                except Exception as exc:
                    consecutive_errors += 1
                    log(ProbeUpdate(name, "error", {"phase": "allocate", "error": str(exc)}))
                    await self._post_error_cooldown(name, log, consecutive_errors)
                    continue

                consecutive_errors = 0

                self.state.add_allocated(
                    AllocatedIp(
                        provider=name,
                        ip=addr.ip,
                        external_id=addr.external_id,
                        allocated_at=asyncio.get_event_loop().time(),
                    )
                )
                self.state.save()
                log(ProbeUpdate(name, "allocated", {"ip": addr.ip, "today_used": self.state.get_today_ops(name)}))

                associated = False
                try:
                    await provider.associate(addr)
                    associated = True
                except Exception as exc:
                    log(ProbeUpdate(name, "error", {"phase": "associate", "ip": addr.ip, "error": str(exc)}))

                check: CheckResult | None = None
                if associated:
                    check = await self.checker.check(addr.ip, cfg.published_cidrs)
                    for st in check.stages:
                        self.state.add_event(name, addr.ip, st.name, st.ok, st.detail)
                        log(ProbeUpdate(name, "stage", {
                            "ip": addr.ip, "stage": st.name, "ok": st.ok, "detail": st.detail,
                        }))

                if check and check.whitelisted:
                    self.state.mark_whitelisted(addr.ip)
                    self.state.save()
                    log(ProbeUpdate(name, "found", {"ip": addr.ip}))
                    return

                try:
                    await asyncio.wait_for(provider.safe_release(addr), timeout=60)
                except Exception as exc:
                    log(ProbeUpdate(name, "error", {"phase": "release", "ip": addr.ip, "error": str(exc)}))
                self.state.remove_allocated(addr.ip)
                self.state.save()
                log(ProbeUpdate(name, "released", {"ip": addr.ip}))

                cooldown = max(0.0, float(cfg.post_release_cooldown_seconds))
                if cooldown > 0:
                    cooldown += random.uniform(0, cooldown * 0.5)
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=cooldown)
                    except asyncio.TimeoutError:
                        pass

    async def cleanup(self) -> None:
        for item in list(self.state.state.allocated):
            try:
                provider = self._make_provider(item.provider)
                async with provider:
                    await asyncio.wait_for(
                        provider.safe_release(
                            AllocatedAddress(ip=item.ip, external_id=item.external_id)
                        ),
                        timeout=60,
                    )
            except Exception:
                pass
            self.state.remove_allocated(item.ip)
        self.state.save()
