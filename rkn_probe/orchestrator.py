from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import AsyncIterator, Callable

from .checker import CheckResult, IpChecker
from .config import AppConfig
from .providers import REGISTRY, MockProvider
from .providers.base import AllocatedAddress, CloudProvider
from .rate_limiter import Killswitch, KillswitchTripped
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

    def stop(self) -> None:
        self._stop.set()

    def _make_provider(self, name: str) -> CloudProvider:
        cfg = self.config.providers[name]
        if self.mock:
            return MockProvider(cfg, self.killswitch)
        cls = REGISTRY.get(name)
        if not cls:
            raise ValueError(f"Unknown provider: {name}")
        return cls(cfg, self.killswitch)

    async def run_provider(self, name: str, log: LogFn) -> AsyncIterator[ProbeUpdate]:
        cfg = self.config.providers[name]
        provider = self._make_provider(name)
        async with provider:
            while not self._stop.is_set():
                try:
                    self.killswitch.check()
                except KillswitchTripped as e:
                    log(ProbeUpdate(name, "killswitch", {"detail": str(e)}))
                    return

                try:
                    addr = await provider.allocate_ip()
                except Exception as exc:
                    log(ProbeUpdate(name, "error", {"phase": "allocate", "error": str(exc)}))
                    await asyncio.sleep(5)
                    continue

                self.state.add_allocated(
                    AllocatedIp(
                        provider=name,
                        ip=addr.ip,
                        external_id=addr.external_id,
                        allocated_at=asyncio.get_event_loop().time(),
                    )
                )
                self.state.save()
                log(ProbeUpdate(name, "allocated", {"ip": addr.ip}))

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

                await provider.safe_release(addr)
                self.state.remove_allocated(addr.ip)
                self.state.save()
                log(ProbeUpdate(name, "released", {"ip": addr.ip}))

    async def cleanup(self) -> None:
        for item in list(self.state.state.allocated):
            try:
                provider = self._make_provider(item.provider)
                async with provider:
                    await provider.safe_release(
                        AllocatedAddress(ip=item.ip, external_id=item.external_id)
                    )
            except Exception:
                pass
            self.state.remove_allocated(item.ip)
        self.state.save()
