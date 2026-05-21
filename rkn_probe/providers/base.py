from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..config import ProviderConfig
from ..rate_limiter import Killswitch, RateLimiter


@dataclass
class AllocatedAddress:
    ip: str
    external_id: str


class ProviderError(RuntimeError):
    pass


class AuthError(ProviderError):
    pass


class CloudProvider(ABC):
    name: str = "base"

    def __init__(self, cfg: ProviderConfig, killswitch: Killswitch) -> None:
        self.cfg = cfg
        self.killswitch = killswitch
        self.limiter = RateLimiter(
            min_interval_seconds=cfg.min_interval_seconds,
            max_ops_per_hour=cfg.max_ops_per_hour,
        )

    async def __aenter__(self) -> "CloudProvider":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...

    @abstractmethod
    async def allocate_ip(self) -> AllocatedAddress:
        """Allocate a new floating/elastic IP."""

    @abstractmethod
    async def associate(self, ip: AllocatedAddress) -> None:
        """Attach IP to the configured probe VM."""

    @abstractmethod
    async def disassociate(self, ip: AllocatedAddress) -> None:
        """Detach IP from the probe VM."""

    @abstractmethod
    async def release(self, ip: AllocatedAddress) -> None:
        """Return the IP back to the pool."""

    async def safe_release(self, ip: AllocatedAddress) -> None:
        try:
            await self.disassociate(ip)
        except Exception:
            pass
        try:
            await self.release(ip)
        except Exception:
            pass
