from __future__ import annotations

import asyncio
import random
import uuid

from .base import AllocatedAddress, CloudProvider


class MockProvider(CloudProvider):
    """Dry-run provider for local testing without API keys."""

    name = "mock"

    async def connect(self) -> None:
        await asyncio.sleep(0.1)

    async def close(self) -> None:
        await asyncio.sleep(0)

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        await asyncio.sleep(0.2)
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return AllocatedAddress(ip=ip, external_id=str(uuid.uuid4()))

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        await asyncio.sleep(0.1)

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        await asyncio.sleep(0.1)

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        await asyncio.sleep(0.1)
