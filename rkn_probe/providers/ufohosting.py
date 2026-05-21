from __future__ import annotations

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class UfoHostingProvider(CloudProvider):
    """
    UFOhosting — public API (token-based).
    NOTE: vendor docs are limited; endpoint paths below are based on the
    billing-panel REST API. Adjust `api_base` and routes in config if needed.
    """

    name = "ufohosting"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        extra = self.cfg.model_extra or {}
        token = extra.get("api_token")
        base = extra.get("api_base", "https://my.ufohosting.ru/api/v1")
        if not token:
            raise AuthError("ufohosting: api_token required")
        self._client = httpx.AsyncClient(
            base_url=base,
            timeout=25.0,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client
        r = await self._client.post("/ips", json={"type": "ipv4"})
        if r.status_code in (401, 403):
            self.killswitch.auth_failed()
            raise AuthError(f"ufohosting auth: {r.status_code}")
        self.killswitch.ok()
        if r.status_code >= 400:
            raise ProviderError(f"ufohosting allocate: {r.status_code} {r.text}")
        data = r.json()
        return AllocatedAddress(ip=data["address"], external_id=str(data["id"]))

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        server_id = (self.cfg.model_extra or {}).get("probe_server_id")
        if not server_id:
            raise ProviderError("ufohosting: probe_server_id required")
        r = await self._client.post(f"/ips/{ip.external_id}/attach", json={"server_id": server_id})
        if r.status_code >= 400:
            raise ProviderError(f"ufohosting associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.post(f"/ips/{ip.external_id}/detach")

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.delete(f"/ips/{ip.external_id}")
