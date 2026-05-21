from __future__ import annotations

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class TimewebProvider(CloudProvider):
    """
    Timeweb Cloud — public REST API v1.
    Docs: https://timeweb.cloud/api-docs
    Uses /floating-ips endpoints.
    """

    name = "timeweb"
    BASE = "https://api.timeweb.cloud/api/v1"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None

    async def connect(self) -> None:
        token = (self.cfg.model_extra or {}).get("api_token")
        if not token:
            raise AuthError("timeweb: api_token required")
        self._token = token
        self._client = httpx.AsyncClient(
            timeout=20.0,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client
        extra = self.cfg.model_extra or {}
        body = {"availability_zone": extra.get("availability_zone", "spb-1")}
        r = await self._client.post(f"{self.BASE}/floating-ips", json=body)
        if r.status_code in (401, 403):
            self.killswitch.auth_failed()
            raise AuthError(f"timeweb auth: {r.status_code}")
        self.killswitch.ok()
        if r.status_code >= 400:
            raise ProviderError(f"timeweb allocate: {r.status_code} {r.text}")
        fip = r.json().get("floating_ip") or r.json().get("ip") or r.json()
        return AllocatedAddress(ip=fip["ip"], external_id=str(fip["id"]))

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        server_id = (self.cfg.model_extra or {}).get("probe_server_id")
        if not server_id:
            raise ProviderError("timeweb: probe_server_id required")
        r = await self._client.post(
            f"{self.BASE}/floating-ips/{ip.external_id}/bind",
            json={"resource_type": "server", "resource_id": int(server_id)},
        )
        if r.status_code >= 400:
            raise ProviderError(f"timeweb associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.post(f"{self.BASE}/floating-ips/{ip.external_id}/unbind")

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.delete(f"{self.BASE}/floating-ips/{ip.external_id}")
