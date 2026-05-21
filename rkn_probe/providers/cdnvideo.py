from __future__ import annotations

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class CdnVideoProvider(CloudProvider):
    """
    CDNvideo — primarily a CDN; their cloud-compute API exposes
    floating-IP-like endpoints. Endpoint base is configurable.
    """

    name = "cdnvideo"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        extra = self.cfg.model_extra or {}
        token = extra.get("api_token")
        base = extra.get("api_base", "https://api.cdnvideo.ru")
        if not token:
            raise AuthError("cdnvideo: api_token required")
        self._client = httpx.AsyncClient(
            base_url=base,
            timeout=25.0,
            headers={"X-Auth-Token": token, "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client
        r = await self._client.post("/cloud/v1/floating_ips")
        if r.status_code in (401, 403):
            self.killswitch.auth_failed()
            raise AuthError(f"cdnvideo auth: {r.status_code}")
        self.killswitch.ok()
        if r.status_code >= 400:
            raise ProviderError(f"cdnvideo allocate: {r.status_code} {r.text}")
        data = r.json()
        return AllocatedAddress(ip=data["ip"], external_id=str(data["id"]))

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        server_id = (self.cfg.model_extra or {}).get("probe_server_id")
        if not server_id:
            raise ProviderError("cdnvideo: probe_server_id required")
        r = await self._client.post(
            f"/cloud/v1/floating_ips/{ip.external_id}/attach",
            json={"server_id": server_id},
        )
        if r.status_code >= 400:
            raise ProviderError(f"cdnvideo associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.post(f"/cloud/v1/floating_ips/{ip.external_id}/detach")

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.delete(f"/cloud/v1/floating_ips/{ip.external_id}")
