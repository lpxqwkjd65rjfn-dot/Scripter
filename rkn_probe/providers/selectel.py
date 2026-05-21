from __future__ import annotations

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class SelectelProvider(CloudProvider):
    """
    Selectel Cloud (OpenStack-compatible).
    Uses the Selectel Cloud Platform v2 API (https://docs.selectel.ru/).
    Floating IPs are operated via OpenStack Neutron endpoint of the project.
    """

    name = "selectel"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._neutron_url: str | None = None

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=20.0)
        token = self.cfg.model_extra.get("api_token") if self.cfg.model_extra else None
        project = self.cfg.model_extra.get("project_id") if self.cfg.model_extra else None
        region = self.cfg.model_extra.get("region", "ru-1") if self.cfg.model_extra else "ru-1"
        if not token or not project:
            raise AuthError("selectel: api_token and project_id required")
        self._token = token
        self._neutron_url = f"https://{region}.cloud.api.selcloud.ru/network/v2.0"

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        return {"X-Auth-Token": self._token or "", "Content-Type": "application/json"}

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        ext_net = (self.cfg.model_extra or {}).get("external_network_id")
        body = {"floatingip": {"floating_network_id": ext_net} if ext_net else {}}
        r = await self._client.post(
            f"{self._neutron_url}/floatingips", headers=self._headers(), json=body
        )
        if r.status_code in (401, 403):
            self.killswitch.auth_failed()
            raise AuthError(f"selectel auth failed: {r.status_code}")
        self.killswitch.ok()
        if r.status_code >= 400:
            raise ProviderError(f"selectel allocate: {r.status_code} {r.text}")
        fip = r.json()["floatingip"]
        return AllocatedAddress(ip=fip["floating_ip_address"], external_id=fip["id"])

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        port_id = (self.cfg.model_extra or {}).get("probe_port_id")
        if not port_id:
            raise ProviderError("selectel: probe_port_id required to associate FIP")
        body = {"floatingip": {"port_id": port_id}}
        r = await self._client.put(
            f"{self._neutron_url}/floatingips/{ip.external_id}",
            headers=self._headers(),
            json=body,
        )
        if r.status_code >= 400:
            raise ProviderError(f"selectel associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        body = {"floatingip": {"port_id": None}}
        await self._client.put(
            f"{self._neutron_url}/floatingips/{ip.external_id}",
            headers=self._headers(),
            json=body,
        )

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        await self._client.delete(
            f"{self._neutron_url}/floatingips/{ip.external_id}",
            headers=self._headers(),
        )
