from __future__ import annotations

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class VkCloudProvider(CloudProvider):
    """
    VK Cloud (formerly Mail.ru Cloud Solutions) — OpenStack Keystone v3 auth,
    Neutron for floating IPs.
    Docs: https://mcs.mail.ru/docs/networks/vnet/operations
    """

    name = "vk"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._neutron_url: str | None = None

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=20.0)
        extra = self.cfg.model_extra or {}
        auth_url = extra.get("auth_url")
        username = extra.get("username")
        password = extra.get("password")
        project_id = extra.get("project_id")
        domain = extra.get("domain", "users")
        if not all([auth_url, username, password, project_id]):
            raise AuthError("vk: auth_url/username/password/project_id required")

        body = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": {"name": domain},
                            "password": password,
                        }
                    },
                },
                "scope": {"project": {"id": project_id}},
            }
        }
        r = await self._client.post(f"{auth_url}/auth/tokens", json=body)
        if r.status_code not in (200, 201):
            self.killswitch.auth_failed()
            raise AuthError(f"vk keystone: {r.status_code} {r.text}")
        self.killswitch.ok()
        self._token = r.headers.get("X-Subject-Token")
        catalog = r.json()["token"]["catalog"]
        for svc in catalog:
            if svc["type"] == "network":
                for ep in svc["endpoints"]:
                    if ep["interface"] == "public":
                        self._neutron_url = ep["url"].rstrip("/")
                        break
        if not self._neutron_url:
            raise ProviderError("vk: neutron endpoint not found in catalog")

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def _h(self) -> dict[str, str]:
        return {"X-Auth-Token": self._token or "", "Content-Type": "application/json"}

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        ext_net = (self.cfg.model_extra or {}).get("external_network_id")
        body = {"floatingip": {"floating_network_id": ext_net} if ext_net else {}}
        r = await self._client.post(
            f"{self._neutron_url}/v2.0/floatingips", headers=self._h(), json=body
        )
        if r.status_code >= 400:
            raise ProviderError(f"vk allocate: {r.status_code} {r.text}")
        fip = r.json()["floatingip"]
        return AllocatedAddress(ip=fip["floating_ip_address"], external_id=fip["id"])

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        port_id = (self.cfg.model_extra or {}).get("probe_port_id")
        if not port_id:
            raise ProviderError("vk: probe_port_id required")
        body = {"floatingip": {"port_id": port_id}}
        r = await self._client.put(
            f"{self._neutron_url}/v2.0/floatingips/{ip.external_id}",
            headers=self._h(),
            json=body,
        )
        if r.status_code >= 400:
            raise ProviderError(f"vk associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        await self._client.put(
            f"{self._neutron_url}/v2.0/floatingips/{ip.external_id}",
            headers=self._h(),
            json={"floatingip": {"port_id": None}},
        )

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._neutron_url
        await self._client.delete(
            f"{self._neutron_url}/v2.0/floatingips/{ip.external_id}", headers=self._h()
        )
