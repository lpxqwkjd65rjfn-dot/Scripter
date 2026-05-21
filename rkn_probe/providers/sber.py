from __future__ import annotations

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class SberCloudProvider(CloudProvider):
    """
    SberCloud Advanced — Huawei Cloud compatible API.
    EIP (Elastic IP) operated via VPC service.
    Docs: https://docs.sbercloud.ru/vpc/api-ref/
    Auth: AK/SK signed requests (SigV4-like). MVP uses token-auth via IAM.
    """

    name = "sber"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._vpc_url: str | None = None
        self._ecs_url: str | None = None

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=20.0)
        extra = self.cfg.model_extra or {}
        username = extra.get("username")
        password = extra.get("password")
        domain = extra.get("domain")
        project_id = extra.get("project_id")
        region = extra.get("region", "ru-moscow-1")
        if not all([username, password, domain, project_id]):
            raise AuthError("sber: username/password/domain/project_id required for IAM token auth")
        iam_url = f"https://iam.{region}.hc.sbercloud.ru/v3/auth/tokens"
        body = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "password": password,
                            "domain": {"name": domain},
                        }
                    },
                },
                "scope": {"project": {"id": project_id}},
            }
        }
        r = await self._client.post(iam_url, json=body)
        if r.status_code not in (200, 201):
            self.killswitch.auth_failed()
            raise AuthError(f"sber IAM: {r.status_code} {r.text}")
        self.killswitch.ok()
        self._token = r.headers.get("X-Subject-Token")
        self._vpc_url = f"https://vpc.{region}.hc.sbercloud.ru/v1/{project_id}"
        self._ecs_url = f"https://ecs.{region}.hc.sbercloud.ru/v1/{project_id}"

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def _h(self) -> dict[str, str]:
        return {"X-Auth-Token": self._token or "", "Content-Type": "application/json"}

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client and self._vpc_url
        body = {
            "publicip": {"type": "5_bgp"},
            "bandwidth": {"name": "probe-bw", "size": 5, "share_type": "PER"},
        }
        r = await self._client.post(f"{self._vpc_url}/publicips", headers=self._h(), json=body)
        if r.status_code >= 400:
            raise ProviderError(f"sber allocate: {r.status_code} {r.text}")
        pip = r.json()["publicip"]
        return AllocatedAddress(ip=pip["public_ip_address"], external_id=pip["id"])

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._vpc_url
        port_id = (self.cfg.model_extra or {}).get("probe_port_id")
        if not port_id:
            raise ProviderError("sber: probe_port_id required")
        body = {"publicip": {"port_id": port_id}}
        r = await self._client.put(
            f"{self._vpc_url}/publicips/{ip.external_id}", headers=self._h(), json=body
        )
        if r.status_code >= 400:
            raise ProviderError(f"sber associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._vpc_url
        body = {"publicip": {"port_id": None}}
        await self._client.put(
            f"{self._vpc_url}/publicips/{ip.external_id}", headers=self._h(), json=body
        )

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client and self._vpc_url
        await self._client.delete(
            f"{self._vpc_url}/publicips/{ip.external_id}", headers=self._h()
        )
