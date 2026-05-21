from __future__ import annotations

import time

import httpx

from .base import AllocatedAddress, AuthError, CloudProvider, ProviderError


class YandexCloudProvider(CloudProvider):
    """
    Yandex Cloud — VPC API.
    Allocates a public address and attaches via instances.updateNetworkInterface.
    Docs: https://cloud.yandex.ru/docs/vpc/api-ref/Address/
    """

    name = "yandex"
    VPC = "https://vpc.api.cloud.yandex.net/vpc/v1"
    COMPUTE = "https://compute.api.cloud.yandex.net/compute/v1"
    IAM = "https://iam.api.cloud.yandex.net/iam/v1"

    def __init__(self, cfg, killswitch) -> None:
        super().__init__(cfg, killswitch)
        self._client: httpx.AsyncClient | None = None
        self._iam_token: str | None = None
        self._iam_expires: float = 0.0

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=20.0)
        await self._refresh_token()

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    async def _refresh_token(self) -> None:
        assert self._client
        extra = self.cfg.model_extra or {}
        oauth = extra.get("oauth_token")
        if not oauth:
            raise AuthError("yandex: oauth_token required")
        r = await self._client.post(f"{self.IAM}/tokens", json={"yandexPassportOauthToken": oauth})
        if r.status_code >= 400:
            self.killswitch.auth_failed()
            raise AuthError(f"yandex IAM: {r.status_code} {r.text}")
        self.killswitch.ok()
        self._iam_token = r.json()["iamToken"]
        self._iam_expires = time.time() + 60 * 50

    async def _headers(self) -> dict[str, str]:
        if not self._iam_token or time.time() > self._iam_expires:
            await self._refresh_token()
        return {"Authorization": f"Bearer {self._iam_token}", "Content-Type": "application/json"}

    async def allocate_ip(self) -> AllocatedAddress:
        await self.limiter.acquire()
        assert self._client
        extra = self.cfg.model_extra or {}
        folder_id = extra.get("folder_id")
        if not folder_id:
            raise ProviderError("yandex: folder_id required")
        body = {
            "folderId": folder_id,
            "externalIpv4AddressSpec": {"zoneId": extra.get("zone_id", "ru-central1-a")},
        }
        r = await self._client.post(f"{self.VPC}/addresses", headers=await self._headers(), json=body)
        if r.status_code >= 400:
            raise ProviderError(f"yandex allocate: {r.status_code} {r.text}")
        op = r.json()
        addr_id = op.get("metadata", {}).get("addressId") or op.get("response", {}).get("id")
        ip = op.get("response", {}).get("externalIpv4Address", {}).get("address")
        if not ip or not addr_id:
            raise ProviderError(f"yandex allocate: unexpected response {op}")
        return AllocatedAddress(ip=ip, external_id=addr_id)

    async def associate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        extra = self.cfg.model_extra or {}
        instance_id = extra.get("probe_instance_id")
        nic_index = extra.get("network_interface_index", 0)
        if not instance_id:
            raise ProviderError("yandex: probe_instance_id required")
        body = {
            "networkInterfaceIndex": str(nic_index),
            "oneToOneNat": {"address": ip.ip, "ipVersion": "IPV4"},
            "updateMask": "oneToOneNatSpec",
        }
        r = await self._client.post(
            f"{self.COMPUTE}/instances/{instance_id}:updateNetworkInterface",
            headers=await self._headers(),
            json=body,
        )
        if r.status_code >= 400:
            raise ProviderError(f"yandex associate: {r.status_code} {r.text}")

    async def disassociate(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        extra = self.cfg.model_extra or {}
        instance_id = extra.get("probe_instance_id")
        nic_index = extra.get("network_interface_index", 0)
        body = {
            "networkInterfaceIndex": str(nic_index),
            "oneToOneNat": None,
            "updateMask": "oneToOneNatSpec",
        }
        await self._client.post(
            f"{self.COMPUTE}/instances/{instance_id}:updateNetworkInterface",
            headers=await self._headers(),
            json=body,
        )

    async def release(self, ip: AllocatedAddress) -> None:
        await self.limiter.acquire()
        assert self._client
        await self._client.delete(
            f"{self.VPC}/addresses/{ip.external_id}", headers=await self._headers()
        )
