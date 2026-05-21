from __future__ import annotations

import asyncio
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import GlobalConfig, ProviderConfig
from ..rate_limiter import CircuitBreaker, Killswitch, RateLimiter


@dataclass
class AllocatedAddress:
    ip: str
    external_id: str


class ProviderError(RuntimeError):
    pass


class AuthError(ProviderError):
    pass


class RateLimited(ProviderError):
    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


class CloudProvider(ABC):
    name: str = "base"

    def __init__(
        self,
        cfg: ProviderConfig,
        killswitch: Killswitch,
        global_cfg: GlobalConfig | None = None,
    ) -> None:
        self.cfg = cfg
        self.global_cfg = global_cfg or GlobalConfig()
        self.killswitch = killswitch
        self.limiter = RateLimiter(
            min_interval_seconds=cfg.min_interval_seconds,
            max_ops_per_hour=cfg.max_ops_per_hour,
            max_ops_per_day=cfg.max_ops_per_day,
            jitter_pct=cfg.jitter_pct,
            backoff_base_seconds=cfg.backoff_base_seconds,
            backoff_cap_seconds=cfg.backoff_cap_seconds,
        )
        self.breaker = CircuitBreaker(
            failure_threshold=self.global_cfg.circuit_failure_threshold,
            reset_after_seconds=self.global_cfg.circuit_reset_seconds,
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
            await asyncio.wait_for(self.disassociate(ip), timeout=30)
        except Exception:
            pass
        try:
            await asyncio.wait_for(self.release(ip), timeout=30)
        except Exception:
            pass

    def polite_headers(self) -> dict[str, str]:
        return {"User-Agent": self.global_cfg.polite_user_agent}

    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """HTTP request with retries, exponential backoff, Retry-After respect."""
        attempts = max(1, int(self.cfg.api_retry_attempts))
        base = max(0.5, float(self.cfg.api_retry_base_seconds))
        merged_headers = self.polite_headers()
        if headers:
            merged_headers.update(headers)

        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = await client.request(method, url, json=json, headers=merged_headers)
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_exc = exc
                self.breaker.record_failure()
                self.limiter.report_error()
                if attempt + 1 >= attempts:
                    raise ProviderError(f"network error after {attempts} attempts: {exc}") from exc
                sleep_for = base * (2 ** attempt) + random.uniform(0, base)
                await asyncio.sleep(sleep_for)
                continue

            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                self.breaker.record_failure()
                self.limiter.report_error(retry_after_seconds=retry_after)
                if attempt + 1 >= attempts:
                    if resp.status_code == 429:
                        raise RateLimited(
                            f"{method} {url} -> 429", retry_after=retry_after
                        )
                    raise ProviderError(
                        f"{method} {url} -> {resp.status_code} {resp.text[:200]}"
                    )
                sleep_for = (retry_after if retry_after else base * (2 ** attempt)) + random.uniform(0, base)
                await asyncio.sleep(sleep_for)
                continue

            self.breaker.record_success()
            self.limiter.report_success()
            return resp

        if last_exc:
            raise ProviderError(str(last_exc))
        raise ProviderError("request failed for unknown reason")
