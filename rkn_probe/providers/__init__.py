from __future__ import annotations

from typing import Type

from .base import CloudProvider
from .cdnvideo import CdnVideoProvider
from .mock import MockProvider
from .sber import SberCloudProvider
from .selectel import SelectelProvider
from .timeweb import TimewebProvider
from .ufohosting import UfoHostingProvider
from .vk import VkCloudProvider
from .yandex import YandexCloudProvider

REGISTRY: dict[str, Type[CloudProvider]] = {
    "selectel": SelectelProvider,
    "yandex": YandexCloudProvider,
    "vk": VkCloudProvider,
    "sber": SberCloudProvider,
    "timeweb": TimewebProvider,
    "ufohosting": UfoHostingProvider,
    "cdnvideo": CdnVideoProvider,
}

__all__ = ["CloudProvider", "REGISTRY", "MockProvider"]
