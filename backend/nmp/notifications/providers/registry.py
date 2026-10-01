"""Provider registry. Add a provider by importing it here (or via register())."""
from __future__ import annotations

from .base import Provider
from .builtin import EmailProvider, SmsProvider, TeamsProvider, WebhookProvider, WebProvider, WhatsAppProvider

_REGISTRY: dict[str, Provider] = {}


def register(p: Provider) -> None:
    _REGISTRY[p.key] = p


for _p in (EmailProvider(), TeamsProvider(), WebhookProvider(), WhatsAppProvider(), SmsProvider(), WebProvider()):
    register(_p)


def get(key: str) -> Provider | None:
    return _REGISTRY.get(key)


def all_providers() -> list[Provider]:
    return list(_REGISTRY.values())
