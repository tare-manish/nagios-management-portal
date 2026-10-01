"""Notification provider interface.

Providers are registered in a registry (see registry.py); nothing in the
engine knows about a specific transport. New transports (e.g. a WhatsApp
Business API, an SMS gateway) are added by implementing Provider.send() or
configured through the generic webhook provider.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Field:
    name: str
    label: str
    type: str = "text"          # text | number | bool | textarea | select | password
    required: bool = False
    secret: bool = False
    default: object = None
    options: list[str] = field(default_factory=list)
    help: str = ""


@dataclass
class Message:
    title: str
    body: str
    event_type: str
    severity: str               # critical | warning | ok | info
    host: str | None = None
    service: str | None = None
    state: str | None = None
    output: str | None = None
    url: str | None = None


class ProviderError(Exception):
    pass


class Provider:
    key: str = ""
    label: str = ""
    description: str = ""
    fields: list[Field] = []

    def send(self, settings: dict, secrets: dict, msg: Message) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def schema(self) -> dict:
        return {"key": self.key, "label": self.label, "description": self.description,
                "fields": [f.__dict__ for f in self.fields]}
