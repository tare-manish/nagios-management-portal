"""Built-in providers: SMTP e-mail, Microsoft Teams webhook, generic HTTP webhook, in-app (web)."""
from __future__ import annotations

import json
import smtplib
import ssl
from email.message import EmailMessage
from string import Template

import httpx

from .base import Field, Message, Provider, ProviderError

COLORS = {"critical": "D13438", "warning": "F7B500", "ok": "2E9E44", "info": "0F6CBD"}


def _check_url(url: str) -> str:
    if not url or not (url.startswith("https://") or url.startswith("http://")):
        raise ProviderError("URL must start with https:// or http://")
    return url


class EmailProvider(Provider):
    key = "email"
    label = "E-mail (SMTP)"
    description = "Send alerts through an SMTP relay (Office 365, Gmail, internal relay...)"
    fields = [
        Field("host", "SMTP host", required=True), Field("port", "Port", "number", default=587),
        Field("security", "Security", "select", default="starttls", options=["starttls", "ssl", "none"]),
        Field("username", "Username"), Field("password", "Password", "password", secret=True),
        Field("from_address", "From address", required=True),
        Field("to_addresses", "Recipients (comma separated)", "textarea", required=True),
    ]

    def send(self, settings: dict, secrets: dict, msg: Message) -> None:
        em = EmailMessage()
        em["Subject"] = msg.title
        em["From"] = settings["from_address"]
        rcpt = [a.strip() for a in str(settings.get("to_addresses", "")).replace(";", ",").split(",") if a.strip()]
        if not rcpt:
            raise ProviderError("no recipients configured")
        em["To"] = ", ".join(rcpt)
        em.set_content(msg.body)
        port = int(settings.get("port") or 587)
        sec = settings.get("security", "starttls")
        ctx = ssl.create_default_context()
        try:
            if sec == "ssl":
                server = smtplib.SMTP_SSL(settings["host"], port, timeout=20, context=ctx)
            else:
                server = smtplib.SMTP(settings["host"], port, timeout=20)
            with server:
                if sec == "starttls":
                    server.starttls(context=ctx)
                if settings.get("username"):
                    server.login(settings["username"], secrets.get("password", ""))
                server.send_message(em)
        except (smtplib.SMTPException, OSError) as exc:
            raise ProviderError(f"SMTP error: {type(exc).__name__}: {str(exc)[:200]}")


class TeamsProvider(Provider):
    key = "teams"
    label = "Microsoft Teams (incoming webhook / Workflows)"
    description = "Posts an adaptive card to a Teams channel webhook URL"
    fields = [Field("webhook_url", "Webhook URL", "password", required=True, secret=True)]

    def send(self, settings: dict, secrets: dict, msg: Message) -> None:
        url = _check_url(secrets.get("webhook_url", ""))
        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": msg.title, "weight": "Bolder", "size": "Medium", "wrap": True,
                         "color": {"critical": "Attention", "warning": "Warning", "ok": "Good"}.get(msg.severity, "Default")},
                        {"type": "FactSet", "facts": [f for f in [
                            {"title": "Host", "value": msg.host or "-"},
                            {"title": "Service", "value": msg.service} if msg.service else None,
                            {"title": "State", "value": msg.state or "-"},
                        ] if f]},
                        {"type": "TextBlock", "text": (msg.output or "")[:1000], "wrap": True, "isSubtle": True},
                    ],
                },
            }],
        }
        try:
            r = httpx.post(url, json=card, timeout=15)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Teams webhook error: {type(exc).__name__}")
        if r.status_code >= 300:
            raise ProviderError(f"Teams webhook returned HTTP {r.status_code}")


class WebhookProvider(Provider):
    key = "webhook"
    label = "Generic HTTP webhook"
    description = ("POST/PUT a JSON or form body to any HTTP API. Use this for WhatsApp Business API, SMS "
                   "gateways, ITSM tools, etc. Body placeholders: $title $body $host $service $state $severity "
                   "$event_type $output")
    fields = [
        Field("url", "URL", "password", required=True, secret=True, help="May contain API keys; stored encrypted"),
        Field("method", "Method", "select", default="POST", options=["POST", "PUT"]),
        Field("content_type", "Content type", "select", default="application/json",
              options=["application/json", "application/x-www-form-urlencoded"]),
        Field("headers", "Extra headers (JSON object)", "textarea", secret=True, default="{}"),
        Field("body_template", "Body template", "textarea",
              default='{"title": "$title", "text": "$body", "severity": "$severity"}'),
    ]

    def send(self, settings: dict, secrets: dict, msg: Message) -> None:
        url = _check_url(secrets.get("url", ""))
        try:
            headers = json.loads(secrets.get("headers") or "{}")
            if not isinstance(headers, dict):
                raise ValueError
        except ValueError:
            raise ProviderError("headers must be a JSON object")
        values = {k: json.dumps(v or "")[1:-1] for k, v in {
            "title": msg.title, "body": msg.body, "host": msg.host, "service": msg.service, "state": msg.state,
            "severity": msg.severity, "event_type": msg.event_type, "output": msg.output}.items()}
        body = Template(settings.get("body_template") or '{"text": "$body"}').safe_substitute(values)
        ctype = settings.get("content_type", "application/json")
        headers = {str(k): str(v) for k, v in headers.items()}
        headers.setdefault("Content-Type", ctype)
        try:
            r = httpx.request(settings.get("method", "POST"), url, content=body.encode("utf-8"), headers=headers,
                              timeout=15)
        except httpx.HTTPError as exc:
            raise ProviderError(f"webhook error: {type(exc).__name__}")
        if r.status_code >= 300:
            raise ProviderError(f"webhook returned HTTP {r.status_code}")


class WhatsAppProvider(WebhookProvider):
    key = "whatsapp"
    label = "WhatsApp (via HTTP API)"
    description = "WhatsApp Business / BSP gateway through its HTTP API (configure URL, headers and body template)."


class SmsProvider(WebhookProvider):
    key = "sms"
    label = "SMS (via HTTP gateway)"
    description = "Any SMS gateway with an HTTP API (configure URL, headers and body template)."


class WebProvider(Provider):
    key = "web"
    label = "Web (in-app notifications)"
    description = "Shows notifications in the portal's notification centre"
    fields = []

    def send(self, settings: dict, secrets: dict, msg: Message) -> None:
        return None  # the Notification row itself is the delivery
