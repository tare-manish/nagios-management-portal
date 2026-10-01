"""Notification channels, rules and the in-app notification feed."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ... import validators as V
from ...audit import audit
from ...db import get_db, utcnow
from ...models import EVENT_TYPES, Notification, NotificationChannel, NotificationRule
from ...notifications.engine import send_test
from ...notifications.providers.base import ProviderError
from ...notifications.providers.registry import all_providers, get as get_provider
from ...security import crypto
from ..deps import Principal, ctx_from, require
from ..errors import ApiError
from ..util import iso, ok

router = APIRouter(tags=["notifications"])


@router.get("/api/notification-providers")
def providers(principal: Principal = Depends(require("notifications.manage"))):
    return ok([p.schema() for p in all_providers()], {"event_types": list(EVENT_TYPES)})


class ChannelIn(BaseModel):
    name: str
    provider: str
    settings: dict = Field(default_factory=dict)
    is_enabled: bool = True

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_free_text(v, "name", 100, required=True)


def channel_payload(c: NotificationChannel) -> dict:
    p = get_provider(c.provider)
    secret_fields = [f.name for f in p.fields if f.secret] if p else []
    stored = crypto.decrypt_json(c.secret_ciphertext, f"channel:{c.provider}") if c.secret_ciphertext else {}
    return {"id": c.id, "name": c.name, "provider": c.provider, "provider_label": p.label if p else c.provider,
            "settings": c.settings, "secrets_set": {k: bool(stored.get(k)) for k in secret_fields},
            "is_enabled": c.is_enabled, "updated_at": iso(c.updated_at)}


def _split(provider_key: str, data: dict, existing_secret: dict) -> tuple[dict, dict]:
    p = get_provider(provider_key)
    if p is None:
        raise ApiError(422, "validation_error", "Unknown provider", [{"field": "provider", "message": "unknown"}])
    settings, secrets = {}, dict(existing_secret)
    names = {f.name for f in p.fields}
    for k in data:
        if k not in names:
            raise ApiError(422, "validation_error", f"Unknown setting '{k}'", [{"field": f"settings.{k}", "message": "unknown"}])
    for f in p.fields:
        v = data.get(f.name)
        if f.secret:
            if v not in (None, ""):
                secrets[f.name] = str(v)[:4000]
            if f.required and not secrets.get(f.name):
                raise ApiError(422, "validation_error", f"{f.label} is required", [{"field": f"settings.{f.name}", "message": "required"}])
        else:
            if v in (None, ""):
                v = f.default
            if f.required and v in (None, ""):
                raise ApiError(422, "validation_error", f"{f.label} is required", [{"field": f"settings.{f.name}", "message": "required"}])
            if f.type == "select" and v is not None and f.options and v not in f.options:
                raise ApiError(422, "validation_error", f"Invalid value for {f.label}", [{"field": f"settings.{f.name}", "message": "invalid"}])
            if isinstance(v, str) and len(v) > 4000:
                raise ApiError(422, "validation_error", f"{f.label} is too long", [{"field": f"settings.{f.name}", "message": "too long"}])
            settings[f.name] = v
    return settings, secrets


@router.get("/api/notification-channels")
def list_channels(principal: Principal = Depends(require("notifications.manage")), db: Session = Depends(get_db)):
    return ok([channel_payload(c) for c in db.scalars(select(NotificationChannel).order_by(NotificationChannel.name))])


@router.post("/api/notification-channels", status_code=201)
def create_channel(body: ChannelIn, request: Request, principal: Principal = Depends(require("notifications.manage")),
                   db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    settings, secrets = _split(body.provider, body.settings, {})
    c = NotificationChannel(name=body.name, provider=body.provider, settings=settings, is_enabled=body.is_enabled,
                            secret_ciphertext=crypto.encrypt_json(secrets, f"channel:{body.provider}") if secrets else None,
                            created_by=ctx.user_id)
    db.add(c)
    db.flush()
    audit(db, ctx, "notification_channel.create", entity_type="notification_channel", entity_id=c.id, entity_name=c.name,
          new={"provider": c.provider, "settings": settings})
    db.commit()
    return ok(channel_payload(c))


@router.put("/api/notification-channels/{cid}")
def update_channel(cid: int, body: ChannelIn, request: Request, principal: Principal = Depends(require("notifications.manage")),
                   db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise ApiError(404, "not_found", "channel not found")
    if body.provider != c.provider:
        raise ApiError(422, "validation_error", "Provider cannot be changed", [{"field": "provider", "message": "immutable"}])
    old = {"settings": c.settings, "is_enabled": c.is_enabled, "name": c.name}
    existing = crypto.decrypt_json(c.secret_ciphertext, f"channel:{c.provider}") if c.secret_ciphertext else {}
    settings, secrets = _split(c.provider, body.settings, existing)
    c.name, c.settings, c.is_enabled = body.name, settings, body.is_enabled
    c.secret_ciphertext = crypto.encrypt_json(secrets, f"channel:{c.provider}") if secrets else None
    c.updated_by = ctx.user_id
    audit(db, ctx, "notification_channel.update", entity_type="notification_channel", entity_id=c.id, entity_name=c.name,
          old=old, new={"settings": settings, "is_enabled": c.is_enabled, "name": c.name})
    db.commit()
    return ok(channel_payload(c))


@router.delete("/api/notification-channels/{cid}")
def delete_channel(cid: int, request: Request, principal: Principal = Depends(require("notifications.manage")),
                   db: Session = Depends(get_db)):
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise ApiError(404, "not_found", "channel not found")
    audit(db, ctx_from(request, principal), "notification_channel.delete", entity_type="notification_channel",
          entity_id=c.id, entity_name=c.name)
    db.delete(c)
    db.commit()
    return ok({"deleted": True})


@router.post("/api/notification-channels/{cid}/test")
def test_channel(cid: int, request: Request, principal: Principal = Depends(require("notifications.manage")),
                 db: Session = Depends(get_db)):
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise ApiError(404, "not_found", "channel not found")
    try:
        send_test(c)
        result, err = "success", None
    except (ProviderError, crypto.CryptoError) as exc:
        result, err = "failure", str(exc)
    audit(db, ctx_from(request, principal), "notification_channel.test", entity_type="notification_channel",
          entity_id=c.id, entity_name=c.name, result=result, detail=err)
    db.commit()
    return ok({"ok": result == "success", "error": err})


class RuleIn(BaseModel):
    name: str
    event_types: list[str] = Field(min_length=1)
    channel_id: int
    throttle_minutes: int = Field(30, ge=0, le=10080)
    environments: list[str] = Field(default_factory=list)
    group_ids: list[int] = Field(default_factory=list)
    server_ids: list[int] = Field(default_factory=list)
    skip_acknowledged: bool = True
    is_enabled: bool = True

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_free_text(v, "name", 100, required=True)

    @field_validator("event_types")
    @classmethod
    def _e(cls, v):
        bad = [e for e in v if e not in EVENT_TYPES]
        if bad:
            raise ValueError(f"unknown event types: {', '.join(bad)}")
        return v

    @field_validator("environments")
    @classmethod
    def _env(cls, v):
        bad = [e for e in v if e not in ("production", "uat", "development", "dr", "test")]
        if bad:
            raise ValueError("unknown environment")
        return v


def rule_payload(r: NotificationRule) -> dict:
    f = r.filters or {}
    return {"id": r.id, "name": r.name, "event_types": r.event_types, "channel_id": r.channel_id,
            "channel_name": r.channel.name if r.channel else None, "throttle_minutes": r.throttle_minutes,
            "environments": f.get("environments", []), "group_ids": f.get("group_ids", []),
            "server_ids": f.get("server_ids", []), "skip_acknowledged": f.get("skip_acknowledged", True),
            "is_enabled": r.is_enabled}


@router.get("/api/notification-rules")
def list_rules(principal: Principal = Depends(require("notifications.manage")), db: Session = Depends(get_db)):
    return ok([rule_payload(r) for r in db.scalars(select(NotificationRule).order_by(NotificationRule.name))])


def _rule_write(db, request, principal, body: RuleIn, r: NotificationRule | None):
    ctx = ctx_from(request, principal)
    if db.get(NotificationChannel, body.channel_id) is None:
        raise ApiError(422, "validation_error", "Unknown channel", [{"field": "channel_id", "message": "not found"}])
    creating = r is None
    old = None if creating else rule_payload(r)
    if creating:
        r = NotificationRule(created_by=ctx.user_id)
        db.add(r)
    r.name, r.event_types, r.channel_id = body.name, body.event_types, body.channel_id
    r.throttle_minutes, r.is_enabled = body.throttle_minutes, body.is_enabled
    r.filters = {"environments": body.environments, "group_ids": body.group_ids, "server_ids": body.server_ids,
                 "skip_acknowledged": body.skip_acknowledged}
    r.updated_by = ctx.user_id
    db.flush()
    db.refresh(r)
    audit(db, ctx, "notification_rule.create" if creating else "notification_rule.update",
          entity_type="notification_rule", entity_id=r.id, entity_name=r.name, old=old, new=rule_payload(r))
    db.commit()
    return ok(rule_payload(r))


@router.post("/api/notification-rules", status_code=201)
def create_rule(body: RuleIn, request: Request, principal: Principal = Depends(require("notifications.manage")),
                db: Session = Depends(get_db)):
    return _rule_write(db, request, principal, body, None)


@router.put("/api/notification-rules/{rid}")
def update_rule(rid: int, body: RuleIn, request: Request, principal: Principal = Depends(require("notifications.manage")),
                db: Session = Depends(get_db)):
    r = db.get(NotificationRule, rid)
    if r is None:
        raise ApiError(404, "not_found", "rule not found")
    return _rule_write(db, request, principal, body, r)


@router.delete("/api/notification-rules/{rid}")
def delete_rule(rid: int, request: Request, principal: Principal = Depends(require("notifications.manage")),
                db: Session = Depends(get_db)):
    r = db.get(NotificationRule, rid)
    if r is None:
        raise ApiError(404, "not_found", "rule not found")
    audit(db, ctx_from(request, principal), "notification_rule.delete", entity_type="notification_rule",
          entity_id=r.id, entity_name=r.name)
    db.delete(r)
    db.commit()
    return ok({"deleted": True})


@router.get("/api/notifications")
def feed(limit: int = Query(50, ge=1, le=500), unread_only: bool = False,
         principal: Principal = Depends(require("monitoring.view")), db: Session = Depends(get_db)):
    web_channels = [c.id for c in db.scalars(select(NotificationChannel).where(NotificationChannel.provider == "web"))]
    stmt = select(Notification).order_by(Notification.id.desc()).limit(limit)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    rows = list(db.scalars(stmt))
    unread = db.scalar(select(func.count()).select_from(Notification).where(
        Notification.read_at.is_(None), Notification.channel_id.in_(web_channels or [0]))) or 0
    return ok([{"id": n.id, "time": iso(n.created_at), "title": n.title, "message": n.message,
                "event_type": n.event_type, "status": n.status, "error": n.error, "server_id": n.server_id,
                "channel_id": n.channel_id, "read": n.read_at is not None, "in_app": n.channel_id in web_channels}
               for n in rows], {"unread": unread})


@router.post("/api/notifications/read-all")
def mark_all_read(principal: Principal = Depends(require("monitoring.view")), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(Notification.read_at.is_(None)).values(read_at=utcnow()))
    db.commit()
    return ok({"ok": True})
