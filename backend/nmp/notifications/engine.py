"""Notification rule engine (runs in the worker).

Detects HARD state transitions from Nagios status.dat, maps them to event
types, matches enabled rules, applies throttling and dispatches through the
provider registry. Nagios' own notifications keep working independently.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import MonitorStateCache, Notification, NotificationChannel, NotificationRule, Server
from ..nagios.status import HOST_STATES, SERVICE_STATES, StatusSnapshot
from ..security import crypto
from .providers.base import Message, ProviderError
from .providers.registry import get as get_provider

log = logging.getLogger("nmp.notifications")

CATEGORY_EVENTS = {"cpu": "high_cpu", "memory": "high_memory", "disk": "high_disk"}


def channel_secrets(ch: NotificationChannel) -> dict:
    return crypto.decrypt_json(ch.secret_ciphertext, f"channel:{ch.provider}") if ch.secret_ciphertext else {}


def detect_events(db: Session, snap: StatusSnapshot) -> list[dict]:
    servers = {s.hostname: s for s in db.scalars(select(Server).where(Server.deleted_token == 0))}
    cache = {c.object_key: c for c in db.scalars(select(MonitorStateCache))}
    events: list[dict] = []
    now = utcnow()
    seen: set[str] = set()

    def transition(key: str, state: int, build):
        seen.add(key)
        prev = cache.get(key)
        if prev is None:
            db.add(MonitorStateCache(object_key=key, state=state, changed_at=now))
            return
        if prev.state != state:
            old = prev.state
            prev.state, prev.changed_at = state, now
            events.extend(build(old))

    for name, h in snap.hosts.items():
        if not h.get("has_been_checked") or h.get("state_type") != 1:
            continue
        srv = servers.get(name)
        st = int(h.get("current_state", 0))

        def build_host(old, name=name, h=h, srv=srv, st=st):
            base = {"host": name, "service": None, "server": srv, "output": h.get("plugin_output"),
                    "state": HOST_STATES.get(st, "UNKNOWN"), "acknowledged": bool(h.get("problem_has_been_acknowledged")),
                    "in_downtime": bool(h.get("scheduled_downtime_depth"))}
            if st == 0:
                return [dict(base, event_type="recovery", severity="ok", old=HOST_STATES.get(old))]
            out = [dict(base, event_type="host_down", severity="critical")]
            if srv is not None and srv.device_type == "network_device":
                out.append(dict(base, event_type="network_down", severity="critical"))
            return out

        transition(f"h:{name}", st, build_host)

    for (host, desc), sv in snap.services.items():
        if not sv.get("has_been_checked") or sv.get("state_type") != 1:
            continue
        srv = servers.get(host)
        st = int(sv.get("current_state", 0))
        category = None
        if srv is not None:
            ss = next((x for x in srv.services if x.service_description == desc), None)
            category = ss.service.category if ss else None

        def build_svc(old, host=host, desc=desc, sv=sv, srv=srv, st=st, category=category):
            base = {"host": host, "service": desc, "server": srv, "output": sv.get("plugin_output"),
                    "state": SERVICE_STATES.get(st, "UNKNOWN"),
                    "acknowledged": bool(sv.get("problem_has_been_acknowledged")),
                    "in_downtime": bool(sv.get("scheduled_downtime_depth"))}
            if st == 0:
                return [dict(base, event_type="recovery", severity="ok", old=SERVICE_STATES.get(old))]
            out = []
            if st == 2:
                out.append(dict(base, event_type="service_critical", severity="critical"))
            elif st == 1:
                out.append(dict(base, event_type="service_warning", severity="warning"))
            if st in (1, 2) and category in CATEGORY_EVENTS:
                out.append(dict(base, event_type=CATEGORY_EVENTS[category], severity="critical" if st == 2 else "warning"))
            return out

        transition(f"s:{host}/{desc}", st, build_svc)
    # forget objects that no longer exist
    for key, c in cache.items():
        if key not in seen and (key.startswith("h:") or key.startswith("s:")):
            db.delete(c)
    return events


def _matches(rule: NotificationRule, ev: dict) -> bool:
    if ev["event_type"] not in (rule.event_types or []):
        return False
    f = rule.filters or {}
    srv = ev.get("server")
    if f.get("environments") and (srv is None or srv.environment not in f["environments"]):
        return False
    if f.get("group_ids") and (srv is None or not {g.id for g in srv.groups} & set(f["group_ids"])):
        return False
    if f.get("server_ids") and (srv is None or srv.id not in f["server_ids"]):
        return False
    if f.get("skip_acknowledged", True) and (ev.get("acknowledged") or ev.get("in_downtime")):
        return False
    return True


def format_message(ev: dict) -> Message:
    what = f"{ev['host']}/{ev['service']}" if ev.get("service") else ev["host"]
    label = ev["event_type"].replace("_", " ").title()
    title = f"[{ev['state']}] {label}: {what}"
    srv = ev.get("server")
    lines = [f"Event: {label}", f"Host: {ev['host']}"]
    if srv is not None:
        lines += [f"Display name: {srv.display_name}", f"Address: {srv.address}", f"Environment: {srv.environment}"]
    if ev.get("service"):
        lines.append(f"Service: {ev['service']}")
    lines += [f"State: {ev['state']}", f"Output: {ev.get('output') or ''}"]
    return Message(title=title[:250], body="\n".join(lines), event_type=ev["event_type"], severity=ev["severity"],
                   host=ev["host"], service=ev.get("service"), state=ev["state"], output=ev.get("output"))


def dispatch(db: Session, events: list[dict]) -> int:
    if not events:
        return 0
    rules = [r for r in db.scalars(select(NotificationRule).where(NotificationRule.is_enabled.is_(True)))
             if r.channel and r.channel.is_enabled]
    sent = 0
    now = utcnow()
    for ev in events:
        key = f"{ev['host']}/{ev.get('service') or ''}"
        for rule in rules:
            if not _matches(rule, ev):
                continue
            recent = db.scalar(select(Notification).where(
                Notification.rule_id == rule.id, Notification.object_key == key,
                Notification.event_type == ev["event_type"], Notification.status == "sent",
                Notification.created_at >= now - timedelta(minutes=rule.throttle_minutes)).limit(1))
            msg = format_message(ev)
            n = Notification(rule_id=rule.id, channel_id=rule.channel_id, server_id=ev["server"].id if ev.get("server") else None,
                             object_key=key[:190], event_type=ev["event_type"], title=msg.title, message=msg.body,
                             status="suppressed" if recent else "sent")
            if not recent:
                provider = get_provider(rule.channel.provider)
                try:
                    if provider is None:
                        raise ProviderError(f"unknown provider '{rule.channel.provider}'")
                    provider.send(rule.channel.settings or {}, channel_secrets(rule.channel), msg)
                    sent += 1
                except (ProviderError, crypto.CryptoError) as exc:
                    n.status, n.error = "failed", str(exc)[:500]
                    log.warning("notification failed rule=%s channel=%s: %s", rule.name, rule.channel.name, exc)
            db.add(n)
    return sent


def send_test(ch: NotificationChannel) -> None:
    provider = get_provider(ch.provider)
    if provider is None:
        raise ProviderError("unknown provider")
    provider.send(ch.settings or {}, channel_secrets(ch), Message(
        title="[TEST] Nagios Management Portal notification", body="This is a test message from the portal.",
        event_type="test", severity="info", host="test-host", state="OK", output="Test notification"))
