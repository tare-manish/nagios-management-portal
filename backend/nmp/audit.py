"""Audit logging and pending-change recording."""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from .models import AuditLog, ConfigurationChange

log = logging.getLogger("nmp.audit")

SECRET_KEYS = {"token", "password", "secret", "community", "auth_password", "priv_password",
               "api_key", "ncpa_token", "snmp_community", "smtp_password", "secret_ciphertext",
               "password_hash", "webhook_url", "auth_token"}


def scrub(value: Any) -> Any:
    """Remove secrets from values stored in audit/changes."""
    if isinstance(value, dict):
        return {k: ("***" if k.lower() in SECRET_KEYS and v not in (None, "") else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def _jsonable(value: Any) -> Any:
    if value is None:
        return None
    return json.loads(json.dumps(scrub(value), default=str))


class AuditContext:
    """Who/where for audit entries (built from the request)."""

    def __init__(self, user_id: int | None, username: str | None, ip: str | None, user_agent: str | None):
        self.user_id = user_id
        self.username = username
        self.ip = ip
        self.user_agent = user_agent

    @classmethod
    def system(cls) -> "AuditContext":
        return cls(None, "system", None, None)


def audit(db: Session, ctx: AuditContext, action: str, *, entity_type: str | None = None,
          entity_id: int | None = None, entity_name: str | None = None, old: Any = None,
          new: Any = None, result: str = "success", detail: str | None = None) -> None:
    entry = AuditLog(
        user_id=ctx.user_id, username=ctx.username, ip_address=(ctx.ip or "")[:45] or None,
        user_agent=(ctx.user_agent or "")[:255] or None, action=action, entity_type=entity_type,
        entity_id=entity_id, entity_name=(entity_name or "")[:190] or None, old_value=_jsonable(old),
        new_value=_jsonable(new), result=result, detail=(detail or "")[:1024] or None,
    )
    db.add(entry)
    log.info("user=%s ip=%s action=%s entity=%s:%s(%s) result=%s", ctx.username, ctx.ip, action,
             entity_type, entity_id, entity_name, result)


def record_change(db: Session, ctx: AuditContext, entity_type: str, entity_id: int | None,
                  entity_name: str, action: str, old: Any = None, new: Any = None) -> None:
    db.add(ConfigurationChange(
        entity_type=entity_type, entity_id=entity_id, entity_name=entity_name[:190], action=action,
        old_value=_jsonable(old), new_value=_jsonable(new), user_id=ctx.user_id,
    ))
