"""Company scope: what a non-Super-Admin user may see.

Super Admin sees every company and location (and servers with neither).
Every other user sees only servers that belong to one of *their* companies (one or
several, assigned by Super Admin). If locations are also assigned to the user, only
those sites of their companies are visible; with no locations, all sites are.
Hosts that exist only in Nagios files (not in the portal inventory) and servers without
a company are visible to Super Admin only.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from ..models import Server
from .deps import Principal
from .errors import ApiError


def unrestricted(p: Principal) -> bool:
    return p.is_super


def has_location_limit(p: Principal) -> bool:
    """True when the user is limited to particular sites (even if those sites were later retired)."""
    return bool(p.user.locations)


def server_filter(p: Principal):
    """SQL condition limiting Server rows to the user's scope (None = no restriction)."""
    if unrestricted(p):
        return None
    cond = Server.company_id.in_(list(p.company_ids) or [-1])
    if has_location_limit(p):
        cond = and_(cond, Server.location_id.in_(list(p.location_ids) or [-1]))
    return cond


def can_see_server(p: Principal, s: Optional[Server]) -> bool:
    if s is None:
        return False
    if unrestricted(p):
        return True
    if s.company_id is None or s.company_id not in p.company_ids:
        return False
    return not has_location_limit(p) or (s.location_id is not None and s.location_id in p.location_ids)


def scoped_servers(db: Session, p: Principal, include_deleted: bool = False) -> list[Server]:
    stmt = select(Server)
    if not include_deleted:
        stmt = stmt.where(Server.deleted_token == 0)
    cond = server_filter(p)
    if cond is not None:
        stmt = stmt.where(cond)
    return list(db.scalars(stmt))


def server_ids(db: Session, p: Principal) -> Optional[set[int]]:
    """Allowed server ids, or None when unrestricted."""
    if unrestricted(p):
        return None
    return set(db.scalars(select(Server.id).where(server_filter(p))))


def check_filters(p: Principal, company_id: Optional[int], location_id: Optional[int]) -> None:
    """Filters may only narrow the user's own scope. -1 ("not assigned") is Super Admin only."""
    if unrestricted(p):
        return
    if company_id and (company_id < 0 or company_id not in p.company_ids):
        raise ApiError(403, "forbidden", "That company is not assigned to you")
    if location_id and (location_id < 0 or (has_location_limit(p) and location_id not in p.location_ids)):
        raise ApiError(403, "forbidden", "That location is not assigned to you")


def narrow(stmt, company_id: Optional[int], location_id: Optional[int]):
    if company_id:
        stmt = stmt.where(Server.company_id == company_id if company_id > 0 else Server.company_id.is_(None))
    if location_id:
        stmt = stmt.where(Server.location_id == location_id if location_id > 0 else Server.location_id.is_(None))
    return stmt


def hostnames(db: Session, p: Principal, company_id: Optional[int] = None,
              location_id: Optional[int] = None) -> Optional[set[str]]:
    """Allowed Nagios host names, or None when unrestricted (company_id/location_id narrow the view)."""
    check_filters(p, company_id, location_id)
    if unrestricted(p) and not company_id and not location_id:
        return None
    stmt = select(Server.hostname).where(Server.deleted_token == 0)
    cond = server_filter(p)
    if cond is not None:
        stmt = stmt.where(cond)
    return set(db.scalars(narrow(stmt, company_id, location_id)))


def host_allowed(allowed: Optional[set[str]], host: Optional[str]) -> bool:
    return allowed is None or (host is not None and host in allowed)


def assert_host(db: Session, p: Principal, host: str) -> None:
    """Operator actions (acknowledge, downtime, re-check) only on hosts of the user's companies."""
    if not host_allowed(hostnames(db, p), host):
        raise ApiError(404, "not_found", "host not found")


def get_visible_server(db: Session, p: Principal, server_id: int, include_deleted: bool = False) -> Server:
    """Fetch a server or 404 - out-of-scope servers look exactly like missing ones."""
    s = db.get(Server, server_id)
    if s is None or (s.deleted_token and not include_deleted) or not can_see_server(p, s):
        raise ApiError(404, "not_found", "server not found")
    return s


def assert_org_allowed(p: Principal, company_id: Optional[int], location_id: Optional[int]) -> None:
    """Non-Super-Admin users must place servers in one of their companies (and sites, if limited)."""
    if unrestricted(p):
        return
    if company_id is None or company_id not in p.company_ids:
        raise ApiError(422, "validation_error", "Choose one of your companies",
                       [{"field": "company_id", "message": "not one of your companies"}])
    if has_location_limit(p) and (location_id is None or location_id not in p.location_ids):
        raise ApiError(422, "validation_error", "Choose one of your assigned locations",
                       [{"field": "location_id", "message": "not one of your locations"}])


SERVER_CHANGE_TYPES = ("server", "server_services")


def change_in_scope(db: Session, p: Principal, entity_type: str, entity_id: Optional[int]) -> bool:
    if unrestricted(p):
        return True
    if entity_type not in SERVER_CHANGE_TYPES or entity_id is None:
        return False
    return can_see_server(p, db.get(Server, entity_id))


def split_pending(db: Session, p: Principal, changes: list) -> tuple[list, list]:
    """(visible, others) pending changes for this user."""
    mine, others = [], []
    for c in changes:
        (mine if change_in_scope(db, p, c.entity_type, c.entity_id) else others).append(c)
    return mine, others


def assert_can_run_pipeline(db: Session, p: Principal) -> None:
    """Validate/apply ships ALL pending changes; a company-scoped admin may only run it when every
    pending change belongs to their own companies (otherwise Super Admin must apply)."""
    if unrestricted(p):
        return
    from ..nagios import pipeline

    _, others = split_pending(db, p, pipeline.pending_changes(db))
    if others:
        raise ApiError(409, "other_changes_pending",
                       f"{len(others)} pending change(s) belong to other companies or to shared configuration. "
                       "A Super Admin must validate and apply them first.", {"other_changes": len(others)})


def require_super(p: Principal) -> None:
    if not unrestricted(p):
        raise ApiError(403, "forbidden", "Only a Super Admin can do this")


def scoped_status(db: Session, p: Principal, company_id: Optional[int] = None, location_id: Optional[int] = None):
    """Nagios status limited to the user's hosts (Super Admin: the full snapshot)."""
    from dataclasses import replace

    from ..nagios.status import get_status

    snap = get_status()
    allowed = hostnames(db, p, company_id, location_id)
    if allowed is None:
        return snap
    return replace(
        snap,
        hosts={h: v for h, v in snap.hosts.items() if h in allowed},
        services={k: v for k, v in snap.services.items() if k[0] in allowed},
        downtimes=[d for d in snap.downtimes if d.get("host_name") in allowed],
        comments=[c for c in snap.comments if c.get("host_name") in allowed],
    )
