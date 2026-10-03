"""Live monitoring views (from Nagios) + operator actions + dashboard + events."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import validators as V
from ...audit import audit
from ...db import get_db
from ...live import availability_30d, service_live
from ...models import ConfigurationChange, ConfigurationVersion, Server, User
from ...nagios import external, logparser
from ...nagios.status import HOST_STATES, get_status, host_state_name, service_state_name
from ..deps import Principal, ctx_from, require
from .. import scope
from ..errors import ApiError
from ..util import iso, ok, paginate, ts_iso

router = APIRouter(tags=["monitoring"])


def _server_index(db: Session, principal: Principal) -> dict[str, Server]:
    return {s.hostname: s for s in scope.scoped_servers(db, principal)}


def _host_row(name: str, h: dict, idx: dict[str, Server], snap) -> dict:
    srv = idx.get(name)
    svcs = snap.services_for(name)
    return {
        "host_name": name, "server_id": srv.id if srv else None,
        "display_name": srv.display_name if srv else name, "address": srv.address if srv else None,
        "managed": bool(srv and srv.managed_by == "portal"), "environment": srv.environment if srv else None,
        "state": host_state_name(h), "output": h.get("plugin_output"), "last_check": ts_iso(h.get("last_check")),
        "last_state_change": ts_iso(h.get("last_state_change")), "duration_seconds":
            int(datetime.now(timezone.utc).timestamp() - h["last_state_change"]) if h.get("last_state_change") else None,
        "acknowledged": bool(h.get("problem_has_been_acknowledged")),
        "in_downtime": bool(h.get("scheduled_downtime_depth")), "attempt": f"{h.get('current_attempt')}/{h.get('max_attempts')}",
        "services_total": len(svcs),
        "services_problem": sum(1 for sv in svcs if sv.get("has_been_checked") and sv.get("current_state", 0) != 0),
    }


def _service_row(host: str, desc: str, sv: dict, idx: dict[str, Server]) -> dict:
    srv = idx.get(host)
    d = service_live(sv)
    d.update({"host_name": host, "service_description": desc, "server_id": srv.id if srv else None,
              "duration_seconds": int(datetime.now(timezone.utc).timestamp() - sv["last_state_change"])
              if sv.get("last_state_change") else None})
    return d


@router.get("/api/monitoring/hosts")
def mon_hosts(q: Optional[str] = Query(None, max_length=100), state: Optional[str] = Query(None, max_length=20),
              page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
              principal: Principal = Depends(require("monitoring.view")), db: Session = Depends(get_db)):
    snap = scope.scoped_status(db, principal)
    idx = _server_index(db, principal)
    rows = [_host_row(n, h, idx, snap) for n, h in snap.hosts.items()]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["host_name"].lower() or ql in (r["display_name"] or "").lower()]
    if state:
        rows = [r for r in rows if r["state"] == state.upper()]
    order = {"DOWN": 0, "UNREACHABLE": 1, "PENDING": 2, "UP": 3}
    rows.sort(key=lambda r: (order.get(r["state"], 9), r["host_name"].lower()))
    items, meta = paginate(rows, page, page_size)
    meta["status_error"] = snap.error
    return ok(items, meta)


@router.get("/api/monitoring/services")
def mon_services(q: Optional[str] = Query(None, max_length=100), state: Optional[str] = Query(None, max_length=20),
                 host: Optional[str] = Query(None, max_length=64), page: int = Query(1, ge=1),
                 page_size: int = Query(50, ge=1, le=1000),
                 principal: Principal = Depends(require("monitoring.view")), db: Session = Depends(get_db)):
    snap = scope.scoped_status(db, principal)
    idx = _server_index(db, principal)
    rows = [_service_row(h, d, sv, idx) for (h, d), sv in snap.services.items() if not host or h == host]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["host_name"].lower() or ql in r["service_description"].lower()
                or ql in (r["output"] or "").lower()]
    if state:
        rows = [r for r in rows if r["state"] == state.upper()]
    order = {"CRITICAL": 0, "WARNING": 1, "UNKNOWN": 2, "PENDING": 3, "OK": 4}
    rows.sort(key=lambda r: (order.get(r["state"], 9), r["host_name"].lower(), r["service_description"].lower()))
    items, meta = paginate(rows, page, page_size)
    meta["status_error"] = snap.error
    return ok(items, meta)


@router.get("/api/monitoring/problems")
def mon_problems(include_handled: bool = False, hide_on_down_hosts: bool = True, principal: Principal = Depends(require("monitoring.view")),
                 db: Session = Depends(get_db)):
    return ok(_problems(db, principal, scope.scoped_status(db, principal), include_handled, hide_on_down_hosts))


def _problems(db: Session, principal: Principal, snap, include_handled: bool, hide_on_down_hosts: bool) -> dict:
    idx = _server_index(db, principal)
    hosts = [_host_row(n, h, idx, snap) for n, h in snap.hosts.items()
             if h.get("has_been_checked") and h.get("current_state", 0) != 0]
    down_hosts = {h["host_name"] for h in hosts}
    services = [_service_row(h, d, sv, idx) for (h, d), sv in snap.services.items()
                if sv.get("has_been_checked") and sv.get("current_state", 0) != 0]
    if not include_handled:
        hosts = [h for h in hosts if not h["acknowledged"] and not h["in_downtime"]]
        services = [s for s in services if not s["acknowledged"] and not s["in_downtime"]
                    and not (hide_on_down_hosts and s["host_name"] in down_hosts)]
    sev = {"DOWN": 0, "UNREACHABLE": 1, "CRITICAL": 0, "WARNING": 2, "UNKNOWN": 1}
    hosts.sort(key=lambda r: (sev.get(r["state"], 9), -(r["duration_seconds"] or 0)))
    services.sort(key=lambda r: (sev.get(r["state"], 9), -(r["duration_seconds"] or 0)))
    return {"hosts": hosts, "services": services, "status_error": snap.error}


@router.get("/api/monitoring/downtimes")
def mon_downtimes(principal: Principal = Depends(require("monitoring.view")), db: Session = Depends(get_db)):
    snap = scope.scoped_status(db, principal)
    out = []
    for d in snap.downtimes:
        out.append({"id": d.get("downtime_id"), "kind": d.get("kind"), "host_name": d.get("host_name"),
                    "service_description": d.get("service_description"), "start": ts_iso(d.get("start_time")),
                    "end": ts_iso(d.get("end_time")), "author": d.get("author"), "comment": d.get("comment"),
                    "fixed": bool(d.get("fixed")), "entry_time": ts_iso(d.get("entry_time"))})
    out.sort(key=lambda x: x["start"] or "")
    return ok(out)


class AckIn(BaseModel):
    host_name: str = Field(max_length=64)
    service_description: Optional[str] = Field(None, max_length=100)
    comment: str = Field(min_length=1, max_length=255)
    sticky: bool = True
    notify: bool = True
    persistent: bool = False

    @field_validator("comment")
    @classmethod
    def _c(cls, v):
        return V.check_free_text(v, "comment", 255, required=True)


class DowntimeIn(BaseModel):
    host_name: str = Field(max_length=64)
    service_description: Optional[str] = Field(None, max_length=100)
    start: datetime
    end: datetime
    comment: str = Field(min_length=1, max_length=255)
    include_services: bool = True
    fixed: bool = True

    @field_validator("comment")
    @classmethod
    def _c(cls, v):
        return V.check_free_text(v, "comment", 255, required=True)


class RecheckIn(BaseModel):
    host_name: str = Field(max_length=64)
    service_description: Optional[str] = Field(None, max_length=100)
    all_services: bool = False


def _author(principal: Principal) -> str:
    return principal.user.full_name or principal.user.username


@router.post("/api/monitoring/acknowledge")
def acknowledge(body: AckIn, request: Request, principal: Principal = Depends(require("monitoring.acknowledge")),
                db: Session = Depends(get_db)):
    scope.assert_host(db, principal, body.host_name)
    try:
        cmd = external.acknowledge(body.host_name, body.service_description, _author(principal), body.comment,
                                   body.sticky, body.notify, body.persistent)
    except external.ExternalCommandError as exc:
        raise ApiError(409, "nagios_command_failed", str(exc))
    audit(db, ctx_from(request, principal), "monitoring.acknowledge", entity_type="host", entity_name=body.host_name,
          new={"service": body.service_description, "comment": body.comment})
    db.commit()
    return ok({"sent": cmd.split(";", 1)[0]})


@router.delete("/api/monitoring/acknowledge")
def remove_ack(request: Request, host_name: str = Query(max_length=64),
               service_description: Optional[str] = Query(None, max_length=100), principal: Principal = Depends(require("monitoring.acknowledge")),
               db: Session = Depends(get_db)):
    scope.assert_host(db, principal, host_name)
    try:
        external.remove_acknowledgement(host_name, service_description)
    except external.ExternalCommandError as exc:
        raise ApiError(409, "nagios_command_failed", str(exc))
    audit(db, ctx_from(request, principal), "monitoring.unacknowledge", entity_type="host", entity_name=host_name,
          new={"service": service_description})
    db.commit()
    return ok({"sent": True})


@router.post("/api/monitoring/downtime")
def schedule_downtime(body: DowntimeIn, request: Request, principal: Principal = Depends(require("monitoring.downtime")),
                      db: Session = Depends(get_db)):
    scope.assert_host(db, principal, body.host_name)
    start = int(body.start.replace(tzinfo=body.start.tzinfo or timezone.utc).timestamp())
    end = int(body.end.replace(tzinfo=body.end.tzinfo or timezone.utc).timestamp())
    try:
        external.schedule_downtime(body.host_name, body.service_description, start, end, _author(principal),
                                   body.comment, include_services=body.include_services, fixed=body.fixed)
    except external.ExternalCommandError as exc:
        raise ApiError(409, "nagios_command_failed", str(exc))
    audit(db, ctx_from(request, principal), "monitoring.downtime", entity_type="host", entity_name=body.host_name,
          new={"service": body.service_description, "start": body.start.isoformat(), "end": body.end.isoformat(),
               "comment": body.comment})
    db.commit()
    return ok({"scheduled": True})


@router.delete("/api/monitoring/downtime/{kind}/{downtime_id}")
def cancel_downtime(kind: str, downtime_id: int, request: Request,
                    principal: Principal = Depends(require("monitoring.downtime")), db: Session = Depends(get_db)):
    if not principal.is_super and not any(d.get("downtime_id") == downtime_id
                                          for d in scope.scoped_status(db, principal).downtimes):
        raise ApiError(404, "not_found", "downtime not found")
    try:
        external.delete_downtime(downtime_id, kind)
    except external.ExternalCommandError as exc:
        raise ApiError(409, "nagios_command_failed", str(exc))
    audit(db, ctx_from(request, principal), "monitoring.downtime_cancel", entity_type="downtime",
          entity_id=downtime_id, entity_name=kind)
    db.commit()
    return ok({"cancelled": True})


@router.post("/api/monitoring/recheck")
def recheck(body: RecheckIn, request: Request, principal: Principal = Depends(require("monitoring.control")),
            db: Session = Depends(get_db)):
    scope.assert_host(db, principal, body.host_name)
    try:
        external.recheck(body.host_name, body.service_description, body.all_services)
    except external.ExternalCommandError as exc:
        raise ApiError(409, "nagios_command_failed", str(exc))
    audit(db, ctx_from(request, principal), "monitoring.recheck", entity_type="host", entity_name=body.host_name,
          new={"service": body.service_description, "all_services": body.all_services})
    db.commit()
    return ok({"scheduled": True})


# ---------------------------------------------------------------- events --
def config_events(db: Session, limit: int, since: datetime | None = None, principal: Principal | None = None) -> list[dict]:
    stmt = select(ConfigurationVersion).where(ConfigurationVersion.status.in_(
        ("applied", "apply_failed", "validation_failed", "superseded", "rolled_back")))
    if principal is not None and not principal.is_super:
        stmt = stmt.where(ConfigurationVersion.created_by == principal.user.id)
    if since:
        stmt = stmt.where(ConfigurationVersion.created_at >= since.replace(tzinfo=None))
    out = []
    users = {u.id: u.username for u in db.scalars(select(User))}
    for v in db.scalars(stmt.order_by(ConfigurationVersion.id.desc()).limit(limit)):
        t = v.applied_at or v.created_at
        out.append({"time": iso(t), "ts": int(t.replace(tzinfo=timezone.utc).timestamp()), "kind": "CONFIG CHANGE",
                    "host": None, "service": None,
                    "state": "APPLIED" if v.status in ("applied", "superseded") else v.status.upper(),
                    "output": f"v{v.id}: {v.summary}", "contact": users.get(v.applied_by or v.created_by),
                    "version_id": v.id})
    return out


@router.get("/api/events")
def events(limit: int = Query(200, ge=1, le=2000), host: Optional[str] = Query(None, max_length=64),
           kind: Optional[str] = Query(None, max_length=40), hours: Optional[int] = Query(None, ge=1, le=24 * 31),
           principal: Principal = Depends(require("monitoring.view")), db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours) if hours else None
    kinds = None
    if kind:
        kinds = {k.strip().upper() for k in kind.split(",") if k.strip()}
    rows = []
    allowed = scope.hostnames(db, principal)
    if host and not scope.host_allowed(allowed, host):
        return ok([])
    if not kinds or kinds - {"CONFIG CHANGE"}:
        rows = logparser.recent_events(limit=limit if allowed is None else limit * 5, host=host,
                                       kinds=(kinds - {"CONFIG CHANGE"}) if kinds else None, since=since)
        if allowed is not None:
            rows = [r for r in rows if r.get("host") in allowed]
    if (not kinds or "CONFIG CHANGE" in kinds) and not host:
        rows += config_events(db, limit, since, principal)
    rows.sort(key=lambda r: r["ts"], reverse=True)
    return ok(rows[:limit])


# ------------------------------------------------------------- dashboard --
@router.get("/api/dashboard")
def dashboard(company_id: Optional[int] = None, location_id: Optional[int] = None,
              principal: Principal = Depends(require("dashboard.view")), db: Session = Depends(get_db)):
    snap = scope.scoped_status(db, principal, company_id, location_id)
    idx = {h: s for h, s in _server_index(db, principal).items()
           if (not company_id or s.company_id == (company_id if company_id > 0 else None))
           and (not location_id or s.location_id == (location_id if location_id > 0 else None))}
    hs = {"total": 0, "UP": 0, "DOWN": 0, "UNREACHABLE": 0, "PENDING": 0}
    for h in snap.hosts.values():
        hs["total"] += 1
        hs[host_state_name(h)] = hs.get(host_state_name(h), 0) + 1
    ss = {"total": 0, "OK": 0, "WARNING": 0, "CRITICAL": 0, "UNKNOWN": 0, "PENDING": 0}
    for sv in snap.services.values():
        ss["total"] += 1
        ss[service_state_name(sv)] = ss.get(service_state_name(sv), 0) + 1
    # WARNING summary for hosts = hosts with at least one warning service
    host_warn = {h for (h, _), sv in snap.services.items() if sv.get("current_state") == 1 and sv.get("has_been_checked")}
    hs["WARNING"] = len(host_warn)
    hs["UNKNOWN"] = len({h for (h, _), sv in snap.services.items() if sv.get("current_state") == 3 and sv.get("has_been_checked")})
    avail = availability_30d(snap)
    vals = [v for k, v in avail.items() if k in snap.hosts]
    availability = round(sum(vals) / len(vals), 3) if vals else None
    problems = _problems(db, principal, snap, False, False)
    top = {
        "critical": [s for s in problems["services"] if s["state"] == "CRITICAL"][:10],
        "warning": [s for s in problems["services"] if s["state"] == "WARNING"][:10],
        "unknown": [s for s in problems["services"] if s["state"] == "UNKNOWN"][:10],
        "down": [h for h in problems["hosts"] if h["state"] == "DOWN"][:10],
        "unreachable": [h for h in problems["hosts"] if h["state"] == "UNREACHABLE"][:10],
    }
    narrowed = principal.is_super and not company_id and not location_id
    recent = logparser.recent_events(limit=25 if narrowed else 200, kinds={"HOST ALERT", "SERVICE ALERT"})
    recent = [e for e in recent if e["state_type"] == "HARD" and (narrowed or e.get("host") in snap.hosts)][:15]
    recent += config_events(db, 10, principal=principal)
    recent.sort(key=lambda r: r["ts"], reverse=True)
    from ...nagios import pipeline as _pl
    pending = len(scope.split_pending(db, principal, _pl.pending_changes(db))[0])

    def bump(bucket: dict, key, label, s):
        e = bucket.setdefault(key, {"id": key, "name": label, "total": 0, "problems": 0})
        e["total"] += 1
        h = snap.hosts.get(s.hostname)
        if h and h.get("has_been_checked") and h.get("current_state", 0) != 0:
            e["problems"] += 1

    by_env: dict[str, dict] = {}
    by_location: dict = {}
    by_company: dict = {}
    for s in idx.values():
        e = by_env.setdefault(s.environment, {"total": 0, "problems": 0})
        e["total"] += 1
        h = snap.hosts.get(s.hostname)
        if h and h.get("has_been_checked") and h.get("current_state", 0) != 0:
            e["problems"] += 1
        bump(by_location, s.location_id or -1, s.site.name if s.site else "Unassigned", s)
        bump(by_company, s.company_id or -1, s.company.name if s.company else "No company", s)
    return ok({
        "hosts": hs, "services": ss, "availability_30d": availability, "top_problems": top,
        "recent_events": recent[:20], "pending_changes": pending, "inventory": {
            "servers": sum(1 for s in idx.values() if s.device_type == "server"),
            "network_devices": sum(1 for s in idx.values() if s.device_type == "network_device"),
            "managed": sum(1 for s in idx.values() if s.managed_by == "portal"),
            "by_environment": by_env,
            "by_location": sorted(by_location.values(), key=lambda x: -x["total"]),
            "by_company": sorted(by_company.values(), key=lambda x: -x["total"]),
        },
        "scope": {"super": principal.is_super, "company_id": company_id, "location_id": location_id,
                  "companies": [{"id": c.id, "name": c.name} for c in principal.user.companies if c.is_active],
                  "locations": [{"id": l.id, "name": l.name} for l in principal.user.locations if l.is_active]},
        "nagios": {"status_error": snap.error, "program_start": ts_iso(snap.program.get("program_start")),
                   "pid": snap.program.get("nagios_pid"), "status_age_seconds":
                       int(datetime.now(timezone.utc).timestamp() - snap.mtime) if snap.mtime else None},
        "host_states": HOST_STATES,
    })
