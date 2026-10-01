"""Servers & network devices: inventory CRUD, services, connection tests, per-server pipeline actions."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ... import agents
from ... import validators as V
from ...audit import AuditContext, audit, record_change
from ...db import get_db, utcnow
from ...live import availability_30d, host_live, service_live, service_metrics
from ...models import (AuditLog, ConfigurationChange, ContactGroup, MonitoringTemplate, PerfSample, Server,
                       ServerCredential, ServerGroup, ServerService, Service, ServiceThreshold)
from ...nagios import logparser, pipeline
from ...nagios.status import get_status
from ...security import crypto
from ..deps import Principal, ctx_from, require
from ..errors import ApiError
from ..schemas import ActionIn, ConnectionTestIn, NcpaIn, NrpeIn, ServerIn, ServiceItemIn
from ..util import get_or_404, iso, ok, paginate
from .config import version_payload

router = APIRouter(prefix="/api/servers", tags=["servers"])

STATE_ORDER = {"DOWN": 0, "UNREACHABLE": 1, "UNKNOWN": 2, "PENDING": 3, "UNMONITORED": 4, "UP": 5}


# ------------------------------------------------------------ serializers --
def credential_payload(c: ServerCredential) -> dict:
    d = {"type": c.credential_type, "port": c.port, "ssl_enabled": c.ssl_enabled, "verify_ssl": c.verify_ssl,
         "timeout": c.timeout, "secret_set": bool(c.secret_ciphertext), "last_test_at": iso(c.last_test_at),
         "last_test_result": c.last_test_result}
    if c.credential_type == "snmp":
        d.update(version=c.snmp_version, username=c.snmp_username, auth_protocol=c.snmp_auth_protocol,
                 priv_protocol=c.snmp_priv_protocol, security_level=c.snmp_security_level)
    return d


def service_payload(ss: ServerService, snap=None, hostname: str | None = None) -> dict:
    th = ss.threshold
    d = {
        "id": ss.id, "service_id": ss.service_id, "service_code": ss.service.code, "service_name": ss.service.name,
        "category": ss.service.category, "service_description": ss.service_description, "params": ss.params,
        "is_enabled": ss.is_enabled, "from_template_id": ss.from_template_id,
        "warning": th.warning if th else ss.service.default_warning,
        "critical": th.critical if th else ss.service.default_critical,
        "check_interval": th.check_interval if th else ss.service.default_check_interval,
        "retry_interval": th.retry_interval if th else ss.service.default_retry_interval,
        "max_check_attempts": th.max_check_attempts if th else 3,
        "notification_interval": th.notification_interval if th else ss.service.default_notification_interval,
        "notifications_enabled": th.notifications_enabled if th else True,
        "unit": ss.service.unit,
    }
    if snap is not None and hostname:
        d["live"] = service_live(snap.services.get((hostname, ss.service_description)))
    return d


def server_payload(s: Server, snap=None, avail: dict | None = None, detail: bool = False) -> dict:
    d = {
        "id": s.id, "hostname": s.hostname, "display_name": s.display_name, "address": s.address,
        "description": s.description, "location": s.location, "environment": s.environment,
        "os_type": s.os_type, "os_version": s.os_version, "device_type": s.device_type,
        "monitoring_method": s.monitoring_method, "host_check": s.host_check,
        "groups": [{"id": g.id, "name": g.name} for g in s.groups],
        "contact_groups": [{"id": g.id, "name": g.name} for g in s.contact_groups],
        "template_id": s.template_id, "template_name": s.template.name if s.template else None,
        "is_enabled": s.is_enabled, "config_state": s.config_state, "managed_by": s.managed_by,
        "imported_from": s.imported_from, "tags": s.tags or [],
        "check_interval": s.check_interval, "retry_interval": s.retry_interval,
        "max_check_attempts": s.max_check_attempts, "notification_interval": s.notification_interval,
        "notifications_enabled": s.notifications_enabled, "check_period": s.check_period,
        "notification_period": s.notification_period, "service_count": len(s.services),
        "created_at": iso(s.created_at), "updated_at": iso(s.updated_at),
    }
    if snap is not None:
        d["live"] = host_live(s.hostname, snap)
        d["metrics"] = service_metrics(s, snap)
        d["availability_30d"] = (avail or {}).get(s.hostname)
    if detail:
        d["credentials"] = [credential_payload(c) for c in s.credentials]
        d["services"] = [service_payload(ss, snap, s.hostname) for ss in s.services]
    return d


def audit_view(s: Server) -> dict:
    """Configuration values recorded in audit/changes (secrets excluded)."""
    return {
        "hostname": s.hostname, "display_name": s.display_name, "address": s.address, "location": s.location,
        "environment": s.environment, "os_type": s.os_type, "monitoring_method": s.monitoring_method,
        "host_check": s.host_check, "groups": sorted(g.name for g in s.groups),
        "contact_groups": sorted(g.name for g in s.contact_groups), "is_enabled": s.is_enabled,
        "check_interval": s.check_interval, "retry_interval": s.retry_interval,
        "max_check_attempts": s.max_check_attempts, "notification_interval": s.notification_interval,
        "notifications_enabled": s.notifications_enabled,
        "credentials": [{k: v for k, v in credential_payload(c).items() if k not in ("last_test_at",)}
                        for c in s.credentials],
        "services": sorted(f"{ss.service_description} [{ss.service.code}] w={ss.threshold.warning if ss.threshold else ''} "
                           f"c={ss.threshold.critical if ss.threshold else ''}{'' if ss.is_enabled else ' (disabled)'}"
                           for ss in s.services),
    }


# ------------------------------------------------------------------ list --
@router.get("")
def list_servers(
    request: Request,
    q: str | None = Query(None, max_length=100),
    status: str | None = Query(None, max_length=20),
    os_type: str | None = Query(None, max_length=20),
    environment: str | None = Query(None, max_length=20),
    group_id: int | None = None,
    monitoring_method: str | None = Query(None, max_length=20),
    device_type: str | None = Query(None, max_length=20),
    config_state: str | None = Query(None, max_length=20),
    sort: str = Query("hostname", max_length=30),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=500),
    principal: Principal = Depends(require("servers.view")),
    db: Session = Depends(get_db),
):
    stmt = select(Server).where(Server.deleted_token == 0)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Server.hostname.like(like), Server.display_name.like(like), Server.address.like(like),
                              Server.location.like(like)))
    for col, val in ((Server.os_type, os_type), (Server.environment, environment),
                     (Server.monitoring_method, monitoring_method), (Server.device_type, device_type),
                     (Server.config_state, config_state)):
        if val:
            stmt = stmt.where(col == val)
    servers = list(db.scalars(stmt))
    if group_id:
        servers = [s for s in servers if any(g.id == group_id for g in s.groups)]
    snap = get_status()
    avail = availability_30d(snap)
    rows = [server_payload(s, snap, avail) for s in servers]
    if status:
        rows = [r for r in rows if r["live"]["state"] == status.upper()]

    def key(r):
        if sort == "status":
            return STATE_ORDER.get(r["live"]["state"], 9)
        if sort in ("cpu", "memory", "disk"):
            return r["metrics"][sort] if r["metrics"][sort] is not None else -1
        if sort == "availability":
            return r["availability_30d"] if r["availability_30d"] is not None else -1
        if sort in ("last_check", "last_state_change"):
            return r["live"][sort] or ""
        if sort == "group":
            return ",".join(g["name"] for g in r["groups"])
        v = r.get(sort)
        return (v or "").lower() if isinstance(v, str) or v is None else v

    rows.sort(key=key, reverse=(order == "desc"))
    items, meta = paginate(rows, page, page_size)
    counts = defaultdict(int)
    for r in rows:
        counts[r["live"]["state"]] += 1
    meta["state_counts"] = counts
    meta["status_error"] = snap.error
    return ok(items, meta)


@router.get("/{server_id}")
def get_server(server_id: int, principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    s = get_or_404(db, Server, server_id, "server")
    snap = get_status()
    return ok(server_payload(s, snap, availability_30d(snap), detail=True))


# ------------------------------------------------------------- helpers --
def _apply_fields(db: Session, s: Server, body: ServerIn) -> None:
    for f in ("hostname", "display_name", "address", "description", "location", "environment", "os_type",
              "os_version", "device_type", "monitoring_method", "host_check", "check_interval", "retry_interval",
              "max_check_attempts", "notification_interval", "notifications_enabled", "check_period",
              "notification_period", "is_enabled", "tags"):
        setattr(s, f, getattr(body, f))
    if body.template_id is not None:
        if db.get(MonitoringTemplate, body.template_id) is None:
            raise ApiError(422, "validation_error", "Template not found", [{"field": "template_id", "message": "not found"}])
    s.template_id = body.template_id
    groups = list(db.scalars(select(ServerGroup).where(ServerGroup.id.in_(body.group_ids)))) if body.group_ids else []
    if len(groups) != len(set(body.group_ids)):
        raise ApiError(422, "validation_error", "Unknown host group", [{"field": "group_ids", "message": "unknown id"}])
    s.groups = groups
    cgs = list(db.scalars(select(ContactGroup).where(ContactGroup.id.in_(body.contact_group_ids)))) if body.contact_group_ids else []
    if len(cgs) != len(set(body.contact_group_ids)):
        raise ApiError(422, "validation_error", "Unknown contact group", [{"field": "contact_group_ids", "message": "unknown id"}])
    s.contact_groups = cgs


def _upsert_credentials(db: Session, s: Server, body: ServerIn, ctx: AuditContext, creating: bool) -> None:
    creds = {c.credential_type: c for c in s.credentials}
    m = body.monitoring_method
    if m == "ncpa":
        n = body.ncpa or NcpaIn()
        c = creds.get("ncpa")
        if c is None:
            if not n.token:
                raise ApiError(422, "validation_error", "NCPA token is required", [{"field": "ncpa.token", "message": "required"}])
            c = ServerCredential(credential_type="ncpa", created_by=ctx.user_id)
            s.credentials.append(c)
        c.port, c.ssl_enabled, c.verify_ssl, c.timeout = n.port, n.ssl_enabled, n.verify_ssl, n.timeout
        c.updated_by = ctx.user_id
        if n.token:
            c.secret_ciphertext = crypto.encrypt_json({"token": n.token}, "cred:ncpa")
    elif m == "snmp":
        sn = body.snmp
        if sn is None:
            raise ApiError(422, "validation_error", "SNMP settings are required", [{"field": "snmp", "message": "required"}])
        c = creds.get("snmp")
        existing = crypto.decrypt_json(c.secret_ciphertext, "cred:snmp") if c and c.secret_ciphertext else {}
        secret = dict(existing)
        if sn.version == "2c":
            if sn.community:
                secret = {"community": sn.community}
            if not secret.get("community"):
                raise ApiError(422, "validation_error", "SNMP community is required", [{"field": "snmp.community", "message": "required"}])
        else:
            if not sn.username:
                raise ApiError(422, "validation_error", "SNMPv3 username is required", [{"field": "snmp.username", "message": "required"}])
            secret.pop("community", None)
            if sn.auth_password:
                secret["auth_password"] = sn.auth_password
            if sn.priv_password:
                secret["priv_password"] = sn.priv_password
            if sn.security_level in ("authNoPriv", "authPriv") and not secret.get("auth_password"):
                raise ApiError(422, "validation_error", "SNMPv3 auth password is required",
                               [{"field": "snmp.auth_password", "message": "required"}])
            if sn.security_level == "authPriv" and not secret.get("priv_password"):
                raise ApiError(422, "validation_error", "SNMPv3 privacy password is required",
                               [{"field": "snmp.priv_password", "message": "required"}])
        if c is None:
            c = ServerCredential(credential_type="snmp", created_by=ctx.user_id, port=161)
            s.credentials.append(c)
        c.snmp_version, c.snmp_username = sn.version, sn.username
        c.snmp_auth_protocol, c.snmp_priv_protocol, c.snmp_security_level = sn.auth_protocol, sn.priv_protocol, sn.security_level
        c.secret_ciphertext = crypto.encrypt_json(secret, "cred:snmp")
        c.updated_by = ctx.user_id
    elif m == "nrpe":
        nr = body.nrpe or NrpeIn()
        c = creds.get("nrpe")
        if c is None:
            c = ServerCredential(credential_type="nrpe", created_by=ctx.user_id)
            s.credentials.append(c)
        c.port, c.timeout, c.updated_by = nr.port, nr.timeout, ctx.user_id
    # drop credentials of other methods
    for t, c in creds.items():
        if t != m:
            s.credentials.remove(c)


def _sync_services(db: Session, s: Server, items: list[ServiceItemIn], ctx: AuditContext) -> None:
    catalog = {c.id: c for c in db.scalars(select(Service))}
    by_id = {ss.id: ss for ss in s.services}
    keep: set[int] = set()
    descs: set[str] = set()
    for it in items:
        cat = catalog.get(it.service_id)
        if cat is None:
            raise ApiError(422, "validation_error", "Unknown service definition",
                           [{"field": "services.service_id", "message": f"{it.service_id} not found"}])
        if it.service_description in descs:
            raise ApiError(422, "validation_error", "Duplicate service description",
                           [{"field": "services.service_description", "message": it.service_description}])
        descs.add(it.service_description)
        params = V.validate_params(cat.params_schema, it.params)
        ss = by_id.get(it.id) if it.id else None
        if ss is None:
            ss = ServerService(service_id=cat.id, created_by=ctx.user_id)
            s.services.append(ss)
        ss.service_id = cat.id
        ss.service = cat
        ss.service_description = it.service_description
        ss.params = params
        ss.is_enabled = it.is_enabled
        ss.updated_by = ctx.user_id
        if ss.threshold is None:
            ss.threshold = ServiceThreshold()
        th = ss.threshold
        th.warning, th.critical = it.warning, it.critical
        th.check_interval, th.retry_interval = it.check_interval, it.retry_interval
        th.max_check_attempts, th.notification_interval = it.max_check_attempts, it.notification_interval
        th.notifications_enabled = it.notifications_enabled
        if ss.id:
            keep.add(ss.id)
    for ss in list(s.services):
        if ss.id and ss.id not in keep:
            s.services.remove(ss)


def template_items(tpl: MonitoringTemplate) -> list[ServiceItemIn]:
    return [ServiceItemIn(service_id=i.service_id, service_description=i.service_description, params=i.params,
                          warning=i.warning, critical=i.critical,
                          check_interval=i.check_interval or i.service.default_check_interval,
                          retry_interval=i.retry_interval or i.service.default_retry_interval,
                          notification_interval=i.notification_interval if i.notification_interval is not None
                          else i.service.default_notification_interval,
                          notifications_enabled=i.notifications_enabled)
            for i in tpl.items]


def _run_action(db: Session, ctx: AuditContext, principal: Principal, action: str, summary: str) -> dict | None:
    if action in ("draft", "save"):
        return None
    if action == "validate" and not principal.has("config.validate"):
        raise ApiError(403, "forbidden", "You do not have permission to validate configuration")
    if action == "apply" and not principal.has("config.apply"):
        raise ApiError(403, "forbidden", "You do not have permission to apply configuration")
    try:
        v = pipeline.run_pipeline(db, ctx, summary, apply=(action == "apply"))
    except pipeline.PipelineBusy as exc:
        raise ApiError(409, "busy", str(exc))
    return version_payload(v)


def _hostname_taken(db: Session, hostname: str, exclude_id: int | None = None) -> bool:
    stmt = select(Server.id).where(Server.hostname == hostname, Server.deleted_token == 0)
    if exclude_id:
        stmt = stmt.where(Server.id != exclude_id)
    return db.scalar(stmt) is not None


# ---------------------------------------------------------------- create --
@router.post("", status_code=201)
def create_server(body: ServerIn, request: Request, principal: Principal = Depends(require("servers.create")),
                  db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    if _hostname_taken(db, body.hostname):
        raise ApiError(409, "conflict", f"A server named '{body.hostname}' already exists")
    s = Server(created_by=ctx.user_id, updated_by=ctx.user_id)
    _apply_fields(db, s, body)
    s.config_state = "draft" if body.action == "draft" else "pending"
    db.add(s)
    db.flush()
    _upsert_credentials(db, s, body, ctx, creating=True)
    items = body.services
    if items is None and s.template_id:
        items = template_items(db.get(MonitoringTemplate, s.template_id))
    _sync_services(db, s, items or [], ctx)
    for ss in s.services:
        if s.template_id and body.services is None:
            ss.from_template_id = s.template_id
    db.flush()
    record_change(db, ctx, "server", s.id, s.hostname, "create", new=audit_view(s))
    audit(db, ctx, "server.create", entity_type="server", entity_id=s.id, entity_name=s.hostname, new=audit_view(s))
    db.commit()
    version = _run_action(db, ctx, principal, body.action, f"Added server {s.hostname}")
    db.refresh(s)
    return ok({"server": server_payload(s, get_status(), detail=True), "version": version})


# ---------------------------------------------------------------- update --
@router.put("/{server_id}")
def update_server(server_id: int, body: ServerIn, request: Request,
                  principal: Principal = Depends(require("servers.edit")), db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Server, server_id, "server")
    if s.managed_by != "portal":
        raise ApiError(409, "read_only", "This server is managed in manual Nagios configuration (imported read-only). "
                                         "Use Import > Take over to manage it here.")
    if _hostname_taken(db, body.hostname, exclude_id=s.id):
        raise ApiError(409, "conflict", f"A server named '{body.hostname}' already exists")
    old = audit_view(s)
    _apply_fields(db, s, body)
    _upsert_credentials(db, s, body, ctx, creating=False)
    if body.services is not None:
        _sync_services(db, s, body.services, ctx)
    s.updated_by = ctx.user_id
    if body.action == "draft":
        s.config_state = "draft"
    elif s.config_state in ("applied", "error", "draft"):
        s.config_state = "pending"
    db.flush()
    new = audit_view(s)
    if old != new:
        record_change(db, ctx, "server", s.id, s.hostname, "update", old=old, new=new)
    audit(db, ctx, "server.update", entity_type="server", entity_id=s.id, entity_name=s.hostname, old=old, new=new)
    db.commit()
    version = _run_action(db, ctx, principal, body.action, f"Modified server {s.hostname}")
    db.refresh(s)
    return ok({"server": server_payload(s, get_status(), detail=True), "version": version})


@router.delete("/{server_id}")
def delete_server(server_id: int, request: Request, apply: bool = False,
                  principal: Principal = Depends(require("servers.delete")), db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Server, server_id, "server")
    old = audit_view(s)
    s.deleted_at = utcnow()
    s.deleted_token = s.id
    s.updated_by = ctx.user_id
    if s.managed_by == "portal" and s.config_state != "draft":
        record_change(db, ctx, "server", s.id, s.hostname, "delete", old=old)
    audit(db, ctx, "server.delete", entity_type="server", entity_id=s.id, entity_name=s.hostname, old=old)
    db.commit()
    version = _run_action(db, ctx, principal, "apply" if apply else "save", f"Deleted server {s.hostname}")
    return ok({"deleted": True, "version": version})


def _toggle(db: Session, request: Request, principal: Principal, server_id: int, enabled: bool, action: str):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Server, server_id, "server")
    if s.managed_by != "portal":
        raise ApiError(409, "read_only", "This server is managed in manual Nagios configuration")
    if s.is_enabled == enabled:
        return ok({"server": server_payload(s, get_status()), "version": None})
    s.is_enabled = enabled
    if s.config_state in ("applied", "error"):
        s.config_state = "pending"
    record_change(db, ctx, "server", s.id, s.hostname, "enable" if enabled else "disable",
                  old={"is_enabled": not enabled}, new={"is_enabled": enabled})
    audit(db, ctx, "server.enable" if enabled else "server.disable", entity_type="server", entity_id=s.id,
          entity_name=s.hostname, old={"is_enabled": not enabled}, new={"is_enabled": enabled})
    db.commit()
    version = _run_action(db, ctx, principal, action, f"{'Enabled' if enabled else 'Disabled'} server {s.hostname}")
    return ok({"server": server_payload(s, get_status()), "version": version})


@router.post("/{server_id}/enable")
def enable_server(server_id: int, request: Request, body: ActionIn | None = None,
                  principal: Principal = Depends(require("servers.edit")), db: Session = Depends(get_db)):
    return _toggle(db, request, principal, server_id, True, (body or ActionIn()).action)


@router.post("/{server_id}/disable")
def disable_server(server_id: int, request: Request, body: ActionIn | None = None,
                   principal: Principal = Depends(require("servers.edit")), db: Session = Depends(get_db)):
    return _toggle(db, request, principal, server_id, False, (body or ActionIn()).action)


# ------------------------------------------------------ connection test --
def _do_test(db: Session, body: ConnectionTestIn, server: Server | None) -> dict:
    if body.monitoring_method == "ncpa":
        n = body.ncpa
        token = n.token if n and n.token else None
        port, verify, timeout, ssl = (n.port, n.verify_ssl, min(n.timeout, 20), n.ssl_enabled) if n else (5693, False, 10, True)
        if token is None and server is not None:
            c = next((c for c in server.credentials if c.credential_type == "ncpa"), None)
            if c and c.secret_ciphertext:
                token = crypto.decrypt_json(c.secret_ciphertext, "cred:ncpa").get("token")
                if not n:
                    port, verify, timeout, ssl = c.port or 5693, c.verify_ssl, min(c.timeout, 20), c.ssl_enabled
        if not token:
            raise ApiError(422, "validation_error", "Enter the NCPA token to test the connection",
                           [{"field": "ncpa.token", "message": "required"}])
        return agents.test_ncpa(body.address, port, token, verify_ssl=verify, timeout=timeout, ssl_enabled=ssl)
    if body.monitoring_method == "snmp":
        sn = body.snmp
        cred: dict = {}
        if server is not None:
            c = next((c for c in server.credentials if c.credential_type == "snmp"), None)
            if c and c.secret_ciphertext:
                cred = crypto.decrypt_json(c.secret_ciphertext, "cred:snmp")
                cred.update(version=c.snmp_version, username=c.snmp_username, auth_protocol=c.snmp_auth_protocol,
                            priv_protocol=c.snmp_priv_protocol, security_level=c.snmp_security_level)
        if sn:
            cred.update({k: v for k, v in sn.model_dump().items() if v})
        return agents.test_snmp(body.address, cred)
    raise ApiError(422, "validation_error", "Connection test is available for NCPA and SNMP")


@router.post("/test-connection")
def test_connection(body: ConnectionTestIn, request: Request, principal: Principal = Depends(require("servers.test")),
                    db: Session = Depends(get_db)):
    server = get_or_404(db, Server, body.server_id, "server") if body.server_id else None
    res = _do_test(db, body, server)
    audit(db, ctx_from(request, principal), "server.test_connection", entity_type="server",
          entity_id=server.id if server else None, entity_name=server.hostname if server else body.address,
          result="success" if res["result"] == "success" else "failure", detail=res["label"])
    db.commit()
    return ok(res)


@router.post("/{server_id}/test")
def test_server(server_id: int, request: Request, principal: Principal = Depends(require("servers.test")),
                db: Session = Depends(get_db)):
    s = get_or_404(db, Server, server_id, "server")
    res = _do_test(db, ConnectionTestIn(address=s.address, monitoring_method=s.monitoring_method), s)
    c = next((c for c in s.credentials if c.credential_type == s.monitoring_method), None)
    if c:
        c.last_test_at, c.last_test_result = utcnow(), res["result"]
    audit(db, ctx_from(request, principal), "server.test_connection", entity_type="server", entity_id=s.id,
          entity_name=s.hostname, result="success" if res["result"] == "success" else "failure", detail=res["label"])
    db.commit()
    return ok(res)


# -------------------------------------------------------- pipeline actions --
@router.post("/{server_id}/validate")
def validate_server(server_id: int, request: Request, principal: Principal = Depends(require("config.validate")),
                    db: Session = Depends(get_db)):
    s = get_or_404(db, Server, server_id, "server")
    if s.config_state == "draft":
        s.config_state = "pending"
        db.commit()
    return ok({"version": _run_action(db, ctx_from(request, principal), principal, "validate",
                                      f"Validate configuration ({s.hostname})")})


@router.post("/{server_id}/apply")
def apply_server(server_id: int, request: Request, principal: Principal = Depends(require("config.apply")),
                 db: Session = Depends(get_db)):
    s = get_or_404(db, Server, server_id, "server")
    if s.config_state == "draft":
        s.config_state = "pending"
        db.commit()
    return ok({"version": _run_action(db, ctx_from(request, principal), principal, "apply",
                                      f"Apply configuration ({s.hostname})")})


# ------------------------------------------------------------- services --
@router.put("/{server_id}/services")
def replace_services(server_id: int, items: list[ServiceItemIn], request: Request,
                     principal: Principal = Depends(require("servers.edit")), db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Server, server_id, "server")
    if s.managed_by != "portal":
        raise ApiError(409, "read_only", "This server is managed in manual Nagios configuration")
    old = audit_view(s)["services"]
    _sync_services(db, s, items, ctx)
    if s.config_state in ("applied", "error"):
        s.config_state = "pending"
    db.flush()
    new = audit_view(s)["services"]
    record_change(db, ctx, "server_services", s.id, s.hostname, "update", old={"services": old}, new={"services": new})
    audit(db, ctx, "server.services_update", entity_type="server", entity_id=s.id, entity_name=s.hostname,
          old={"services": old}, new={"services": new})
    db.commit()
    db.refresh(s)
    return ok([service_payload(ss, get_status(), s.hostname) for ss in s.services])


@router.post("/{server_id}/apply-template/{template_id}")
def apply_template(server_id: int, template_id: int, request: Request, replace: bool = False,
                   principal: Principal = Depends(require("servers.edit")), db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Server, server_id, "server")
    tpl = get_or_404(db, MonitoringTemplate, template_id, "template")
    existing = [] if replace else [
        ServiceItemIn(id=ss.id, service_id=ss.service_id, service_description=ss.service_description, params=ss.params,
                      is_enabled=ss.is_enabled, warning=ss.threshold.warning if ss.threshold else None,
                      critical=ss.threshold.critical if ss.threshold else None,
                      check_interval=ss.threshold.check_interval if ss.threshold else 5,
                      retry_interval=ss.threshold.retry_interval if ss.threshold else 1,
                      max_check_attempts=ss.threshold.max_check_attempts if ss.threshold else 3,
                      notification_interval=ss.threshold.notification_interval if ss.threshold else 60,
                      notifications_enabled=ss.threshold.notifications_enabled if ss.threshold else True)
        for ss in s.services]
    have = {i.service_description for i in existing}
    items = existing + [i for i in template_items(tpl) if i.service_description not in have]
    _sync_services(db, s, items, ctx)
    s.template_id = tpl.id
    if s.config_state in ("applied", "error"):
        s.config_state = "pending"
    record_change(db, ctx, "server", s.id, s.hostname, "apply_template", new={"template": tpl.name, "replace": replace})
    audit(db, ctx, "server.apply_template", entity_type="server", entity_id=s.id, entity_name=s.hostname,
          new={"template": tpl.name, "replace": replace})
    db.commit()
    db.refresh(s)
    return ok(server_payload(s, get_status(), detail=True))


# ----------------------------------------------------- monitoring views --
@router.get("/{server_id}/performance")
def performance(server_id: int, hours: int = Query(24, ge=1, le=24 * 90), service: str | None = Query(None, max_length=100),
                principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    s = get_or_404(db, Server, server_id, "server")
    since = utcnow() - timedelta(hours=hours)
    stmt = select(PerfSample).where(PerfSample.server_id == s.id, PerfSample.sampled_at >= since)
    if service:
        stmt = stmt.where(PerfSample.service_description == service)
    stmt = stmt.order_by(PerfSample.sampled_at)
    series: dict[tuple, dict] = {}
    for p in db.scalars(stmt):
        k = (p.service_description, p.label)
        ser = series.setdefault(k, {"service": p.service_description, "label": p.label, "uom": p.uom,
                                    "category": p.category, "warn": p.warn, "crit": p.crit, "points": []})
        ser["points"].append([p.sampled_at.isoformat() + "Z", p.value])
    out = []
    max_points = 400
    for ser in series.values():
        pts = ser["points"]
        if len(pts) > max_points:
            step = len(pts) / max_points
            pts = [pts[int(i * step)] for i in range(max_points)] + [pts[-1]]
        ser["points"] = pts
        out.append(ser)
    return ok(out, {"hours": hours})


@router.get("/{server_id}/events")
def server_events(server_id: int, limit: int = Query(200, ge=1, le=1000),
                  principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    s = get_or_404(db, Server, server_id, "server")
    return ok(logparser.recent_events(limit=limit, host=s.hostname))


@router.get("/{server_id}/history")
def server_history(server_id: int, principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    s = db.get(Server, server_id)
    if s is None:
        raise ApiError(404, "not_found", "server not found")
    logs = db.scalars(select(AuditLog).where(AuditLog.entity_type == "server", AuditLog.entity_id == s.id)
                      .order_by(AuditLog.occurred_at.desc()).limit(300))
    changes = db.scalars(select(ConfigurationChange).where(ConfigurationChange.entity_id == s.id,
                                                           ConfigurationChange.entity_type.in_(("server", "server_services")))
                         .order_by(ConfigurationChange.created_at.desc()).limit(300))
    return ok({
        "audit": [{"id": a.id, "time": iso(a.occurred_at), "user": a.username, "action": a.action, "result": a.result,
                   "ip": a.ip_address, "old": a.old_value, "new": a.new_value, "detail": a.detail} for a in logs],
        "changes": [{"id": c.id, "time": iso(c.created_at), "action": c.action, "version_id": c.version_id,
                     "old": c.old_value, "new": c.new_value} for c in changes],
    })
