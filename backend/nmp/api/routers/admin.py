"""Administration: users, roles & permissions, system settings, audit log, health."""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from ... import validators as V
from ...audit import audit
from ...config import get_settings
from ...db import get_db, utcnow
from ...models import (AuditLog, ConfigBackup, ConfigurationVersion, ConfigurationVersionFile, Permission, Role,
                       Server, SystemSetting, User, WorkerHeartbeat)
from ...nagios import privileged
from ...nagios.status import get_status
from ...security import passwords
from ...security.rbac import PERMISSIONS, SUPER_ADMIN_ONLY
from ...security.sessions import revoke_user_sessions
from ..deps import Principal, ctx_from, require
from ..errors import ApiError
from ..util import csv_response, iso, ok, paginate, ts_iso

router = APIRouter(tags=["administration"])


# ================================================================= users ==
class UserIn(BaseModel):
    username: str
    full_name: str = ""
    email: Optional[str] = None
    role_ids: list[int] = Field(min_length=1)
    is_active: bool = True
    password: Optional[str] = Field(None, max_length=256)
    must_change_password: bool = True

    @field_validator("username")
    @classmethod
    def _u(cls, v):
        v = v.strip().lower()
        if not V.USERNAME_RE.match(v):
            raise ValueError("3-64 chars: letters, digits, '.', '_' or '-'")
        return v

    @field_validator("full_name")
    @classmethod
    def _f(cls, v):
        return V.check_free_text(v, "full_name", 120) or ""

    @field_validator("email")
    @classmethod
    def _e(cls, v):
        return V.check_email(v)


def user_payload(u: User) -> dict:
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "email": u.email, "is_active": u.is_active,
            "roles": [{"id": r.id, "name": r.name, "display_name": r.display_name} for r in u.roles],
            "must_change_password": u.must_change_password, "locked": bool(u.locked_until and u.locked_until > utcnow()),
            "last_login_at": iso(u.last_login_at), "last_login_ip": u.last_login_ip, "created_at": iso(u.created_at)}


def _super_admin_count(db: Session, exclude: int | None = None) -> int:
    n = 0
    for u in db.scalars(select(User).where(User.is_active.is_(True))):
        if u.id != exclude and any(r.name == "super_admin" for r in u.roles):
            n += 1
    return n


def _assert_can_grant(principal: Principal, roles: list[Role]) -> None:
    """Prevent privilege escalation: nobody can grant permissions they do not hold."""
    for r in roles:
        missing = {p.code for p in r.permissions} - set(principal.permissions)
        if missing:
            raise ApiError(403, "forbidden", f"You cannot assign role '{r.display_name}' (it has permissions you do not hold)")


@router.get("/api/users")
def list_users(principal: Principal = Depends(require("users.manage")), db: Session = Depends(get_db)):
    return ok([user_payload(u) for u in db.scalars(select(User).order_by(User.username))])


@router.post("/api/users", status_code=201)
def create_user(body: UserIn, request: Request, principal: Principal = Depends(require("users.manage")),
                db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    if db.scalar(select(User).where(User.username == body.username)):
        raise ApiError(409, "conflict", "Username already exists")
    if not body.password:
        raise ApiError(422, "validation_error", "Initial password is required", [{"field": "password", "message": "required"}])
    errs = passwords.password_policy_errors(body.password, body.username)
    if errs:
        raise ApiError(422, "weak_password", "Password does not meet the policy", [{"field": "password", "message": e} for e in errs])
    roles = list(db.scalars(select(Role).where(Role.id.in_(body.role_ids))))
    if len(roles) != len(set(body.role_ids)):
        raise ApiError(422, "validation_error", "Unknown role", [{"field": "role_ids", "message": "unknown id"}])
    _assert_can_grant(principal, roles)
    u = User(username=body.username, full_name=body.full_name, email=body.email, is_active=body.is_active,
             password_hash=passwords.hash_password(body.password), must_change_password=body.must_change_password,
             created_by=ctx.user_id, password_changed_at=utcnow())
    u.roles = roles
    db.add(u)
    db.flush()
    audit(db, ctx, "user.create", entity_type="user", entity_id=u.id, entity_name=u.username, new=user_payload(u))
    db.commit()
    return ok(user_payload(u))


@router.put("/api/users/{uid}")
def update_user(uid: int, body: UserIn, request: Request, principal: Principal = Depends(require("users.manage")),
                db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    u = db.get(User, uid)
    if u is None:
        raise ApiError(404, "not_found", "user not found")
    old = user_payload(u)
    roles = list(db.scalars(select(Role).where(Role.id.in_(body.role_ids))))
    if len(roles) != len(set(body.role_ids)):
        raise ApiError(422, "validation_error", "Unknown role", [{"field": "role_ids", "message": "unknown id"}])
    _assert_can_grant(principal, roles)
    was_super = any(r.name == "super_admin" for r in u.roles)
    will_be_super = any(r.name == "super_admin" for r in roles) and body.is_active
    if was_super and not will_be_super and _super_admin_count(db, exclude=u.id) == 0:
        raise ApiError(409, "last_super_admin", "At least one active Super Admin must remain")
    if u.id == principal.user.id and not body.is_active:
        raise ApiError(409, "self_disable", "You cannot deactivate your own account")
    u.full_name, u.email, u.is_active = body.full_name, body.email, body.is_active
    u.roles = roles
    u.updated_by = ctx.user_id
    if body.password:
        errs = passwords.password_policy_errors(body.password, u.username)
        if errs:
            raise ApiError(422, "weak_password", "Password does not meet the policy", [{"field": "password", "message": e} for e in errs])
        u.password_hash = passwords.hash_password(body.password)
        u.must_change_password = body.must_change_password
        u.password_changed_at = utcnow()
    if not u.is_active or body.password or {r["id"] for r in old["roles"]} != set(body.role_ids):
        revoke_user_sessions(db, u.id, except_id=principal.session.id if u.id == principal.user.id else None)
    audit(db, ctx, "user.update", entity_type="user", entity_id=u.id, entity_name=u.username, old=old, new=user_payload(u))
    db.commit()
    return ok(user_payload(u))


@router.post("/api/users/{uid}/unlock")
def unlock_user(uid: int, request: Request, principal: Principal = Depends(require("users.manage")),
                db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if u is None:
        raise ApiError(404, "not_found", "user not found")
    u.locked_until, u.failed_logins = None, 0
    audit(db, ctx_from(request, principal), "user.unlock", entity_type="user", entity_id=u.id, entity_name=u.username)
    db.commit()
    return ok(user_payload(u))


@router.delete("/api/users/{uid}")
def delete_user(uid: int, request: Request, principal: Principal = Depends(require("users.manage")),
                db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if u is None:
        raise ApiError(404, "not_found", "user not found")
    if u.id == principal.user.id:
        raise ApiError(409, "self_delete", "You cannot delete your own account")
    if any(r.name == "super_admin" for r in u.roles) and _super_admin_count(db, exclude=u.id) == 0:
        raise ApiError(409, "last_super_admin", "At least one active Super Admin must remain")
    audit(db, ctx_from(request, principal), "user.delete", entity_type="user", entity_id=u.id, entity_name=u.username,
          old=user_payload(u))
    db.delete(u)
    db.commit()
    return ok({"deleted": True})


# ================================================================= roles ==
class RoleIn(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    display_name: str
    description: Optional[str] = None
    permissions: list[str]

    @field_validator("display_name")
    @classmethod
    def _dn(cls, v):
        return V.check_free_text(v, "display_name", 100, required=True)

    @field_validator("description")
    @classmethod
    def _d(cls, v):
        return V.check_free_text(v, "description", 255)

    @field_validator("permissions")
    @classmethod
    def _p(cls, v):
        bad = [p for p in v if p not in PERMISSIONS]
        if bad:
            raise ValueError(f"unknown permissions: {', '.join(bad)}")
        reserved = sorted(set(v) & SUPER_ADMIN_ONLY)
        if reserved:
            raise ValueError(f"reserved for the Super Admin role: {', '.join(reserved)}")
        return sorted(set(v))


def role_payload(r: Role, users: int = 0) -> dict:
    return {"id": r.id, "name": r.name, "display_name": r.display_name, "description": r.description,
            "is_system": r.is_system, "permissions": sorted(p.code for p in r.permissions), "users": users}


@router.get("/api/permissions")
def list_permissions(principal: Principal = Depends(require("users.manage"))):
    return ok([{"code": k, "category": c, "description": d} for k, (c, d) in PERMISSIONS.items()])


@router.get("/api/roles")
def list_roles(principal: Principal = Depends(require("users.manage")), db: Session = Depends(get_db)):
    from ...models import UserRole
    counts = dict(db.execute(select(UserRole.role_id, func.count()).group_by(UserRole.role_id)).all())
    return ok([role_payload(r, counts.get(r.id, 0)) for r in db.scalars(select(Role).order_by(Role.id))])


def _role_write(db, request, principal, body: RoleIn, r: Role | None):
    ctx = ctx_from(request, principal)
    missing = set(body.permissions) - set(principal.permissions)
    if missing:
        raise ApiError(403, "forbidden", "You cannot grant permissions you do not hold", sorted(missing))
    creating = r is None
    if creating:
        r = Role(name=body.name)
        db.add(r)
        old = None
    else:
        if r.name == "super_admin":
            raise ApiError(409, "read_only", "The Super Admin role cannot be modified")
        old = role_payload(r)
    r.display_name, r.description = body.display_name, body.description
    r.permissions = list(db.scalars(select(Permission).where(Permission.code.in_(body.permissions))))
    db.flush()
    audit(db, ctx, "role.create" if creating else "role.update", entity_type="role", entity_id=r.id, entity_name=r.name,
          old=old, new=role_payload(r))
    db.commit()
    return ok(role_payload(r))


@router.post("/api/roles", status_code=201)
def create_role(body: RoleIn, request: Request, principal: Principal = Depends(require("roles.manage")),
                db: Session = Depends(get_db)):
    if db.scalar(select(Role).where(Role.name == body.name)):
        raise ApiError(409, "conflict", "Role already exists")
    return _role_write(db, request, principal, body, None)


@router.put("/api/roles/{rid}")
def update_role(rid: int, body: RoleIn, request: Request, principal: Principal = Depends(require("roles.manage")),
                db: Session = Depends(get_db)):
    r = db.get(Role, rid)
    if r is None:
        raise ApiError(404, "not_found", "role not found")
    return _role_write(db, request, principal, body, r)


@router.delete("/api/roles/{rid}")
def delete_role(rid: int, request: Request, principal: Principal = Depends(require("roles.manage")),
                db: Session = Depends(get_db)):
    r = db.get(Role, rid)
    if r is None:
        raise ApiError(404, "not_found", "role not found")
    if r.is_system:
        raise ApiError(409, "read_only", "Built-in roles cannot be deleted")
    from ...models import UserRole
    if db.scalar(select(func.count()).select_from(UserRole).where(UserRole.role_id == r.id)):
        raise ApiError(409, "in_use", "Role is assigned to users")
    audit(db, ctx_from(request, principal), "role.delete", entity_type="role", entity_id=r.id, entity_name=r.name,
          old=role_payload(r))
    db.delete(r)
    db.commit()
    return ok({"deleted": True})


# ============================================================== settings ==
SETTING_VALIDATORS: dict[str, Any] = {
    "display_timezone": lambda v: _tz(v),
    "default_contact_group": lambda v: V.check_object_name(v, "default_contact_group"),
    "ncpa_default_port": lambda v: V.check_interval(v, "ncpa_default_port", 1, 65535),
    "ncpa_default_timeout": lambda v: V.check_interval(v, "ncpa_default_timeout", 3, 120),
    "ncpa_default_verify_ssl": lambda v: bool(v),
    "perf_retention_days": lambda v: V.check_interval(v, "perf_retention_days", 1, 730),
    "sla_targets": lambda v: {k: float(x) for k, x in dict(v).items()
                              if k in ("production", "uat", "development", "dr", "test") and 0 <= float(x) <= 100},
    "host_notification_command": lambda v: V.check_object_name(v, "host_notification_command"),
    "service_notification_command": lambda v: V.check_object_name(v, "service_notification_command"),
    "health_thresholds": lambda v: {k: V.check_interval(x, k, 1, 100) for k, x in dict(v).items() if k in ("cpu", "memory", "disk")},
    "session_idle_minutes": lambda v: V.check_interval(v, "session_idle_minutes", 5, 480),
}


def _tz(v):
    from zoneinfo import ZoneInfo
    try:
        ZoneInfo(str(v))
    except Exception:
        raise V.ValidationError("display_timezone", "unknown time zone")
    return str(v)


@router.get("/api/settings")
def get_settings_api(principal: Principal = Depends(require("dashboard.view")), db: Session = Depends(get_db)):
    return ok({s.key: s.value for s in db.scalars(select(SystemSetting))})


@router.put("/api/settings")
def put_settings(body: dict, request: Request, principal: Principal = Depends(require("settings.manage")),
                 db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    changed = {}
    for k, v in body.items():
        if k not in SETTING_VALIDATORS:
            raise ApiError(422, "validation_error", f"Unknown setting '{k}'", [{"field": k, "message": "unknown"}])
        try:
            val = SETTING_VALIDATORS[k](v)
        except (TypeError, ValueError) as exc:
            msg = exc.message if isinstance(exc, V.ValidationError) else "invalid value"
            raise ApiError(422, "validation_error", "Invalid setting", [{"field": k, "message": msg}])
        row = db.get(SystemSetting, k)
        old = row.value if row else None
        if row is None:
            row = SystemSetting(key=k, value=val)
            db.add(row)
        else:
            row.value = val
        row.updated_by = ctx.user_id
        if old != val:
            changed[k] = {"old": old, "new": val}
    if changed:
        audit(db, ctx, "settings.update", entity_type="settings", old={k: c["old"] for k, c in changed.items()},
              new={k: c["new"] for k, c in changed.items()})
    db.commit()
    return ok({s.key: s.value for s in db.scalars(select(SystemSetting))})


# ================================================================= audit ==
def _audit_query(db: Session, q, user, action, entity_type, result, since, until):
    stmt = select(AuditLog)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(AuditLog.entity_name.like(like), AuditLog.detail.like(like), AuditLog.action.like(like)))
    if user:
        stmt = stmt.where(AuditLog.username == user)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if since:
        stmt = stmt.where(AuditLog.occurred_at >= since.replace(tzinfo=None))
    if until:
        stmt = stmt.where(AuditLog.occurred_at <= until.replace(tzinfo=None))
    return stmt.order_by(AuditLog.id.desc())


def audit_payload(a: AuditLog) -> dict:
    return {"id": a.id, "time": iso(a.occurred_at), "user": a.username, "ip": a.ip_address, "action": a.action,
            "entity_type": a.entity_type, "entity_id": a.entity_id, "entity_name": a.entity_name,
            "old": a.old_value, "new": a.new_value, "result": a.result, "detail": a.detail}


@router.get("/api/audit")
def audit_log(q: Optional[str] = Query(None, max_length=100), user: Optional[str] = Query(None, max_length=64),
              action: Optional[str] = Query(None, max_length=64), entity_type: Optional[str] = Query(None, max_length=32),
              result: Optional[str] = Query(None, pattern="^(success|failure|denied)$"),
              since: Optional[datetime] = None, until: Optional[datetime] = None,
              page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
              format: str = Query("json", pattern="^(json|csv)$"),
              principal: Principal = Depends(require("audit.view")), db: Session = Depends(get_db)):
    stmt = _audit_query(db, q, user, action, entity_type, result, since, until)
    if format == "csv":
        rows = db.scalars(stmt.limit(100000))
        return csv_response("audit-log.csv", ["time_utc", "user", "ip", "action", "entity_type", "entity",
                                              "result", "detail", "old_value", "new_value"],
                            ([iso(a.occurred_at), a.username, a.ip_address, a.action, a.entity_type, a.entity_name,
                              a.result, a.detail, a.old_value, a.new_value] for a in rows))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size))
    return ok([audit_payload(a) for a in items], {"total": total, "page": page, "page_size": page_size,
                                                  "pages": (total + page_size - 1) // page_size})


# ================================================================ health ==
def _svc_state(name: str) -> str:
    try:
        p = subprocess.run(["/usr/bin/systemctl", "is-active", name], capture_output=True, text=True, timeout=5,
                           env={"PATH": "/usr/bin:/bin"})
        return p.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _cpu_percent() -> float | None:
    def read():
        with open("/proc/stat") as fh:
            parts = [int(x) for x in fh.readline().split()[1:]]
        return sum(parts), parts[3] + (parts[4] if len(parts) > 4 else 0)
    try:
        import time
        t1, i1 = read()
        time.sleep(0.2)
        t2, i2 = read()
        return round(100.0 * (1 - (i2 - i1) / max(1, t2 - t1)), 1)
    except OSError:
        return None


def _meminfo() -> dict:
    out = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, v = line.split(":", 1)
                out[k] = int(v.split()[0]) * 1024
    except OSError:
        return {}
    total, avail = out.get("MemTotal", 0), out.get("MemAvailable", 0)
    return {"total_bytes": total, "available_bytes": avail,
            "used_percent": round(100 * (1 - avail / total), 1) if total else None}


@router.get("/api/health")
def health(deep: bool = False, principal: Principal = Depends(require("health.view")), db: Session = Depends(get_db)):
    s = get_settings()
    snap = get_status()
    checks: list[dict] = []

    def add(name, status, detail="", **extra):
        checks.append({"name": name, "status": status, "detail": detail, **extra})

    nagios_state = _svc_state(s.nagios_service)
    age = int(datetime.now(timezone.utc).timestamp() - snap.mtime) if snap.mtime else None
    add("Nagios", "ok" if nagios_state == "active" and not snap.error and (age or 0) < 120 else "critical",
        f"service {nagios_state}; status.dat age {age}s" if age is not None else (snap.error or nagios_state),
        pid=snap.program.get("nagios_pid"), program_start=ts_iso(snap.program.get("program_start")))
    add("Apache", "ok" if _svc_state("apache2") == "active" else "warning", _svc_state("apache2"))
    try:
        ver = db.execute(text("SELECT VERSION()")).scalar()
        add("MariaDB", "ok", f"connected ({ver})")
    except Exception as exc:  # pragma: no cover
        add("MariaDB", "critical", type(exc).__name__)
    for label, path in (("Disk (/)", "/"), ("Disk (backups)", s.backup_dir if os.path.exists(s.backup_dir) else "/")):
        du = shutil.disk_usage(path)
        pct = round(100 * du.used / du.total, 1)
        add(label, "ok" if pct < 85 else "warning" if pct < 95 else "critical", f"{pct}% used, {du.free // (1024**3)} GB free",
            used_percent=pct)
    mem = _meminfo()
    if mem:
        add("Memory", "ok" if (mem["used_percent"] or 0) < 90 else "warning", f"{mem['used_percent']}% used", **mem)
    cpu = _cpu_percent()
    load = os.getloadavg()
    add("CPU", "ok" if (cpu or 0) < 90 else "warning", f"{cpu}% busy, load {load[0]:.2f} {load[1]:.2f} {load[2]:.2f}",
        cpu_percent=cpu, cores=os.cpu_count())
    last = db.scalar(select(ConfigurationVersion).where(ConfigurationVersion.status == "applied")
                     .order_by(ConfigurationVersion.id.desc()))
    latest = db.scalar(select(ConfigurationVersion).order_by(ConfigurationVersion.id.desc()))
    drift = _drift(db, last)
    cfg_status = "ok"
    detail = f"version {last.id} applied {iso(last.applied_at)}" if last else "no configuration applied yet"
    if latest and latest.status in ("validation_failed", "apply_failed"):
        cfg_status, detail = "warning", detail + f"; latest v{latest.id} {latest.status}"
    if drift:
        cfg_status, detail = "warning", detail + f"; drift detected in {len(drift)} file(s)"
    add("Configuration", cfg_status, detail, drift=drift[:20])
    b = db.scalar(select(ConfigBackup).order_by(ConfigBackup.id.desc()))
    add("Last configuration backup", "ok" if b else "warning", f"{b.name} ({iso(b.created_at)})" if b else "none yet")
    hb = {h.name: h for h in db.scalars(select(WorkerHeartbeat))}
    w = hb.get("worker")
    wage = (utcnow() - w.last_run_at).total_seconds() if w else None
    add("Background worker", "ok" if wage is not None and wage < 180 else "warning",
        f"last run {int(wage)}s ago" if wage is not None else "not running")
    ncpa = _ncpa_summary(db, snap, probe=deep)
    add("NCPA connectivity", ncpa["status"], ncpa["detail"], agents=ncpa["agents"])
    if deep:
        try:
            res = privileged.run("status")
            add("Live configuration validation", "ok" if res.get("config_valid") else "critical",
                f"{len(res.get('errors') or [])} errors, {len(res.get('warnings') or [])} warnings",
                errors=res.get("errors"), warnings=res.get("warnings"))
        except privileged.PrivilegedError as exc:
            add("Live configuration validation", "warning", str(exc))
    overall = "critical" if any(c["status"] == "critical" for c in checks) else \
        "warning" if any(c["status"] == "warning" for c in checks) else "ok"
    return ok({"status": overall, "checks": checks, "hostname": socket.gethostname()})


def _drift(db: Session, v: ConfigurationVersion | None) -> list[str]:
    from pathlib import Path
    import hashlib

    if v is None:
        return []
    base = Path(get_settings().managed_dir)
    if not base.is_dir():
        return ["managed directory missing"]
    expected = {f.path[len("managed/"):]: f.sha256 for f in db.scalars(
        select(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id == v.id,
                                               ConfigurationVersionFile.path.like("managed/%")))}
    out = []
    try:
        actual = {str(p.relative_to(base)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in base.rglob("*") if p.is_file()}
    except OSError:
        return ["managed directory not readable"]
    for rel in sorted(set(expected) | set(actual)):
        if expected.get(rel) != actual.get(rel):
            out.append(rel)
    return out


def _ncpa_summary(db: Session, snap, probe: bool) -> dict:
    servers = list(db.scalars(select(Server).where(Server.deleted_token == 0, Server.monitoring_method == "ncpa")))
    agents = []
    bad = 0
    for s in servers:
        cred = next((c for c in s.credentials if c.credential_type == "ncpa"), None)
        port = cred.port if cred and cred.port else 5693
        h = snap.hosts.get(s.hostname)
        state = "UP" if h and h.get("current_state") == 0 and h.get("has_been_checked") else ("DOWN" if h else "UNKNOWN")
        reachable = None
        if probe:
            try:
                with socket.create_connection((s.address, port), timeout=2):
                    reachable = True
            except OSError:
                reachable = False
        if state != "UP" or reachable is False:
            bad += 1
        agents.append({"hostname": s.hostname, "address": s.address, "port": port, "host_state": state,
                       "tcp_reachable": reachable})
    status = "ok" if not bad else ("warning" if bad < max(1, len(servers)) else "critical")
    return {"status": status if servers else "ok", "agents": agents,
            "detail": f"{len(servers) - bad}/{len(servers)} agents healthy" if servers else "no NCPA servers"}
