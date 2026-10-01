"""Service definitions, commands, templates, host groups, contacts and contact groups."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import validators as V
from ...audit import audit, record_change
from ...config import get_settings
from ...db import get_db
from ...models import (Command, Contact, ContactGroup, MonitoringTemplate, Server, ServerGroup, ServerService, Service,
                       TemplateService)
from ...nagios.legacy import load_legacy
from ..deps import Principal, ctx_from, require
from ..errors import ApiError
from ..util import get_or_404, iso, ok

router = APIRouter(tags=["catalog"])

PARAM_TYPES = sorted(V.PARAM_PATTERNS)


# =============================================================== commands ==
class CommandIn(BaseModel):
    name: str
    command_line: str = Field(max_length=1024)
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_object_name(v)

    @field_validator("description")
    @classmethod
    def _d(cls, v):
        return V.check_free_text(v, "description", 255)


def _allowed_prefixes() -> list[str]:
    s = get_settings()
    return ["$USER1$/", s.plugin_dir_std.rstrip("/") + "/", s.plugin_dir_nmp.rstrip("/") + "/",
            s.plugin_dir_ncpa.rstrip("/") + "/"]


def command_payload(c: Command) -> dict:
    return {"id": c.id, "name": c.name, "command_line": c.command_line, "description": c.description,
            "is_system": c.is_system, "updated_at": iso(c.updated_at)}


@router.get("/api/commands")
def list_commands(principal: Principal = Depends(require("templates.view")), db: Session = Depends(get_db)):
    return ok([command_payload(c) for c in db.scalars(select(Command).order_by(Command.name))])


@router.post("/api/commands", status_code=201)
def create_command(body: CommandIn, request: Request, principal: Principal = Depends(require("catalog.manage")),
                   db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    cl = V.check_command_line(body.command_line, _allowed_prefixes())
    if body.name.startswith("nmp_"):
        raise ApiError(422, "validation_error", "The nmp_ prefix is reserved", [{"field": "name", "message": "reserved prefix"}])
    if body.name in load_legacy().names("command", "command_name"):
        raise ApiError(409, "conflict", "A command with this name exists in manual Nagios configuration")
    c = Command(name=body.name, command_line=cl, description=body.description, created_by=ctx.user_id)
    db.add(c)
    db.flush()
    record_change(db, ctx, "command", c.id, c.name, "create", new=command_payload(c))
    audit(db, ctx, "command.create", entity_type="command", entity_id=c.id, entity_name=c.name, new=command_payload(c))
    db.commit()
    return ok(command_payload(c))


@router.put("/api/commands/{cid}")
def update_command(cid: int, body: CommandIn, request: Request, principal: Principal = Depends(require("catalog.manage")),
                   db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    c = get_or_404(db, Command, cid, "command")
    if c.is_system:
        raise ApiError(409, "read_only", "Built-in commands cannot be modified")
    old = command_payload(c)
    c.command_line = V.check_command_line(body.command_line, _allowed_prefixes())
    c.description = body.description
    c.updated_by = ctx.user_id
    record_change(db, ctx, "command", c.id, c.name, "update", old=old, new=command_payload(c))
    audit(db, ctx, "command.update", entity_type="command", entity_id=c.id, entity_name=c.name, old=old, new=command_payload(c))
    db.commit()
    return ok(command_payload(c))


@router.delete("/api/commands/{cid}")
def delete_command(cid: int, request: Request, principal: Principal = Depends(require("catalog.manage")),
                   db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    c = get_or_404(db, Command, cid, "command")
    if c.is_system:
        raise ApiError(409, "read_only", "Built-in commands cannot be deleted")
    if db.scalar(select(func.count()).select_from(Service).where(Service.command_id == c.id)):
        raise ApiError(409, "in_use", "Command is used by service definitions")
    record_change(db, ctx, "command", c.id, c.name, "delete", old=command_payload(c))
    audit(db, ctx, "command.delete", entity_type="command", entity_id=c.id, entity_name=c.name, old=command_payload(c))
    db.delete(c)
    db.commit()
    return ok({"deleted": True})


# ===================================================== service definitions ==
class ParamIn(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,30}$")
    type: str
    label: str = Field(max_length=80)
    required: bool = False
    default: Optional[str] = Field(None, max_length=120)

    @field_validator("type")
    @classmethod
    def _t(cls, v):
        if v not in V.PARAM_PATTERNS:
            raise ValueError(f"unknown parameter type (allowed: {', '.join(PARAM_TYPES)})")
        return v


class ServiceDefIn(BaseModel):
    code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    name: str
    category: Literal["availability", "cpu", "memory", "disk", "processes", "services", "network", "uptime",
                      "eventlog", "users", "custom"]
    monitoring_method: Literal["ncpa", "snmp", "nrpe", "ping", "custom"]
    os_types: list[Literal["windows", "linux", "unix", "network", "other"]] = Field(min_length=1)
    command_id: int
    arg_template: str = Field("", max_length=512)
    params_schema: list[ParamIn] = Field(default_factory=list, max_length=10)
    default_description: str
    default_warning: Optional[str] = None
    default_critical: Optional[str] = None
    default_check_interval: int = Field(5, ge=1, le=1440)
    default_retry_interval: int = Field(1, ge=1, le=1440)
    default_notification_interval: int = Field(60, ge=0, le=10080)
    unit: Optional[str] = Field(None, max_length=16)
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_free_text(v, "name", 100, required=True)

    @field_validator("description")
    @classmethod
    def _d(cls, v):
        return V.check_free_text(v, "description", 255)

    @field_validator("default_warning", "default_critical")
    @classmethod
    def _th(cls, v, info):
        return V.check_threshold(v, info.field_name)

    @field_validator("arg_template")
    @classmethod
    def _at(cls, v):
        import re
        stripped = re.sub(r"\{[a-z_]+\}", "", v).replace("[[", "").replace("]]", "")
        if not re.match(r"^[A-Za-z0-9 _=,.:/%@~+'|-]*!?[A-Za-z0-9 _=,.:/%@~+'|!-]*$", stripped) or "!!" in stripped:
            raise ValueError("argument template contains characters that are not allowed")
        if stripped.count("'") % 2:
            raise ValueError("unbalanced single quotes")
        return v


def service_def_payload(s: Service, usage: int | None = None) -> dict:
    d = {"id": s.id, "code": s.code, "name": s.name, "category": s.category, "monitoring_method": s.monitoring_method,
         "os_types": s.os_types, "command_id": s.command_id, "command_name": s.command.name if s.command else None,
         "arg_template": s.arg_template, "params_schema": s.params_schema, "default_description": s.default_description,
         "default_warning": s.default_warning, "default_critical": s.default_critical,
         "default_check_interval": s.default_check_interval, "default_retry_interval": s.default_retry_interval,
         "default_notification_interval": s.default_notification_interval, "unit": s.unit,
         "description": s.description, "is_system": s.is_system}
    if usage is not None:
        d["usage"] = usage
    return d


@router.get("/api/services")
def list_service_defs(principal: Principal = Depends(require("templates.view")), db: Session = Depends(get_db)):
    usage = dict(db.execute(select(ServerService.service_id, func.count()).group_by(ServerService.service_id)).all())
    return ok([service_def_payload(s, usage.get(s.id, 0)) for s in db.scalars(select(Service).order_by(Service.category, Service.name))],
              {"param_types": PARAM_TYPES})


_SAMPLES = {"drive": "C", "mount": "/", "winservice": "Svc", "process": "proc", "interface": "eth0",
            "metric": "cpu/percent", "query": "a=b", "logname": "System", "severity": "ERROR", "window": "1h",
            "state": "running", "mismatch": "critical", "direction": "recv", "int": "1", "oid": "1.3.6.1",
            "units": "M", "args": "x", "plugin": "check_x", "text": "x"}


def _check_def(db: Session, body: ServiceDefIn) -> None:
    if db.get(Command, body.command_id) is None:
        raise ApiError(422, "validation_error", "Unknown command", [{"field": "command_id", "message": "not found"}])
    from ...nagios.generator import GenerationError, build_check_values, render_args
    schema = [p.model_dump() for p in body.params_schema]
    sample = {}
    for p in body.params_schema:
        if p.default and V.PARAM_PATTERNS[p.type].match(p.default):
            sample[p.name] = p.default
        else:
            sample[p.name] = _SAMPLES.get(p.type, "x")
    try:
        values = build_check_values(body.default_warning or "1", body.default_critical or "2", schema, sample)
        render_args(body.arg_template, values)
    except (V.ValidationError, GenerationError) as exc:
        raise ApiError(422, "validation_error", "Argument template does not render",
                       [{"field": "arg_template", "message": str(exc)}])


@router.post("/api/services", status_code=201)
def create_service_def(body: ServiceDefIn, request: Request, principal: Principal = Depends(require("catalog.manage")),
                       db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    _check_def(db, body)
    data = body.model_dump()
    data["params_schema"] = [p for p in data["params_schema"]]
    s = Service(**data, is_system=False, created_by=ctx.user_id)
    db.add(s)
    db.flush()
    audit(db, ctx, "service_def.create", entity_type="service_def", entity_id=s.id, entity_name=s.code, new=data)
    db.commit()
    return ok(service_def_payload(s))


@router.put("/api/services/{sid}")
def update_service_def(sid: int, body: ServiceDefIn, request: Request,
                       principal: Principal = Depends(require("catalog.manage")), db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Service, sid, "service definition")
    _check_def(db, body)
    old = service_def_payload(s)
    data = body.model_dump()
    if s.is_system:
        # built-in definitions: only defaults and argument template may be tuned
        for k in ("arg_template", "default_warning", "default_critical", "default_check_interval",
                  "default_retry_interval", "default_notification_interval", "description"):
            setattr(s, k, data[k])
    else:
        for k, v in data.items():
            setattr(s, k, v)
    s.updated_by = ctx.user_id
    db.flush()
    n_used = db.scalar(select(func.count()).select_from(ServerService).where(ServerService.service_id == s.id)) or 0
    if n_used:
        record_change(db, ctx, "service_def", s.id, s.code, "update", old=old, new=service_def_payload(s))
        db.execute(Server.__table__.update().where(Server.id.in_(
            select(ServerService.server_id).where(ServerService.service_id == s.id)), Server.config_state == "applied")
            .values(config_state="pending"))
    audit(db, ctx, "service_def.update", entity_type="service_def", entity_id=s.id, entity_name=s.code, old=old,
          new=service_def_payload(s))
    db.commit()
    return ok(service_def_payload(s))


@router.delete("/api/services/{sid}")
def delete_service_def(sid: int, request: Request, principal: Principal = Depends(require("catalog.manage")),
                       db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    s = get_or_404(db, Service, sid, "service definition")
    if s.is_system:
        raise ApiError(409, "read_only", "Built-in service definitions cannot be deleted")
    used = db.scalar(select(func.count()).select_from(ServerService).where(ServerService.service_id == s.id)) or 0
    used += db.scalar(select(func.count()).select_from(TemplateService).where(TemplateService.service_id == s.id)) or 0
    if used:
        raise ApiError(409, "in_use", "Service definition is used by servers or templates")
    audit(db, ctx, "service_def.delete", entity_type="service_def", entity_id=s.id, entity_name=s.code,
          old=service_def_payload(s))
    db.delete(s)
    db.commit()
    return ok({"deleted": True})


# ============================================================== templates ==
class TemplateItemIn(BaseModel):
    service_id: int
    service_description: str
    params: dict = Field(default_factory=dict)
    warning: Optional[str] = None
    critical: Optional[str] = None
    check_interval: Optional[int] = Field(None, ge=1, le=1440)
    retry_interval: Optional[int] = Field(None, ge=1, le=1440)
    notification_interval: Optional[int] = Field(None, ge=0, le=10080)
    notifications_enabled: bool = True

    @field_validator("service_description")
    @classmethod
    def _d(cls, v):
        return V.check_service_description(v)

    @field_validator("warning", "critical")
    @classmethod
    def _t(cls, v, info):
        return V.check_threshold(v, info.field_name)


class TemplateIn(BaseModel):
    name: str
    description: Optional[str] = None
    os_type: Literal["windows", "linux", "unix", "network", "other"]
    monitoring_method: Literal["ncpa", "snmp", "nrpe", "ping", "custom"]
    items: list[TemplateItemIn] = Field(default_factory=list, max_length=100)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_free_text(v, "name", 100, required=True)

    @field_validator("description")
    @classmethod
    def _d(cls, v):
        return V.check_free_text(v, "description", 255)


def template_payload(t: MonitoringTemplate, usage: int | None = None) -> dict:
    d = {"id": t.id, "name": t.name, "description": t.description, "os_type": t.os_type,
         "monitoring_method": t.monitoring_method, "is_system": t.is_system, "updated_at": iso(t.updated_at),
         "items": [{"id": i.id, "service_id": i.service_id, "service_code": i.service.code,
                    "service_name": i.service.name, "service_description": i.service_description, "params": i.params,
                    "warning": i.warning, "critical": i.critical, "check_interval": i.check_interval,
                    "retry_interval": i.retry_interval, "notification_interval": i.notification_interval,
                    "notifications_enabled": i.notifications_enabled} for i in t.items]}
    if usage is not None:
        d["usage"] = usage
    return d


def _set_items(db: Session, t: MonitoringTemplate, items: list[TemplateItemIn]) -> None:
    cat = {s.id: s for s in db.scalars(select(Service))}
    seen = set()
    t.items.clear()
    db.flush()
    for i, it in enumerate(items):
        svc = cat.get(it.service_id)
        if svc is None:
            raise ApiError(422, "validation_error", "Unknown service definition", [{"field": f"items.{i}.service_id", "message": "not found"}])
        if it.service_description in seen:
            raise ApiError(422, "validation_error", "Duplicate service description", [{"field": f"items.{i}.service_description", "message": it.service_description}])
        seen.add(it.service_description)
        t.items.append(TemplateService(service_id=svc.id, service_description=it.service_description,
                                       params=V.validate_params(svc.params_schema, it.params), warning=it.warning,
                                       critical=it.critical, check_interval=it.check_interval,
                                       retry_interval=it.retry_interval, notification_interval=it.notification_interval,
                                       notifications_enabled=it.notifications_enabled, sort_order=i))


@router.get("/api/templates")
def list_templates(principal: Principal = Depends(require("templates.view")), db: Session = Depends(get_db)):
    usage = dict(db.execute(select(Server.template_id, func.count()).where(Server.deleted_token == 0)
                            .group_by(Server.template_id)).all())
    return ok([template_payload(t, usage.get(t.id, 0)) for t in db.scalars(select(MonitoringTemplate).order_by(MonitoringTemplate.name))])


@router.get("/api/templates/{tid}")
def get_template(tid: int, principal: Principal = Depends(require("templates.view")), db: Session = Depends(get_db)):
    return ok(template_payload(get_or_404(db, MonitoringTemplate, tid, "template")))


@router.post("/api/templates", status_code=201)
def create_template(body: TemplateIn, request: Request, principal: Principal = Depends(require("templates.manage")),
                    db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    t = MonitoringTemplate(name=body.name, description=body.description, os_type=body.os_type,
                           monitoring_method=body.monitoring_method, created_by=ctx.user_id)
    db.add(t)
    db.flush()
    _set_items(db, t, body.items)
    db.flush()
    audit(db, ctx, "template.create", entity_type="template", entity_id=t.id, entity_name=t.name, new=template_payload(t))
    db.commit()
    db.refresh(t)
    return ok(template_payload(t))


@router.put("/api/templates/{tid}")
def update_template(tid: int, body: TemplateIn, request: Request, principal: Principal = Depends(require("templates.manage")),
                    db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    t = get_or_404(db, MonitoringTemplate, tid, "template")
    old = template_payload(t)
    t.name, t.description, t.os_type, t.monitoring_method = body.name, body.description, body.os_type, body.monitoring_method
    t.updated_by = ctx.user_id
    _set_items(db, t, body.items)
    db.flush()
    audit(db, ctx, "template.update", entity_type="template", entity_id=t.id, entity_name=t.name, old=old,
          new=template_payload(t))
    db.commit()
    db.refresh(t)
    return ok(template_payload(t))


@router.delete("/api/templates/{tid}")
def delete_template(tid: int, request: Request, principal: Principal = Depends(require("templates.manage")),
                    db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    t = get_or_404(db, MonitoringTemplate, tid, "template")
    audit(db, ctx, "template.delete", entity_type="template", entity_id=t.id, entity_name=t.name, old=template_payload(t))
    db.delete(t)
    db.commit()
    return ok({"deleted": True})


# ============================================================ host groups ==
class GroupIn(BaseModel):
    name: str
    alias: str
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_object_name(v)

    @field_validator("alias")
    @classmethod
    def _a(cls, v):
        return V.check_free_text(v, "alias", 120, required=True)

    @field_validator("description")
    @classmethod
    def _d(cls, v):
        return V.check_free_text(v, "description", 255)


def group_payload(g: ServerGroup, members: int = 0) -> dict:
    return {"id": g.id, "name": g.name, "alias": g.alias, "description": g.description, "is_managed": g.is_managed,
            "members": members}


@router.get("/api/hostgroups")
def list_groups(principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    from ...models import ServerGroupMember
    counts = dict(db.execute(select(ServerGroupMember.group_id, func.count()).join(Server, Server.id == ServerGroupMember.server_id)
                             .where(Server.deleted_token == 0).group_by(ServerGroupMember.group_id)).all())
    return ok([group_payload(g, counts.get(g.id, 0)) for g in db.scalars(select(ServerGroup).order_by(ServerGroup.name))])


@router.post("/api/hostgroups", status_code=201)
def create_group(body: GroupIn, request: Request, principal: Principal = Depends(require("groups.manage")),
                 db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    if body.name in load_legacy().names("hostgroup", "hostgroup_name"):
        raise ApiError(409, "conflict", "This host group exists in manual configuration; it is available as an external group")
    g = ServerGroup(name=body.name, alias=body.alias, description=body.description, created_by=ctx.user_id)
    db.add(g)
    db.flush()
    record_change(db, ctx, "hostgroup", g.id, g.name, "create", new=group_payload(g))
    audit(db, ctx, "hostgroup.create", entity_type="hostgroup", entity_id=g.id, entity_name=g.name, new=group_payload(g))
    db.commit()
    return ok(group_payload(g))


@router.put("/api/hostgroups/{gid}")
def update_group(gid: int, body: GroupIn, request: Request, principal: Principal = Depends(require("groups.manage")),
                 db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    g = get_or_404(db, ServerGroup, gid, "host group")
    if not g.is_managed:
        raise ApiError(409, "read_only", "External host groups are managed in manual configuration")
    if body.name != g.name:
        raise ApiError(422, "validation_error", "Host group names cannot be changed", [{"field": "name", "message": "immutable"}])
    old = group_payload(g)
    g.alias, g.description, g.updated_by = body.alias, body.description, ctx.user_id
    record_change(db, ctx, "hostgroup", g.id, g.name, "update", old=old, new=group_payload(g))
    audit(db, ctx, "hostgroup.update", entity_type="hostgroup", entity_id=g.id, entity_name=g.name, old=old, new=group_payload(g))
    db.commit()
    return ok(group_payload(g))


@router.delete("/api/hostgroups/{gid}")
def delete_group(gid: int, request: Request, principal: Principal = Depends(require("groups.manage")),
                 db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    g = get_or_404(db, ServerGroup, gid, "host group")
    used = [s.hostname for s in db.scalars(select(Server).where(Server.deleted_token == 0)) if g in s.groups]
    if used:
        raise ApiError(409, "in_use", f"Host group is used by {len(used)} server(s): {', '.join(used[:5])}")
    if g.is_managed:
        record_change(db, ctx, "hostgroup", g.id, g.name, "delete", old=group_payload(g))
    audit(db, ctx, "hostgroup.delete", entity_type="hostgroup", entity_id=g.id, entity_name=g.name, old=group_payload(g))
    db.delete(g)
    db.commit()
    return ok({"deleted": True})


# ================================================= contacts / contact groups ==
class ContactIn(BaseModel):
    name: str
    alias: str
    email: Optional[str] = None
    phone: Optional[str] = Field(None, pattern=r"^\+?[0-9 ()-]{5,20}$")
    host_notification_options: str = "d,u,r"
    service_notification_options: str = "w,u,c,r"
    notification_period: str = "24x7"
    is_enabled: bool = True

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_object_name(v)

    @field_validator("alias")
    @classmethod
    def _a(cls, v):
        return V.check_free_text(v, "alias", 120, required=True)

    @field_validator("email")
    @classmethod
    def _e(cls, v):
        return V.check_email(v)

    @field_validator("host_notification_options")
    @classmethod
    def _h(cls, v):
        if not V.NOTIF_OPTS_HOST_RE.match(v):
            raise ValueError("use letters d,u,r,f,s or n separated by commas")
        return v

    @field_validator("service_notification_options")
    @classmethod
    def _s(cls, v):
        if not V.NOTIF_OPTS_SVC_RE.match(v):
            raise ValueError("use letters w,u,c,r,f,s or n separated by commas")
        return v

    @field_validator("notification_period")
    @classmethod
    def _p(cls, v):
        return V.check_timeperiod(v, "notification_period")


def contact_payload(c: Contact) -> dict:
    return {"id": c.id, "name": c.name, "alias": c.alias, "email": c.email, "phone": c.phone,
            "host_notification_options": c.host_notification_options,
            "service_notification_options": c.service_notification_options,
            "notification_period": c.notification_period, "is_enabled": c.is_enabled, "is_managed": c.is_managed}


@router.get("/api/contacts")
def list_contacts(principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    return ok([contact_payload(c) for c in db.scalars(select(Contact).order_by(Contact.name))])


def _contact_write(db, request, principal, body: ContactIn, c: Contact | None):
    ctx = ctx_from(request, principal)
    creating = c is None
    if creating:
        if body.name in load_legacy().names("contact", "contact_name"):
            raise ApiError(409, "conflict", "This contact exists in manual configuration")
        c = Contact(name=body.name, created_by=ctx.user_id)
        db.add(c)
        old = None
    else:
        if not c.is_managed:
            raise ApiError(409, "read_only", "External contacts are managed in manual configuration")
        old = contact_payload(c)
    for k, v in body.model_dump().items():
        if k != "name":
            setattr(c, k, v)
    c.updated_by = ctx.user_id
    db.flush()
    record_change(db, ctx, "contact", c.id, c.name, "create" if creating else "update", old=old, new=contact_payload(c))
    audit(db, ctx, "contact.create" if creating else "contact.update", entity_type="contact", entity_id=c.id,
          entity_name=c.name, old=old, new=contact_payload(c))
    db.commit()
    return ok(contact_payload(c))


@router.post("/api/contacts", status_code=201)
def create_contact(body: ContactIn, request: Request, principal: Principal = Depends(require("contacts.manage")),
                   db: Session = Depends(get_db)):
    return _contact_write(db, request, principal, body, None)


@router.put("/api/contacts/{cid}")
def update_contact(cid: int, body: ContactIn, request: Request, principal: Principal = Depends(require("contacts.manage")),
                   db: Session = Depends(get_db)):
    return _contact_write(db, request, principal, body, get_or_404(db, Contact, cid, "contact"))


@router.delete("/api/contacts/{cid}")
def delete_contact(cid: int, request: Request, principal: Principal = Depends(require("contacts.manage")),
                   db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    c = get_or_404(db, Contact, cid, "contact")
    if c.is_managed:
        record_change(db, ctx, "contact", c.id, c.name, "delete", old=contact_payload(c))
    audit(db, ctx, "contact.delete", entity_type="contact", entity_id=c.id, entity_name=c.name, old=contact_payload(c))
    db.delete(c)
    db.commit()
    return ok({"deleted": True})


class ContactGroupIn(BaseModel):
    name: str
    alias: str
    member_ids: list[int] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return V.check_object_name(v)

    @field_validator("alias")
    @classmethod
    def _a(cls, v):
        return V.check_free_text(v, "alias", 120, required=True)


def cgroup_payload(g: ContactGroup) -> dict:
    return {"id": g.id, "name": g.name, "alias": g.alias, "is_managed": g.is_managed,
            "members": [{"id": m.id, "name": m.name} for m in g.members]}


@router.get("/api/contact-groups")
def list_cgroups(principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    return ok([cgroup_payload(g) for g in db.scalars(select(ContactGroup).order_by(ContactGroup.name))])


def _cgroup_write(db, request, principal, body: ContactGroupIn, g: ContactGroup | None):
    ctx = ctx_from(request, principal)
    creating = g is None
    if creating:
        if body.name in load_legacy().names("contactgroup", "contactgroup_name"):
            raise ApiError(409, "conflict", "This contact group exists in manual configuration")
        g = ContactGroup(name=body.name, created_by=ctx.user_id)
        db.add(g)
        old = None
    else:
        if not g.is_managed:
            raise ApiError(409, "read_only", "External contact groups are managed in manual configuration")
        old = cgroup_payload(g)
    g.alias = body.alias
    members = list(db.scalars(select(Contact).where(Contact.id.in_(body.member_ids)))) if body.member_ids else []
    if len(members) != len(set(body.member_ids)):
        raise ApiError(422, "validation_error", "Unknown contact", [{"field": "member_ids", "message": "unknown id"}])
    g.members = members
    g.updated_by = ctx.user_id
    db.flush()
    record_change(db, ctx, "contactgroup", g.id, g.name, "create" if creating else "update", old=old, new=cgroup_payload(g))
    audit(db, ctx, "contactgroup.create" if creating else "contactgroup.update", entity_type="contactgroup",
          entity_id=g.id, entity_name=g.name, old=old, new=cgroup_payload(g))
    db.commit()
    return ok(cgroup_payload(g))


@router.post("/api/contact-groups", status_code=201)
def create_cgroup(body: ContactGroupIn, request: Request, principal: Principal = Depends(require("contacts.manage")),
                  db: Session = Depends(get_db)):
    return _cgroup_write(db, request, principal, body, None)


@router.put("/api/contact-groups/{gid}")
def update_cgroup(gid: int, body: ContactGroupIn, request: Request,
                  principal: Principal = Depends(require("contacts.manage")), db: Session = Depends(get_db)):
    return _cgroup_write(db, request, principal, body, get_or_404(db, ContactGroup, gid, "contact group"))


@router.delete("/api/contact-groups/{gid}")
def delete_cgroup(gid: int, request: Request, principal: Principal = Depends(require("contacts.manage")),
                  db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    g = get_or_404(db, ContactGroup, gid, "contact group")
    used = [s.hostname for s in db.scalars(select(Server).where(Server.deleted_token == 0)) if g in s.contact_groups]
    if used:
        raise ApiError(409, "in_use", f"Contact group is used by {len(used)} server(s)")
    if g.is_managed:
        record_change(db, ctx, "contactgroup", g.id, g.name, "delete", old=cgroup_payload(g))
    audit(db, ctx, "contactgroup.delete", entity_type="contactgroup", entity_id=g.id, entity_name=g.name,
          old=cgroup_payload(g))
    db.delete(g)
    db.commit()
    return ok({"deleted": True})


@router.get("/api/timeperiods")
def timeperiods(principal: Principal = Depends(require("servers.view"))):
    return ok(sorted(load_legacy().names("timeperiod", "timeperiod_name")))
