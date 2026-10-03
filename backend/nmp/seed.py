"""Idempotent seeding of reference data (roles, permissions, catalog, templates, settings)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (Command, Contact, ContactGroup, MonitoringTemplate, Permission, Role, Service, ServerGroup,
                     SystemSetting, TemplateService)
from .nagios import catalog
from .nagios.legacy import load_legacy
from .security.rbac import DEFAULT_ROLES, PERMISSIONS, SUPER_ADMIN_ONLY


def seed_rbac(db: Session) -> None:
    perms = {p.code: p for p in db.scalars(select(Permission))}
    for code, (cat, desc) in PERMISSIONS.items():
        if code not in perms:
            p = Permission(code=code, category=cat, description=desc)
            db.add(p)
            perms[code] = p
        else:
            perms[code].category, perms[code].description = cat, desc
    db.flush()
    for name, spec in DEFAULT_ROLES.items():
        role = db.scalar(select(Role).where(Role.name == name))
        if role is None:
            role = Role(name=name, display_name=spec["display_name"], description=spec["description"], is_system=True)
            db.add(role)
            role.permissions = [perms[c] for c in spec["permissions"]]
        elif name == "super_admin":
            role.permissions = [perms[c] for c in spec["permissions"]]  # super admin always has everything
    db.flush()
    # invariant: Super-Admin-only permissions never stay on any other role (built-in or custom)
    for role in db.scalars(select(Role).where(Role.name != "super_admin")):
        keep = [p for p in role.permissions if p.code not in SUPER_ADMIN_ONLY]
        if len(keep) != len(role.permissions):
            role.permissions = keep
    db.flush()


def seed_catalog(db: Session) -> None:
    cmds = {c.name: c for c in db.scalars(select(Command))}
    for spec in catalog.SYSTEM_COMMANDS:
        c = cmds.get(spec["name"])
        if c is None:
            c = Command(name=spec["name"], command_line=spec["command_line"], description=spec["description"],
                        is_system=True)
            db.add(c)
            cmds[c.name] = c
        elif c.is_system:
            c.command_line, c.description = spec["command_line"], spec["description"]
    db.flush()
    svcs = {s.code: s for s in db.scalars(select(Service))}
    for spec in catalog.SERVICES:
        spec = dict(spec)
        cmd = cmds[spec.pop("command")]
        s = svcs.get(spec["code"])
        fields = dict(spec, command_id=cmd.id, is_system=True)
        if s is None:
            s = Service(**fields)
            db.add(s)
            svcs[s.code] = s
        elif s.is_system:
            for k, v in fields.items():
                setattr(s, k, v)
    db.flush()
    for t in catalog.TEMPLATES:
        if db.scalar(select(MonitoringTemplate).where(MonitoringTemplate.name == t["name"])):
            continue
        tpl = MonitoringTemplate(name=t["name"], description=t["description"], os_type=t["os_type"],
                                 monitoring_method=t["monitoring_method"], is_system=True)
        for i, (code, desc, params) in enumerate(t["items"]):
            svc = svcs[code]
            tpl.items.append(TemplateService(service_id=svc.id, service_description=desc, params=params,
                                             warning=svc.default_warning, critical=svc.default_critical,
                                             sort_order=i))
        db.add(tpl)
    db.flush()


def seed_settings(db: Session) -> None:
    for k, v in catalog.DEFAULT_SETTINGS.items():
        if db.get(SystemSetting, k) is None:
            db.add(SystemSetting(key=k, value=v))
    db.flush()


def sync_legacy_objects(db: Session) -> dict:
    """Register host groups / contact groups defined in manual config as external objects
    and create the default portal groups that do not exist yet."""
    legacy = load_legacy()
    report = {"external_hostgroups": [], "managed_hostgroups": [], "external_contactgroups": [], "errors": legacy.errors}
    lhg = legacy.names("hostgroup", "hostgroup_name")
    existing = {g.name: g for g in db.scalars(select(ServerGroup))}
    for name in sorted(lhg):
        if name not in existing:
            db.add(ServerGroup(name=name, alias=name, is_managed=False, description="Defined in manual configuration"))
            report["external_hostgroups"].append(name)
        elif existing[name].is_managed:
            existing[name].is_managed = False
            report["external_hostgroups"].append(name)
    for name, alias in catalog.DEFAULT_GROUPS:
        if name not in existing and name not in lhg:
            db.add(ServerGroup(name=name, alias=alias, is_managed=True))
            report["managed_hostgroups"].append(name)
    lcg = legacy.names("contactgroup", "contactgroup_name")
    existing_cg = {g.name: g for g in db.scalars(select(ContactGroup))}
    lcontacts = legacy.names("contact", "contact_name")
    existing_ct = {c.name: c for c in db.scalars(select(Contact))}
    for name in sorted(lcontacts):
        if name not in existing_ct:
            db.add(Contact(name=name, alias=name, is_managed=False))
    for name in sorted(lcg):
        if name not in existing_cg:
            db.add(ContactGroup(name=name, alias=name, is_managed=False))
            report["external_contactgroups"].append(name)
    db.flush()
    if not lcg and "nmp-admins" not in existing_cg:
        db.add(ContactGroup(name="nmp-admins", alias="Portal Administrators", is_managed=True))
        s = db.get(SystemSetting, "default_contact_group")
        if s:
            s.value = "nmp-admins"
    db.flush()
    return report


def seed_all(db: Session, sync_legacy: bool = True) -> dict:
    seed_rbac(db)
    seed_catalog(db)
    seed_settings(db)
    report = sync_legacy_objects(db) if sync_legacy else {}
    db.commit()
    return report
