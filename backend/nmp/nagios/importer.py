"""Import existing (manually configured) Nagios hosts and services.

Modes
  takeover  - hosts become portal-managed; their original blocks are commented
              out of the manual file IN THE SAME validated change (one version,
              backed up, rollback-able). NCPA tokens found inline are encrypted.
  readonly  - hosts are recorded in the inventory as 'external' (not generated);
              they keep being managed in the original files.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import validators as V
from ..audit import AuditContext, audit, record_change
from ..models import ContactGroup, Server, ServerCredential, ServerGroup, ServerService, Service, ServiceThreshold
from ..security import crypto
from .legacy import LegacyConfig, NagiosObject, comment_out_blocks, load_legacy


@dataclass
class ServicePlan:
    description: str
    check_command: str
    catalog_code: str | None = None
    params: dict = field(default_factory=dict)
    warning: str | None = None
    critical: str | None = None
    check_interval: int | None = None
    retry_interval: int | None = None
    max_check_attempts: int | None = None
    notification_interval: int | None = None
    notifications_enabled: bool = True
    problem: str | None = None
    obj: NagiosObject | None = None

    def as_dict(self) -> dict:
        return {"description": self.description, "catalog_code": self.catalog_code, "params": self.params,
                "warning": self.warning, "critical": self.critical, "problem": self.problem,
                "file": self.obj.file if self.obj else None, "line": self.obj.start_line if self.obj else None}


@dataclass
class HostPlan:
    hostname: str
    address: str
    alias: str
    obj: NagiosObject
    method: str = "ping"
    host_check: str = "ping"
    os_guess: str = "other"
    ncpa_port: int = 5693
    ncpa_token: str | None = None
    hostgroups: list[str] = field(default_factory=list)
    contact_groups: list[str] = field(default_factory=list)
    services: list[ServicePlan] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname, "address": self.address, "alias": self.alias, "file": self.obj.file,
            "line": self.obj.start_line, "method": self.method, "host_check": self.host_check,
            "os_guess": self.os_guess, "ncpa_port": self.ncpa_port, "token_found": bool(self.ncpa_token),
            "hostgroups": self.hostgroups, "contact_groups": self.contact_groups,
            "services": [s.as_dict() for s in self.services], "blockers": self.blockers,
            "can_take_over": not self.blockers,
        }


def _expand_command(legacy: LegacyConfig, check_command: str) -> tuple[str, list[str]] | None:
    """Return (plugin_basename, argv) for a check_command using the legacy command definition."""
    parts = check_command.split("!")
    name, args = parts[0], parts[1:]
    cmd = next((o for o in legacy.objects if o.type == "command" and o.attrs.get("command_name") == name), None)
    if not cmd:
        return None
    line = cmd.attrs.get("command_line", "")
    for i, a in enumerate(args, start=1):
        line = line.replace(f"$ARG{i}$", a)
    line = re.sub(r"\$ARG\d+\$", "", line)
    try:
        argv = shlex.split(line)
    except ValueError:
        return None
    if not argv:
        return None
    return argv[0].rsplit("/", 1)[-1], argv[1:]


def _ncpa_opts(argv: list[str]) -> dict:
    opts: dict = {}
    flags = {"-t": "token", "--token": "token", "-P": "port", "--port": "port", "-M": "metric", "--metric": "metric",
             "-w": "warning", "--warning": "warning", "-c": "critical", "--critical": "critical",
             "-q": "query", "--queryargs": "query", "-u": "units", "--units": "units", "-a": "args",
             "--arguments": "args", "-T": "timeout", "--timeout": "timeout", "-H": "host", "--hostname": "host"}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in flags and i + 1 < len(argv):
            opts[flags[a]] = argv[i + 1]
            i += 2
            continue
        if "=" in a and a.split("=", 1)[0] in flags:
            k, v = a.split("=", 1)
            opts[flags[k]] = v
        elif a in ("-d", "--delta"):
            opts["delta"] = True
        elif a in ("-s", "--secure"):
            opts["secure"] = True
        i += 1
    return opts


def _map_ncpa_metric(opts: dict, os_guess: str) -> tuple[str | None, dict, str | None]:
    metric = opts.get("metric", "").strip("'\"")
    query = (opts.get("query") or "").strip("'\"")
    q = dict(kv.split("=", 1) for kv in query.split(",") if "=" in kv) if query else {}
    if metric == "cpu/percent":
        return "ncpa_cpu", {}, None
    if metric == "memory/virtual/percent":
        return "ncpa_memory", {}, None
    if metric == "memory/swap/percent":
        return ("ncpa_pagefile" if os_guess == "windows" else "ncpa_swap"), {}, None
    m = re.match(r"^disk/logical/([A-Za-z]):\|/used_percent$", metric)
    if m:
        return "ncpa_disk_windows", {"drive": m.group(1).upper()}, None
    m = re.match(r"^disk/logical/(\|[^/]*)/used_percent$", metric)
    if m:
        return "ncpa_disk_linux", {"mount": m.group(1).replace("|", "/") or "/"}, None
    if metric == "processes":
        if "name" in q:
            return "ncpa_process_named", {"process": q["name"]}, None
        return "ncpa_processes", {}, None
    if metric == "services" and "service" in q:
        return "ncpa_windows_service", {"service": q["service"], "state": q.get("status", "running"),
                                        "mismatch": "critical"}, None
    if metric == "system/uptime":
        return "ncpa_uptime", {}, None
    if metric == "user/count":
        return "ncpa_users", {}, None
    m = re.match(r"^interface/([^/]+)/bytes_(recv|sent)$", metric)
    if m:
        return "ncpa_network", {"interface": m.group(1), "direction": m.group(2)}, None
    if metric:
        params = {"metric": metric}
        if query:
            params["query"] = query
        if opts.get("units"):
            params["units"] = opts["units"]
        return "ncpa_custom", params, None
    return None, {}, "no NCPA metric (-M) found"


def _int(v, default=None):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def plan_imports(db: Session, legacy: LegacyConfig | None = None) -> list[HostPlan]:
    legacy = legacy or load_legacy()
    existing = {h for (h,) in db.execute(select(Server.hostname).where(Server.deleted_token == 0))}
    catalog = {s.code: s for s in db.scalars(select(Service))}
    plans: list[HostPlan] = []
    for h in legacy.hosts():
        hn = h.attrs["host_name"]
        if hn in existing or hn == "localhost":
            continue
        a = h.attrs
        plan = HostPlan(hostname=hn, address=a.get("address", ""), alias=a.get("alias", hn), obj=h, attrs=a)
        plan.hostgroups = [x.strip() for x in a.get("hostgroups", "").split(",") if x.strip()]
        plan.contact_groups = [x.strip() for x in a.get("contact_groups", "").split(",") if x.strip()]
        try:
            V.check_hostname(hn)
        except V.ValidationError:
            plan.blockers.append("host name contains characters the portal does not allow")
        try:
            V.check_address(plan.address)
        except V.ValidationError:
            plan.blockers.append("address is not a valid IP address or DNS name")
        svcs = legacy.services_for(hn)
        text_blob = " ".join([hn, plan.alias] + [s.attrs.get("check_command", "") for s in svcs]).lower()
        if re.search(r"disk/logical/[a-z]:", text_blob) or "win" in text_blob:
            plan.os_guess = "windows"
        elif "disk/logical/|" in text_blob or "linux" in text_blob:
            plan.os_guess = "linux"
        hc = a.get("check_command", "")
        exp = _expand_command(legacy, hc) if hc else None
        if exp and exp[0].startswith("check_ncpa"):
            o = _ncpa_opts(exp[1])
            plan.method, plan.host_check = "ncpa", "agent"
            plan.ncpa_token = o.get("token")
            plan.ncpa_port = _int(o.get("port"), 5693)
        for sv in svcs:
            sa = sv.attrs
            sp = ServicePlan(description=sa.get("service_description", ""), check_command=sa.get("check_command", ""),
                             obj=sv, check_interval=_int(sa.get("check_interval")),
                             retry_interval=_int(sa.get("retry_interval")),
                             max_check_attempts=_int(sa.get("max_check_attempts")),
                             notification_interval=_int(sa.get("notification_interval")),
                             notifications_enabled=sa.get("notifications_enabled", "1").strip() != "0")
            if "," in sa.get("host_name", "") or "hostgroup_name" in sa:
                sp.problem = "service is shared with other hosts/host groups"
            else:
                exp = _expand_command(legacy, sp.check_command)
                if not exp:
                    sp.problem = "check command not found"
                elif exp[0].startswith("check_ncpa"):
                    o = _ncpa_opts(exp[1])
                    if o.get("token"):
                        plan.method = "ncpa"
                        plan.ncpa_token = plan.ncpa_token or o["token"]
                        plan.ncpa_port = _int(o.get("port"), plan.ncpa_port)
                    code, params, problem = _map_ncpa_metric(o, plan.os_guess)
                    sp.catalog_code, sp.params, sp.problem = code, params, problem
                    sp.warning, sp.critical = o.get("warning"), o.get("critical")
                elif exp[0] == "check_ping":
                    sp.catalog_code = "ping"
                    o = dict(zip(exp[1][::2], exp[1][1::2]))
                    sp.warning, sp.critical = o.get("-w"), o.get("-c")
                else:
                    sp.problem = f"plugin '{exp[0]}' has no portal service definition"
            if sp.catalog_code and not sp.problem:
                cat = catalog.get(sp.catalog_code)
                try:
                    if cat is None:
                        raise V.ValidationError("catalog", "service definition missing")
                    V.validate_params(cat.params_schema, sp.params)
                    V.check_threshold(sp.warning, "warning")
                    V.check_threshold(sp.critical, "critical")
                    V.check_service_description(sp.description)
                except V.ValidationError as exc:
                    sp.problem = exc.message
            if sp.problem:
                plan.blockers.append(f"service '{sp.description}': {sp.problem}")
            plan.services.append(sp)
        if plan.method == "ncpa" and not plan.ncpa_token:
            plan.blockers.append("NCPA token could not be found in the existing definition")
        plans.append(plan)
    return plans


def import_hosts(db: Session, ctx: AuditContext, selections: list[dict], mode: str) -> tuple[list[Server], list[dict]]:
    """Create inventory rows. Returns (servers, overrides) - overrides only for takeover."""
    legacy = load_legacy()
    plans = {p.hostname: p for p in plan_imports(db, legacy)}
    catalog = {s.code: s for s in db.scalars(select(Service))}
    groups = {g.name: g for g in db.scalars(select(ServerGroup))}
    cgroups = {g.name: g for g in db.scalars(select(ContactGroup))}
    servers: list[Server] = []
    ranges_by_file: dict[str, list[tuple[int, int]]] = {}
    for sel in selections:
        plan = plans.get(sel["hostname"])
        if plan is None:
            raise ValueError(f"host '{sel['hostname']}' is not importable")
        if mode == "takeover" and plan.blockers:
            raise ValueError(f"host '{plan.hostname}' cannot be taken over: " + "; ".join(plan.blockers))
        a = plan.attrs
        srv = Server(
            hostname=plan.hostname, display_name=V.check_free_text(plan.alias, "alias") or plan.hostname,
            address=plan.address, environment=sel.get("environment", "production"),
            os_type=sel.get("os_type") or plan.os_guess, monitoring_method=plan.method, host_check=plan.host_check,
            location=V.check_free_text(sel.get("location"), "location"),
            check_interval=_int(a.get("check_interval"), 5), retry_interval=_int(a.get("retry_interval"), 1),
            max_check_attempts=_int(a.get("max_check_attempts"), 5),
            notification_interval=_int(a.get("notification_interval"), 60),
            notifications_enabled=a.get("notifications_enabled", "1").strip() != "0",
            check_period=a.get("check_period", "24x7"), notification_period=a.get("notification_period", "24x7"),
            managed_by="portal" if mode == "takeover" else "external",
            config_state="pending" if mode == "takeover" else "applied",
            imported_from=f"{plan.obj.file}:{plan.obj.start_line}", created_by=ctx.user_id, updated_by=ctx.user_id,
        )
        for gname in plan.hostgroups:
            g = groups.get(gname)
            if g is None:
                g = ServerGroup(name=gname, alias=gname, is_managed=False, created_by=ctx.user_id)
                db.add(g)
                groups[gname] = g
            srv.groups.append(g)
        for cname in plan.contact_groups:
            if cname in cgroups:
                srv.contact_groups.append(cgroups[cname])
        db.add(srv)
        db.flush()
        if plan.method == "ncpa" and plan.ncpa_token and mode == "takeover":
            db.add(ServerCredential(server_id=srv.id, credential_type="ncpa", port=plan.ncpa_port, ssl_enabled=True,
                                    verify_ssl=False, timeout=30,
                                    secret_ciphertext=crypto.encrypt_json({"token": plan.ncpa_token}, "cred:ncpa"),
                                    created_by=ctx.user_id))
        if mode == "takeover":
            for sp in plan.services:
                cat = catalog[sp.catalog_code]
                ss = ServerService(server_id=srv.id, service_id=cat.id, service_description=sp.description,
                                   params=V.validate_params(cat.params_schema, sp.params), created_by=ctx.user_id)
                ss.threshold = ServiceThreshold(
                    warning=V.check_threshold(sp.warning, "warning"), critical=V.check_threshold(sp.critical, "critical"),
                    check_interval=sp.check_interval or cat.default_check_interval,
                    retry_interval=sp.retry_interval or cat.default_retry_interval,
                    max_check_attempts=sp.max_check_attempts or 3,
                    notification_interval=sp.notification_interval or cat.default_notification_interval,
                    notifications_enabled=sp.notifications_enabled)
                db.add(ss)
                ranges_by_file.setdefault(sp.obj.file, []).append((sp.obj.start_line, sp.obj.end_line))
            ranges_by_file.setdefault(plan.obj.file, []).append((plan.obj.start_line, plan.obj.end_line))
        record_change(db, ctx, "server", srv.id, srv.hostname, f"import_{mode}",
                      new={"hostname": srv.hostname, "address": srv.address, "from": srv.imported_from,
                           "services": len(plan.services)})
        audit(db, ctx, f"server.import_{mode}", entity_type="server", entity_id=srv.id, entity_name=srv.hostname,
              new={"from": srv.imported_from, "services": [s.description for s in plan.services]})
        servers.append(srv)
    overrides = []
    for path, ranges in ranges_by_file.items():
        overrides.append({
            "target": path,
            "content": comment_out_blocks(path, ranges, "NMP-MIGRATED"),
            "sha256_before": legacy.files[path],
        })
    db.flush()
    return servers, overrides
