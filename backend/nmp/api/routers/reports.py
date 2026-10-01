"""Reports: availability, service availability, SLA, performance, infrastructure health (JSON or CSV)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...db import get_db
from ...live import service_metrics
from ...models import PerfSample, Server, SystemSetting
from ...nagios import logparser
from ...nagios.status import get_status, host_state_name, service_state_name
from ..deps import Principal, require
from ..errors import ApiError
from ..util import csv_response, ok

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _window(start: Optional[datetime], end: Optional[datetime], default_days: int = 30) -> tuple[datetime, datetime]:
    end = (end or datetime.now(timezone.utc))
    end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
    start = start or end - timedelta(days=default_days)
    start = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
    if start >= end:
        raise ApiError(422, "validation_error", "'from' must be before 'to'")
    if end - start > timedelta(days=366):
        raise ApiError(422, "validation_error", "Maximum report period is 366 days")
    return start, end


def _servers(db: Session, environment: str | None, group_id: int | None) -> list[Server]:
    stmt = select(Server).where(Server.deleted_token == 0)
    if environment:
        stmt = stmt.where(Server.environment == environment)
    rows = list(db.scalars(stmt.order_by(Server.hostname)))
    if group_id:
        rows = [s for s in rows if any(g.id == group_id for g in s.groups)]
    return rows


@router.get("/availability")
def availability_report(start: Optional[datetime] = Query(None, alias="from"), end: Optional[datetime] = Query(None, alias="to"),
                        environment: Optional[str] = Query(None, max_length=20), group_id: Optional[int] = None,
                        format: str = Query("json", pattern="^(json|csv)$"),
                        principal: Principal = Depends(require("reports.view")), db: Session = Depends(get_db)):
    start, end = _window(start, end)
    servers = _servers(db, environment, group_id)
    snap = get_status()
    current = {s.hostname: host_state_name(snap.hosts.get(s.hostname)) for s in servers if s.hostname in snap.hosts}
    av = logparser.availability(start, end, hosts={s.hostname for s in servers}, current_states=current)
    rows = []
    for s in servers:
        a = av.get(s.hostname)
        secs = a.seconds if a else {}
        down = secs.get("DOWN", 0) + secs.get("UNREACHABLE", 0)
        rows.append({"server_id": s.id, "hostname": s.hostname, "display_name": s.display_name,
                     "environment": s.environment, "availability_pct": a.pct("UP") if a and a.known else None,
                     "downtime_minutes": round(down / 60, 1), "down_pct": a.pct("DOWN") if a else None,
                     "unreachable_pct": a.pct("UNREACHABLE") if a else None,
                     "undetermined_minutes": round(secs.get("UNDETERMINED", 0) / 60, 1)})
    if format == "csv":
        return csv_response("availability.csv", ["hostname", "display_name", "environment", "availability_pct",
                                                 "downtime_minutes", "undetermined_minutes"],
                            ([r["hostname"], r["display_name"], r["environment"], r["availability_pct"],
                              r["downtime_minutes"], r["undetermined_minutes"]] for r in rows))
    return ok(rows, {"from": start.isoformat(), "to": end.isoformat()})


@router.get("/service-availability")
def service_availability(start: Optional[datetime] = Query(None, alias="from"), end: Optional[datetime] = Query(None, alias="to"),
                         host: Optional[str] = Query(None, max_length=64), environment: Optional[str] = Query(None, max_length=20),
                         format: str = Query("json", pattern="^(json|csv)$"),
                         principal: Principal = Depends(require("reports.view")), db: Session = Depends(get_db)):
    start, end = _window(start, end)
    servers = _servers(db, environment, None)
    hosts = {s.hostname for s in servers}
    if host:
        hosts = {host} & hosts
    snap = get_status()
    current = {f"{h}/{d}": service_state_name(sv) for (h, d), sv in snap.services.items() if h in hosts}
    av = logparser.availability(start, end, hosts=hosts, services=True, current_states=current)
    rows = []
    for key in sorted(av):
        a = av[key]
        h, _, d = key.partition("/")
        rows.append({"host": h, "service": d, "ok_pct": a.pct("OK"), "warning_pct": a.pct("WARNING"),
                     "critical_pct": a.pct("CRITICAL"), "unknown_pct": a.pct("UNKNOWN"),
                     "undetermined_minutes": round(a.seconds.get("UNDETERMINED", 0) / 60, 1)})
    if format == "csv":
        return csv_response("service-availability.csv", ["host", "service", "ok_pct", "warning_pct", "critical_pct",
                                                         "unknown_pct", "undetermined_minutes"],
                            ([r[k] for k in ("host", "service", "ok_pct", "warning_pct", "critical_pct", "unknown_pct",
                                             "undetermined_minutes")] for r in rows))
    return ok(rows, {"from": start.isoformat(), "to": end.isoformat()})


@router.get("/sla")
def sla_report(start: Optional[datetime] = Query(None, alias="from"), end: Optional[datetime] = Query(None, alias="to"),
               environment: Optional[str] = Query(None, max_length=20), format: str = Query("json", pattern="^(json|csv)$"),
               principal: Principal = Depends(require("reports.view")), db: Session = Depends(get_db)):
    targets = (db.get(SystemSetting, "sla_targets").value if db.get(SystemSetting, "sla_targets") else {}) or {}
    rows = availability_report(start, end, environment, None, "json", principal, db)["data"]
    out = []
    for r in rows:
        target = float(targets.get(r["environment"], 99.0))
        pct = r["availability_pct"]
        allowed = None
        s, e = _window(start, end)
        total_min = (e - s).total_seconds() / 60
        allowed = round(total_min * (100 - target) / 100, 1)
        out.append({**r, "target_pct": target, "allowed_downtime_minutes": allowed,
                    "status": "no data" if pct is None else ("met" if pct >= target else "breached")})
    if format == "csv":
        return csv_response("sla.csv", ["hostname", "environment", "target_pct", "availability_pct", "downtime_minutes",
                                        "allowed_downtime_minutes", "status"],
                            ([r["hostname"], r["environment"], r["target_pct"], r["availability_pct"],
                              r["downtime_minutes"], r["allowed_downtime_minutes"], r["status"]] for r in out))
    met = sum(1 for r in out if r["status"] == "met")
    return ok(out, {"met": met, "breached": sum(1 for r in out if r["status"] == "breached"), "targets": targets})


@router.get("/performance")
def performance_report(start: Optional[datetime] = Query(None, alias="from"), end: Optional[datetime] = Query(None, alias="to"),
                       environment: Optional[str] = Query(None, max_length=20),
                       format: str = Query("json", pattern="^(json|csv)$"),
                       principal: Principal = Depends(require("reports.view")), db: Session = Depends(get_db)):
    start, end = _window(start, end, default_days=7)
    servers = {s.id: s for s in _servers(db, environment, None)}
    stmt = (select(PerfSample.server_id, PerfSample.category, func.avg(PerfSample.value), func.max(PerfSample.value),
                   func.count())
            .where(PerfSample.sampled_at >= start.replace(tzinfo=None), PerfSample.sampled_at <= end.replace(tzinfo=None),
                   PerfSample.category.in_(("cpu", "memory", "disk")), PerfSample.uom == "%")
            .group_by(PerfSample.server_id, PerfSample.category))
    agg: dict[int, dict] = {}
    for sid, cat, avg, mx, n in db.execute(stmt):
        if sid in servers:
            agg.setdefault(sid, {})[cat] = {"avg": round(float(avg), 1), "max": round(float(mx), 1), "samples": n}
    rows = []
    for sid, s in servers.items():
        a = agg.get(sid, {})
        rows.append({"server_id": sid, "hostname": s.hostname, "environment": s.environment,
                     "cpu_avg": a.get("cpu", {}).get("avg"), "cpu_max": a.get("cpu", {}).get("max"),
                     "memory_avg": a.get("memory", {}).get("avg"), "memory_max": a.get("memory", {}).get("max"),
                     "disk_avg": a.get("disk", {}).get("avg"), "disk_max": a.get("disk", {}).get("max")})
    rows.sort(key=lambda r: -(r["cpu_avg"] or 0))
    if format == "csv":
        cols = ["hostname", "environment", "cpu_avg", "cpu_max", "memory_avg", "memory_max", "disk_avg", "disk_max"]
        return csv_response("performance.csv", cols, ([r[c] for c in cols] for r in rows))
    return ok(rows, {"from": start.isoformat(), "to": end.isoformat()})


@router.get("/health")
def health_report(days: int = Query(7, ge=1, le=90), format: str = Query("json", pattern="^(json|csv)$"),
                  principal: Principal = Depends(require("reports.view")), db: Session = Depends(get_db)):
    th = (db.get(SystemSetting, "health_thresholds").value if db.get(SystemSetting, "health_thresholds") else {}) or {}
    cpu_t, mem_t, disk_t = th.get("cpu", 85), th.get("memory", 85), th.get("disk", 85)
    snap = get_status()
    servers = _servers(db, None, None)
    end = datetime.now(timezone.utc)
    counts = logparser.alert_counts(end - timedelta(days=days), end)
    high_cpu, high_mem, high_disk, repeated = [], [], [], []
    for s in servers:
        m = service_metrics(s, snap)
        base = {"server_id": s.id, "hostname": s.hostname, "environment": s.environment}
        if m["cpu"] is not None and m["cpu"] >= cpu_t:
            high_cpu.append({**base, "value": m["cpu"]})
        if m["memory"] is not None and m["memory"] >= mem_t:
            high_mem.append({**base, "value": m["memory"]})
        if m["disk"] is not None and m["disk"] >= disk_t:
            high_disk.append({**base, "value": m["disk"]})
        if counts.get(s.hostname, 0) >= 3:
            repeated.append({**base, "value": counts[s.hostname]})
    for lst in (high_cpu, high_mem, high_disk, repeated):
        lst.sort(key=lambda r: -r["value"])
    if format == "csv":
        rows = [["high_cpu", r["hostname"], r["value"]] for r in high_cpu] + \
               [["high_memory", r["hostname"], r["value"]] for r in high_mem] + \
               [["high_disk", r["hostname"], r["value"]] for r in high_disk] + \
               [["repeated_failures", r["hostname"], r["value"]] for r in repeated]
        return csv_response("infrastructure-health.csv", ["finding", "hostname", "value"], rows)
    return ok({"high_cpu": high_cpu, "high_memory": high_mem, "high_disk": high_disk, "repeated_failures": repeated,
               "thresholds": {"cpu": cpu_t, "memory": mem_t, "disk": disk_t}, "days": days})
