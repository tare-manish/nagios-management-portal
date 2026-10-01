"""Join configuration (MariaDB) with live state (Nagios status.dat / logs)."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from .api.util import ts_iso
from .models import Server
from .nagios import logparser
from .nagios.status import (StatusSnapshot, get_status, host_state_name, parse_perfdata, primary_percent,
                            service_state_name)

_avail_cache: dict = {"at": 0.0, "data": {}}
_avail_lock = threading.Lock()


def availability_30d(snapshot: StatusSnapshot | None = None) -> dict[str, float]:
    """Host availability % over the last 30 days (cached 5 minutes)."""
    with _avail_lock:
        if time.time() - _avail_cache["at"] < 300:
            return _avail_cache["data"]
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)
    snap = snapshot or get_status()
    current = {h: host_state_name(v) for h, v in snap.hosts.items() if v.get("has_been_checked")}
    try:
        res = logparser.availability(start, end, current_states=current)
        data = {k: v.pct("UP") for k, v in res.items()}
    except Exception:
        data = {}
    with _avail_lock:
        _avail_cache.update(at=time.time(), data=data)
    return data


def service_metrics(server: Server, snap: StatusSnapshot) -> dict:
    """Headline CPU / memory / disk / uptime values from the server's live services."""
    out = {"cpu": None, "memory": None, "disk": None, "uptime_seconds": None}
    for ss in server.services:
        sv = snap.services.get((server.hostname, ss.service_description))
        if not sv or not sv.get("has_been_checked"):
            continue
        cat = ss.service.category if ss.service else None
        perf = sv.get("performance_data")
        if cat == "cpu" and out["cpu"] is None and ss.service.code == "ncpa_cpu":
            out["cpu"] = primary_percent(perf)
        elif cat == "memory" and ss.service.code == "ncpa_memory":
            out["memory"] = primary_percent(perf)
        elif cat == "disk":
            v = primary_percent(perf)
            if v is not None and (out["disk"] is None or v > out["disk"]):
                out["disk"] = v
        elif cat == "uptime":
            items = parse_perfdata(perf)
            if items:
                out["uptime_seconds"] = items[0]["value"]
    for k in ("cpu", "memory", "disk"):
        if out[k] is not None:
            out[k] = round(out[k], 1)
    return out


def host_live(hostname: str, snap: StatusSnapshot) -> dict:
    h = snap.hosts.get(hostname)
    services = snap.services_for(hostname)
    counts = {"OK": 0, "WARNING": 0, "CRITICAL": 0, "UNKNOWN": 0, "PENDING": 0}
    for sv in services:
        counts[service_state_name(sv)] = counts.get(service_state_name(sv), 0) + 1
    return {
        "state": host_state_name(h) if not snap.error else "UNKNOWN",
        "output": (h or {}).get("plugin_output"),
        "last_check": ts_iso((h or {}).get("last_check")),
        "next_check": ts_iso((h or {}).get("next_check")),
        "last_state_change": ts_iso((h or {}).get("last_state_change")),
        "acknowledged": bool((h or {}).get("problem_has_been_acknowledged")),
        "in_downtime": bool((h or {}).get("scheduled_downtime_depth")),
        "checks_enabled": bool((h or {}).get("active_checks_enabled", 1)),
        "notifications_enabled": bool((h or {}).get("notifications_enabled", 1)),
        "service_counts": counts,
        "in_nagios": h is not None,
    }


def service_live(sv: dict | None) -> dict:
    sv = sv or {}
    return {
        "state": service_state_name(sv if sv else None),
        "output": sv.get("plugin_output"),
        "perf_data": sv.get("performance_data"),
        "perf": parse_perfdata(sv.get("performance_data")),
        "last_check": ts_iso(sv.get("last_check")),
        "next_check": ts_iso(sv.get("next_check")),
        "last_state_change": ts_iso(sv.get("last_state_change")),
        "state_type": "HARD" if sv.get("state_type") == 1 else ("SOFT" if sv else None),
        "attempt": f"{sv.get('current_attempt', 0)}/{sv.get('max_attempts', 0)}" if sv else None,
        "acknowledged": bool(sv.get("problem_has_been_acknowledged")),
        "in_downtime": bool(sv.get("scheduled_downtime_depth")),
        "is_flapping": bool(sv.get("is_flapping")),
    }
