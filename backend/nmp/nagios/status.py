"""Live monitoring state read directly from Nagios (status.dat).

Nothing here is persisted to MariaDB: Nagios stays the source of live truth.
The parsed file is cached until its mtime changes (Nagios rewrites it every
status_update_interval seconds).
"""
from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import get_settings

HOST_STATES = {0: "UP", 1: "DOWN", 2: "UNREACHABLE"}
SERVICE_STATES = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}

_INT_FIELDS = {
    "current_state", "last_hard_state", "state_type", "current_attempt", "max_attempts", "has_been_checked",
    "last_check", "next_check", "last_state_change", "last_hard_state_change", "last_time_up", "last_time_down",
    "last_time_unreachable", "last_time_ok", "last_time_warning", "last_time_critical", "last_time_unknown",
    "problem_has_been_acknowledged", "scheduled_downtime_depth", "active_checks_enabled", "notifications_enabled",
    "is_flapping", "check_type", "downtime_id", "start_time", "end_time", "entry_time", "fixed", "duration",
    "comment_id", "entry_type", "program_start", "nagios_pid", "last_command_check", "last_log_rotation",
    "enable_notifications", "execute_service_checks", "execute_host_checks", "current_notification_number",
    "acknowledgement_type", "triggered_by", "persistent",
}
_FLOAT_FIELDS = {"percent_state_change", "check_execution_time", "check_latency"}


@dataclass
class StatusSnapshot:
    mtime: float = 0.0
    info: dict = field(default_factory=dict)
    program: dict = field(default_factory=dict)
    hosts: dict[str, dict] = field(default_factory=dict)
    services: dict[tuple[str, str], dict] = field(default_factory=dict)
    downtimes: list[dict] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)
    error: str | None = None

    def services_for(self, host: str) -> list[dict]:
        return [s for (h, _), s in self.services.items() if h == host]

    @property
    def generated_at(self) -> datetime | None:
        return datetime.fromtimestamp(self.mtime, tz=timezone.utc) if self.mtime else None


def _convert(k: str, v: str):
    if k in _INT_FIELDS:
        try:
            return int(v)
        except ValueError:
            return 0
    if k in _FLOAT_FIELDS:
        try:
            return float(v)
        except ValueError:
            return 0.0
    return v


def parse_status(text: str) -> StatusSnapshot:
    snap = StatusSnapshot()
    block = None
    cur: dict = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.endswith("{"):
            block = s[:-1].strip()
            cur = {}
            continue
        if s == "}":
            if block == "hoststatus":
                snap.hosts[cur.get("host_name", "")] = cur
            elif block == "servicestatus":
                snap.services[(cur.get("host_name", ""), cur.get("service_description", ""))] = cur
            elif block in ("hostdowntime", "servicedowntime"):
                cur["kind"] = "host" if block == "hostdowntime" else "service"
                snap.downtimes.append(cur)
            elif block in ("hostcomment", "servicecomment"):
                cur["kind"] = "host" if block == "hostcomment" else "service"
                snap.comments.append(cur)
            elif block == "info":
                snap.info = cur
            elif block == "programstatus":
                snap.program = cur
            block = None
            continue
        if block and "=" in s:
            k, v = s.split("=", 1)
            cur[k] = _convert(k, v)
    return snap


_cache = StatusSnapshot()
_lock = threading.Lock()


def get_status(path: str | None = None) -> StatusSnapshot:
    global _cache
    path = path or get_settings().nagios_status_file
    try:
        mtime = os.stat(path).st_mtime
    except OSError as exc:
        return StatusSnapshot(error=f"status file not readable: {exc.strerror}")
    with _lock:
        if _cache.mtime == mtime and not _cache.error:
            return _cache
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                snap = parse_status(fh.read())
        except OSError as exc:
            return StatusSnapshot(error=f"status file not readable: {exc.strerror}")
        snap.mtime = mtime
        _cache = snap
        return snap


# ------------------------------------------------------------ perf data --
_PERF_RE = re.compile(r"""('([^']+)'|[^\s=]+)=([-0-9.]+)([^;\s]*)(?:;([^;\s]*))?(?:;([^;\s]*))?(?:;([^;\s]*))?(?:;([^;\s]*))?""")


def _num(v: str | None) -> float | None:
    if v in (None, ""):
        return None
    m = re.match(r"^[~@]?(-?[0-9.]+)", v)
    if not m:
        return None
    try:
        # for ranges like 10:20 keep the upper bound when present
        if ":" in v:
            hi = v.split(":", 1)[1]
            return float(hi) if hi else float(m.group(1))
        return float(m.group(1))
    except ValueError:
        return None


def parse_perfdata(perf: str | None) -> list[dict]:
    out = []
    if not perf:
        return out
    for m in _PERF_RE.finditer(perf):
        label = m.group(2) or m.group(1)
        try:
            value = float(m.group(3))
        except ValueError:
            continue
        out.append({"label": label[:100], "value": value, "uom": (m.group(4) or "")[:16],
                    "warn": _num(m.group(5)), "crit": _num(m.group(6)),
                    "min": _num(m.group(7)), "max": _num(m.group(8))})
    return out


def primary_percent(perf: str | None) -> float | None:
    """Best-effort 'headline' percentage from perf data (CPU/memory/disk)."""
    items = parse_perfdata(perf)
    for it in items:
        if it["uom"] == "%":
            return it["value"]
    return items[0]["value"] if items else None


def host_state_name(h: dict | None) -> str:
    if not h:
        return "UNMONITORED"
    if not h.get("has_been_checked"):
        return "PENDING"
    return HOST_STATES.get(h.get("current_state", 0), "UNKNOWN")


def service_state_name(sv: dict | None) -> str:
    if not sv:
        return "UNMONITORED"
    if not sv.get("has_been_checked"):
        return "PENDING"
    return SERVICE_STATES.get(sv.get("current_state", 3), "UNKNOWN")
