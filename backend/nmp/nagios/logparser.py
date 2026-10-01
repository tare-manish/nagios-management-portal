"""Nagios event log parsing: recent events, alert history and availability.

Reads /usr/local/nagios/var/nagios.log and the rotated archives
(nagios-MM-DD-YYYY-HH.log). Read-only.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import get_settings

_LINE_RE = re.compile(r"^\[(\d+)\] ([A-Z ]+?): (.*)$")
_ARCH_RE = re.compile(r"nagios-(\d{2})-(\d{2})-(\d{4})-(\d{2})\.log$")

HOST_STATE_NUM = {"UP": 0, "DOWN": 1, "UNREACHABLE": 2}
SVC_STATE_NUM = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}


@dataclass
class LogEvent:
    ts: int
    kind: str
    host: str | None = None
    service: str | None = None
    state: str | None = None
    state_type: str | None = None
    output: str | None = None
    contact: str | None = None

    def as_dict(self) -> dict:
        return {"time": datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat(), "ts": self.ts,
                "kind": self.kind, "host": self.host, "service": self.service, "state": self.state,
                "state_type": self.state_type, "output": self.output, "contact": self.contact}


def parse_line(line: str) -> LogEvent | None:
    m = _LINE_RE.match(line.rstrip("\n"))
    if not m:
        if line.startswith("[") and "] " in line:
            try:
                ts = int(line[1:line.index("]")])
            except ValueError:
                return None
            msg = line[line.index("]") + 2:].strip()
            if "Caught SIGHUP" in msg or "starting..." in msg or "shutting down" in msg.lower():
                return LogEvent(ts, "PROGRAM", output=msg)
        return None
    ts, kind, rest = int(m.group(1)), m.group(2).strip(), m.group(3)
    f = rest.split(";")
    if kind in ("HOST ALERT", "CURRENT HOST STATE", "INITIAL HOST STATE") and len(f) >= 4:
        return LogEvent(ts, kind, host=f[0], state=f[1], state_type=f[2], output=";".join(f[4:]))
    if kind in ("SERVICE ALERT", "CURRENT SERVICE STATE", "INITIAL SERVICE STATE") and len(f) >= 5:
        return LogEvent(ts, kind, host=f[0], service=f[1], state=f[2], state_type=f[3], output=";".join(f[5:]))
    if kind == "HOST NOTIFICATION" and len(f) >= 4:
        return LogEvent(ts, kind, contact=f[0], host=f[1], state=f[2], output=";".join(f[4:]))
    if kind == "SERVICE NOTIFICATION" and len(f) >= 5:
        return LogEvent(ts, kind, contact=f[0], host=f[1], service=f[2], state=f[3], output=";".join(f[5:]))
    if kind in ("HOST DOWNTIME ALERT", "HOST FLAPPING ALERT") and len(f) >= 2:
        return LogEvent(ts, kind, host=f[0], state=f[1], output=";".join(f[2:]))
    if kind in ("SERVICE DOWNTIME ALERT", "SERVICE FLAPPING ALERT") and len(f) >= 3:
        return LogEvent(ts, kind, host=f[0], service=f[1], state=f[2], output=";".join(f[3:]))
    if kind == "EXTERNAL COMMAND":
        return LogEvent(ts, kind, output=rest[:300])
    return None


def _archive_files() -> list[tuple[datetime, Path]]:
    s = get_settings()
    out = []
    d = Path(s.nagios_log_archive)
    if d.is_dir():
        for p in d.iterdir():
            m = _ARCH_RE.search(p.name)
            if m:
                mm, dd, yyyy, hh = map(int, m.groups())
                try:
                    out.append((datetime(yyyy, mm, dd, hh, tzinfo=timezone.utc), p))
                except ValueError:
                    continue
    return sorted(out)


def log_files_for(start: datetime, end: datetime) -> list[Path]:
    """Archive files are named after their rotation time (they contain the preceding period)."""
    files = []
    arch = _archive_files()
    for when, p in arch:
        # an archive rotated at `when` holds events from the previous rotation up to `when`
        if when >= start - timedelta(days=1) and when - timedelta(days=2) <= end:
            files.append(p)
    cur = Path(get_settings().nagios_log_file)
    if cur.exists():
        files.append(cur)
    return files


def iter_events(start: datetime, end: datetime, lead_in: bool = False):
    lo = int(start.timestamp()) - (86400 * 2 if lead_in else 0)
    hi = int(end.timestamp())
    for p in log_files_for(start, end):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    ev = parse_line(line)
                    if ev and lo <= ev.ts <= hi:
                        yield ev
        except OSError:
            continue


def recent_events(limit: int = 100, host: str | None = None, kinds: set[str] | None = None,
                  max_bytes: int = 4_000_000, since: datetime | None = None) -> list[dict]:
    """Newest-first events from the current log (tail) and recent archives if needed."""
    files = [Path(get_settings().nagios_log_file)] + [p for _, p in reversed(_archive_files())][:7]
    kinds = kinds or {"HOST ALERT", "SERVICE ALERT", "HOST NOTIFICATION", "SERVICE NOTIFICATION",
                      "HOST DOWNTIME ALERT", "SERVICE DOWNTIME ALERT", "PROGRAM", "HOST FLAPPING ALERT",
                      "SERVICE FLAPPING ALERT"}
    out: list[dict] = []
    budget = max_bytes
    min_ts = int(since.timestamp()) if since else 0
    for p in files:
        if budget <= 0 or len(out) >= limit:
            break
        try:
            size = p.stat().st_size
            with open(p, "rb") as fh:
                start = max(0, size - budget)
                fh.seek(start)
                data = fh.read().decode("utf-8", errors="replace")
                budget -= size - start
        except OSError:
            continue
        lines = data.splitlines()
        if start > 0 and lines:
            lines = lines[1:]
        for line in reversed(lines):
            ev = parse_line(line)
            if not ev or ev.kind not in kinds:
                continue
            if ev.ts < min_ts:
                return out
            if host and ev.host != host:
                continue
            out.append(ev.as_dict())
            if len(out) >= limit:
                return out
    return out


@dataclass
class Availability:
    object_key: str
    seconds: dict[str, float]
    total: float

    @property
    def known(self) -> float:
        return sum(v for k, v in self.seconds.items() if k != "UNDETERMINED")

    def pct(self, state: str) -> float:
        k = self.known
        return round(self.seconds.get(state, 0.0) / k * 100.0, 3) if k > 0 else 0.0

    def as_dict(self) -> dict:
        return {"object": self.object_key, "seconds": {k: round(v) for k, v in self.seconds.items()},
                "total_seconds": round(self.total), "known_seconds": round(self.known)}


def availability(start: datetime, end: datetime, hosts: set[str] | None = None,
                 services: bool = False, current_states: dict | None = None) -> dict[str, Availability]:
    """HARD-state availability per host (or per 'host/service' when services=True).

    current_states: optional {key: state_name} used when no log entries exist for
    an object in the window (state assumed constant for the whole window).
    """
    t0, t1 = start.timestamp(), min(end.timestamp(), datetime.now(timezone.utc).timestamp())
    state_at: dict[str, tuple[float, str]] = {}
    acc: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    def add(key: str, upto: float) -> None:
        if key in state_at:
            since, st = state_at[key]
            a, b = max(since, t0), min(upto, t1)
            if b > a:
                acc[key][st] += b - a

    for ev in iter_events(start, end, lead_in=True):
        if services:
            if ev.kind not in ("SERVICE ALERT", "CURRENT SERVICE STATE", "INITIAL SERVICE STATE"):
                continue
            key = f"{ev.host}/{ev.service}"
        else:
            if ev.kind not in ("HOST ALERT", "CURRENT HOST STATE", "INITIAL HOST STATE"):
                continue
            key = ev.host or ""
        if hosts is not None and ev.host not in hosts:
            continue
        if ev.state_type != "HARD":
            continue
        prev = state_at.get(key)
        if prev and prev[1] == ev.state:
            continue
        add(key, ev.ts)
        state_at[key] = (ev.ts, ev.state or "UNKNOWN")
    for key in list(state_at):
        add(key, t1)
    out: dict[str, Availability] = {}
    total = max(0.0, t1 - t0)
    keys = set(acc) | set(state_at) | set((current_states or {}).keys())
    for key in keys:
        secs = dict(acc.get(key, {}))
        if not secs and current_states and key in current_states:
            secs = {current_states[key]: total}
        known = sum(secs.values())
        if total - known > 1:
            secs["UNDETERMINED"] = total - known
        out[key] = Availability(key, secs, total)
    return out


def alert_counts(start: datetime, end: datetime, hard_only: bool = True) -> dict[str, int]:
    """Number of non-OK HARD alerts per host within the window."""
    counts: dict[str, int] = defaultdict(int)
    for ev in iter_events(start, end):
        if ev.kind in ("HOST ALERT", "SERVICE ALERT") and (ev.state_type == "HARD" or not hard_only):
            if ev.state not in ("UP", "OK"):
                counts[ev.host or ""] += 1
    return dict(counts)
