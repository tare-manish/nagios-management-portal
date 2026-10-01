"""Data cleanup (Super Admin only): remove junk and stale portal data.

Every category is previewed first (counts only, nothing deleted), and then
executed on explicit confirmation. Hard safety rules, enforced here and not
in the UI:

  * the live Nagios configuration (managed dir, nagios.cfg, object files) is never touched
  * the currently applied configuration version, the newest versions and anything
    not yet applied are never deleted
  * the backup taken before the current version, and the newest backups, are never
    deleted; installer/upgrade backups are never touched
  * a soft-deleted server is purged only after its deletion is live in Nagios
  * backup archives are root-owned: they are removed only through the whitelisted
    privileged helper `nagios-config-backup-delete`, which re-checks the rules
"""
from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import utcnow
from .models import (AuditLog, ConfigBackup, ConfigurationChange, ConfigurationVersion, ConfigurationVersionFile,
                     MonitorStateCache, Notification, PerfSample, RateLimitBucket, Server, SystemSetting,
                     UserSession)

log = logging.getLogger("nmp.config")

KEEP_VERSIONS = 10          # newest configuration versions always kept
KEEP_BACKUPS = 10           # newest portal backups always kept
BATCH = 20000               # rows per DELETE statement for large tables
OPEN_STATUSES = ("generated", "validated", "applying")


@dataclass(frozen=True)
class Category:
    key: str
    label: str
    description: str
    uses_age: bool
    default_days: int = 0
    min_days: int = 0


CATEGORIES: list[Category] = [
    Category("sessions", "Expired sessions & rate-limit records",
             "Login sessions that have expired and login rate-limit counters older than one day.", False),
    Category("perf_samples", "Old performance samples",
             "Graph data points older than the selected age.", True, 90, 1),
    Category("orphan_data", "Orphaned monitoring data",
             "Graph samples and alert history of servers that no longer exist, and notification-engine state "
             "for hosts/services that are no longer in Nagios.", False),
    Category("notifications", "Old notification history",
             "Sent, failed and suppressed alert notification records older than the selected age.", True, 90, 7),
    Category("audit_logs", "Old audit log entries",
             "Audit trail entries older than the selected age. The cleanup itself is always audited.", True, 365, 30),
    Category("failed_versions", "Failed & abandoned configuration versions",
             "Versions that failed validation or apply, and generated/validated versions that were never applied "
             "and are older than the current live version.", False),
    Category("config_versions", "Old configuration history",
             f"Superseded and rolled-back versions older than the selected age. The live version and the newest "
             f"{KEEP_VERSIONS} versions are always kept.", True, 90, 7),
    Category("staging", "Leftover staging directories",
             "Generated-file staging folders of versions that are already applied, failed or deleted. These folders "
             "contain agent tokens in plain text, so removing them also reduces exposure.", False),
    Category("backups", "Old configuration backups",
             f"Backup archives older than the selected age, and backup records whose archive file is missing. The "
             f"backup taken before the live version and the newest {KEEP_BACKUPS} backups are always kept.",
             True, 90, 7),
    Category("deleted_servers", "Deleted servers (purge)",
             "Servers that were deleted in the portal, whose deletion is already applied to Nagios, deleted longer "
             "ago than the selected age. Removes their stored services, thresholds and encrypted credentials.",
             True, 30, 0),
]
CATEGORY_MAP = {c.key: c for c in CATEGORIES}


@dataclass
class Result:
    count: int = 0
    bytes: int = 0
    protected: int = 0
    note: str = ""
    errors: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = {"count": self.count, "protected": self.protected, "note": self.note, "errors": self.errors}
        if self.bytes:
            d["bytes"] = self.bytes
        if self.detail:
            d["detail"] = self.detail
        return d


def category_payload(db: Session) -> list[dict]:
    s = db.get(SystemSetting, "perf_retention_days")
    perf_default = int(s.value) if s else 90
    out = []
    for c in CATEGORIES:
        out.append({"key": c.key, "label": c.label, "description": c.description, "uses_age": c.uses_age,
                    "default_days": perf_default if c.key == "perf_samples" else c.default_days,
                    "min_days": c.min_days})
    return out


# ---------------------------------------------------------------- helpers --
def _current_applied(db: Session) -> ConfigurationVersion | None:
    return db.scalar(select(ConfigurationVersion).where(ConfigurationVersion.status == "applied")
                     .order_by(ConfigurationVersion.id.desc()))


def _batched_delete(db: Session, model, where, execute: bool) -> int:
    """Count, or delete in batches (avoids one huge transaction on large tables)."""
    pk = model.__mapper__.primary_key[0]
    if not execute:
        return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)
    total = 0
    while True:
        ids = list(db.scalars(select(pk).where(*where).limit(BATCH)))
        if not ids:
            break
        total += db.execute(delete(model).where(pk.in_(ids))).rowcount or 0
        db.commit()
        if len(ids) < BATCH:
            break
    return total


def _active_server_ids(db: Session) -> list[int]:
    return list(db.scalars(select(Server.id).where(Server.deleted_token == 0)))


# ------------------------------------------------------------- categories --
def _sessions(db: Session, days: int, execute: bool) -> Result:
    now = utcnow()
    r = Result()
    r.count = _batched_delete(db, UserSession, [UserSession.expires_at < now], execute)
    buckets = _batched_delete(db, RateLimitBucket, [RateLimitBucket.window_start < now - timedelta(days=1)], execute)
    r.detail = {"sessions": r.count, "rate_limit_buckets": buckets}
    r.count += buckets
    return r


def _perf_samples(db: Session, days: int, execute: bool) -> Result:
    cutoff = utcnow() - timedelta(days=days)
    return Result(count=_batched_delete(db, PerfSample, [PerfSample.sampled_at < cutoff], execute))


def _orphan_data(db: Session, days: int, execute: bool) -> Result:
    active = _active_server_ids(db) or [-1]
    r = Result()
    perf = _batched_delete(db, PerfSample, [PerfSample.server_id.not_in(active)], execute)
    notif = _batched_delete(db, Notification, [Notification.server_id.is_not(None),
                                               Notification.server_id.not_in(active)], execute)
    state = 0
    from .nagios.status import get_status
    snap = get_status()
    if snap.error:
        r.note = "Nagios status is unavailable - engine state was not checked"
    else:
        live = {f"h:{h}" for h in snap.hosts} | {f"s:{h}/{d}" for (h, d) in snap.services}
        stale = [k for k in db.scalars(select(MonitorStateCache.object_key)) if k not in live]
        state = len(stale)
        if execute and stale:
            for i in range(0, len(stale), 1000):
                db.execute(delete(MonitorStateCache).where(MonitorStateCache.object_key.in_(stale[i:i + 1000])))
            db.commit()
    r.detail = {"perf_samples": perf, "notifications": notif, "state_cache": state}
    r.count = perf + notif + state
    return r


def _notifications(db: Session, days: int, execute: bool) -> Result:
    cutoff = utcnow() - timedelta(days=days)
    return Result(count=_batched_delete(db, Notification, [Notification.created_at < cutoff], execute))


def _audit_logs(db: Session, days: int, execute: bool) -> Result:
    cutoff = utcnow() - timedelta(days=days)
    return Result(count=_batched_delete(db, AuditLog, [AuditLog.occurred_at < cutoff], execute))


def _protected_version_ids(db: Session) -> set[int]:
    keep = set(db.scalars(select(ConfigurationVersion.id).order_by(ConfigurationVersion.id.desc()).limit(KEEP_VERSIONS)))
    cur = _current_applied(db)
    if cur is not None:
        keep.add(cur.id)
        # anything newer than the live version that is not yet applied may still be applied
        keep.update(db.scalars(select(ConfigurationVersion.id).where(ConfigurationVersion.id > cur.id)))
    keep.update(db.scalars(select(ConfigurationVersion.id).where(ConfigurationVersion.status == "applying")))
    return keep


def _delete_versions(db: Session, ids: list[int]) -> None:
    for i in range(0, len(ids), 200):
        chunk = ids[i:i + 200]
        # changes must go first: their FK is ON DELETE SET NULL, and a NULL version_id
        # would make old, applied changes re-appear as "pending"
        db.execute(delete(ConfigurationChange).where(ConfigurationChange.version_id.in_(chunk)))
        db.execute(delete(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id.in_(chunk)))
        db.execute(delete(ConfigurationVersion).where(ConfigurationVersion.id.in_(chunk)))
        db.commit()


def _failed_versions(db: Session, days: int, execute: bool) -> Result:
    cur = _current_applied(db)
    newest = db.scalar(select(func.max(ConfigurationVersion.id)))
    q = select(ConfigurationVersion.id, ConfigurationVersion.status)
    ids: list[int] = []
    protected = 0
    for vid, status in db.execute(q):
        junk = status in ("validation_failed", "apply_failed") or (
            status in ("generated", "validated") and cur is not None and vid < cur.id)
        if not junk:
            continue
        if vid == newest or (cur is not None and vid == cur.id):
            protected += 1
            continue
        ids.append(vid)
    if execute and ids:
        _delete_versions(db, ids)
    return Result(count=len(ids), protected=protected)


def _config_versions(db: Session, days: int, execute: bool) -> Result:
    cutoff = utcnow() - timedelta(days=days)
    keep = _protected_version_ids(db)
    rows = list(db.execute(select(ConfigurationVersion.id).where(
        ConfigurationVersion.status.in_(("superseded", "rolled_back")), ConfigurationVersion.created_at < cutoff)))
    ids = [vid for (vid,) in rows if vid not in keep]
    r = Result(count=len(ids), protected=len(rows) - len(ids))
    if execute and ids:
        _delete_versions(db, ids)
    return r


def _stage_dirs() -> list[tuple[int, Path]]:
    base = Path(get_settings().staging_dir)
    if not base.is_dir():
        return []
    out = []
    for d in base.iterdir():
        if d.is_dir() and not d.is_symlink() and d.name.startswith("v") and d.name[1:].isdigit():
            out.append((int(d.name[1:]), d))
    return sorted(out)


def _dir_size(p: Path) -> int:
    n = 0
    for f in p.rglob("*"):
        try:
            if f.is_file() and not f.is_symlink():
                n += f.stat().st_size
        except OSError:
            pass
    return n


def _staging(db: Session, days: int, execute: bool) -> Result:
    cur = _current_applied(db)
    status = dict(db.execute(select(ConfigurationVersion.id, ConfigurationVersion.status)).all())
    newest = max(status) if status else None
    r = Result()
    base = Path(get_settings().staging_dir).resolve()
    for vid, d in _stage_dirs():
        st = status.get(vid)
        needed = vid == newest or (st in OPEN_STATUSES and (cur is None or vid > cur.id))
        if needed:
            r.protected += 1
            continue
        r.count += 1
        r.bytes += _dir_size(d)
        if execute:
            if d.resolve().parent != base:
                r.errors.append(f"{d.name}: outside the staging directory - skipped")
                continue
            shutil.rmtree(d, ignore_errors=False)
    return r


def _backup_path(name: str) -> Path:
    return Path(get_settings().backup_dir) / f"{name}.tar.gz"


def _backups(db: Session, days: int, execute: bool) -> Result:
    from .nagios import privileged

    cutoff = utcnow() - timedelta(days=days)
    cur = _current_applied(db)
    rows = list(db.scalars(select(ConfigBackup).order_by(ConfigBackup.id.desc())))
    keep = {b.id for b in rows[:KEEP_BACKUPS]}
    if cur is not None and cur.backup_id:
        keep.add(cur.backup_id)
    keep.update(b.id for b in rows if b.name[16:].startswith("install"))  # first backup taken by the installer
    r = Result()
    missing_files = 0
    for b in rows:
        path = _backup_path(b.name)
        exists = path.is_file()
        if not exists:
            # record of an archive that no longer exists (pruned or removed by hand)
            if cur is not None and b.id == cur.backup_id:
                r.protected += 1
                continue
            missing_files += 1
            r.count += 1
            if execute:
                db.delete(b)
            continue
        if b.created_at >= cutoff:
            continue
        if b.id in keep:
            r.protected += 1
            continue
        r.count += 1
        r.bytes += b.size_bytes or 0
        if execute:
            try:
                res = privileged.run("backup_delete", b.name)
            except privileged.PrivilegedError as exc:
                r.errors.append(f"{b.name}: {exc}")
                continue
            if not res.get("ok"):
                r.errors.append(f"{b.name}: {res.get('error', 'refused')}")
                continue
            db.delete(b)
    if execute:
        db.commit()
    r.detail = {"archives": r.count - missing_files, "records_without_file": missing_files}
    return r


def _deleted_servers(db: Session, days: int, execute: bool) -> Result:
    cur = _current_applied(db)
    r = Result()
    deleted = list(db.scalars(select(Server).where(Server.deleted_token != 0)))
    if cur is None or cur.applied_at is None:
        r.protected = len(deleted)
        r.note = "No configuration has been applied yet - deleted servers are kept"
        return r
    cutoff = utcnow() - timedelta(days=days)
    purge = []
    for s in deleted:
        when: datetime | None = s.deleted_at
        if when is None or when >= cur.applied_at or when >= cutoff:
            r.protected += 1  # deletion not yet live in Nagios, or too recent
            continue
        purge.append(s)
    r.count = len(purge)
    if purge:
        r.detail = {"servers": [s.hostname for s in purge[:50]]}
    if execute and purge:
        ids = [s.id for s in purge]
        _batched_delete(db, PerfSample, [PerfSample.server_id.in_(ids)], True)
        for s in purge:
            db.delete(s)  # ORM cascade: credentials, services, thresholds, group links
        db.commit()
    return r


HANDLERS: dict[str, Callable[[Session, int, bool], Result]] = {
    "sessions": _sessions, "perf_samples": _perf_samples, "orphan_data": _orphan_data,
    "notifications": _notifications, "audit_logs": _audit_logs, "failed_versions": _failed_versions,
    "config_versions": _config_versions, "staging": _staging, "backups": _backups,
    "deleted_servers": _deleted_servers,
}
ORDER = [c.key for c in CATEGORIES]


def run_cleanup(db: Session, items: dict[str, int], execute: bool) -> dict[str, dict]:
    """items: {category: older_than_days}. Returns per-category results."""
    out: dict[str, dict] = {}
    for key in ORDER:
        if key not in items:
            continue
        cat = CATEGORY_MAP[key]
        days = max(int(items[key] or 0), cat.min_days) if cat.uses_age else 0
        try:
            res = HANDLERS[key](db, days, execute)
        except Exception as exc:  # one failing category never blocks the others
            db.rollback()
            log.exception("cleanup category %s failed", key)
            res = Result(errors=[f"{type(exc).__name__}: {str(exc)[:200]}"])
        d = res.as_dict()
        if cat.uses_age:
            d["older_than_days"] = days
        out[key] = d
        if execute:
            log.info("cleanup %s: removed=%s protected=%s errors=%s", key, res.count, res.protected, len(res.errors))
    return out
