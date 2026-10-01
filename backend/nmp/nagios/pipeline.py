"""Configuration pipeline orchestration (application side).

  generate_version()  DB -> files -> staging dir + manifest   (no privileges)
  validate_version()  -> nagios-config-validate (sudo)       (never touches live config)
  apply_version()     -> nagios-config-apply    (sudo)       (backup/validate/install/reload/verify)
  rollback_to()       restore DB snapshot of version N, regenerate, apply
"""
from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import shutil
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from ..audit import AuditContext, audit, record_change
from ..config import get_settings
from ..db import utcnow
from ..models import (ConfigBackup, ConfigurationChange, ConfigurationVersion, ConfigurationVersionFile,
                      Server)
from . import privileged
from .generator import Generated, generate
from .legacy import load_legacy
from .snapshot import restore_snapshot, take_snapshot

log = logging.getLogger("nmp.config")


class PipelineBusy(Exception):
    pass


@contextmanager
def config_lock(db: Session):
    """Cluster-wide pipeline lock (MariaDB GET_LOCK).

    GET_LOCK is bound to a *connection*; the ORM session returns its connection to
    the pool on every commit, so the lock is held on a dedicated connection.
    """
    bind = db.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect not in ("mysql", "mariadb"):
        yield
        return
    engine = getattr(bind, "engine", bind)
    conn = engine.connect()
    try:
        got = conn.execute(text("SELECT GET_LOCK('nmp_config_pipeline', 5)")).scalar()
        if got != 1:
            raise PipelineBusy("another configuration operation is in progress")
        try:
            yield
        finally:
            conn.execute(text("SELECT RELEASE_LOCK('nmp_config_pipeline')"))
    finally:
        conn.close()


def _sha(text_: str) -> str:
    return hashlib.sha256(text_.encode("utf-8")).hexdigest()


def pending_changes(db: Session) -> list[ConfigurationChange]:
    return list(db.scalars(select(ConfigurationChange).where(ConfigurationChange.version_id.is_(None))
                           .order_by(ConfigurationChange.created_at)))


def write_stage(version_id: int, gen: Generated, overrides: list[dict] | None) -> Path:
    s = get_settings()
    base = Path(s.staging_dir)
    base.mkdir(parents=True, exist_ok=True)
    stage = base / f"v{version_id}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(mode=0o750)
    files, secrets = {}, {}
    for rel, content in gen.files.items():
        p = stage / "managed" / rel
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        p.write_text(content, encoding="utf-8")
        os.chmod(p, 0o640)
        files[rel] = _sha(content)
    sdir = stage / "secrets"
    sdir.mkdir(mode=0o700)
    for rel, content in gen.secrets.items():
        fd = os.open(str(sdir / rel), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        secrets[rel] = _sha(content)
    ov_meta = []
    if overrides:
        (stage / "overrides").mkdir(mode=0o750)
        for i, ov in enumerate(overrides):
            name = f"{i:04d}.cfg"
            (stage / "overrides" / name).write_text(ov["content"], encoding="utf-8")
            ov_meta.append({"target": ov["target"], "file": name, "sha256": _sha(ov["content"]),
                            "sha256_before": ov["sha256_before"]})
    manifest = {"version": version_id, "files": files, "secrets": secrets, "overrides": ov_meta,
                "expected_hosts": gen.expected_hosts, "generated_at": utcnow().isoformat()}
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    _prune_stages(base, keep=20)
    return stage


def _prune_stages(base: Path, keep: int) -> None:
    dirs = sorted((d for d in base.glob("v*") if d.is_dir() and d.name[1:].isdigit()),
                  key=lambda d: int(d.name[1:]))
    for d in dirs[:-keep]:
        shutil.rmtree(d, ignore_errors=True)


def generate_version(db: Session, ctx: AuditContext, summary: str, *, overrides: list[dict] | None = None,
                     takeover_hosts: set[str] | None = None, rollback_of: int | None = None) -> ConfigurationVersion:
    legacy = load_legacy()
    # a take-over removes those hosts' definitions from manual files in the same change
    gen = generate(db, legacy, takeover_hosts=takeover_hosts)
    for e in legacy.errors:
        gen.warnings.append({"object": None, "message": e})
    v = ConfigurationVersion(
        created_by=ctx.user_id, summary=summary[:255], status="generated", config_hash=gen.config_hash,
        snapshot=take_snapshot(db), rollback_of_version=rollback_of,
        validation_warnings=gen.warnings or None,
        legacy_overrides=[{"target": o["target"], "sha256_before": o["sha256_before"]} for o in overrides or []] or None,
    )
    db.add(v)
    db.flush()
    for rel, content in sorted(gen.files.items()):
        db.add(ConfigurationVersionFile(version_id=v.id, path=f"managed/{rel}", content=content, sha256=_sha(content)))
    for ov in overrides or []:
        db.add(ConfigurationVersionFile(version_id=v.id, path=f"override:{ov['target']}", content=ov["content"],
                                        sha256=_sha(ov["content"])))
    if gen.errors:
        v.status = "validation_failed"
        v.validation_errors = gen.errors
        v.validation_output = "Pre-validation by the portal found errors; Nagios validation was not run."
    else:
        write_stage(v.id, gen, overrides)
    audit(db, ctx, "config.generate", entity_type="config_version", entity_id=v.id, entity_name=f"v{v.id}",
          new={"summary": summary, "hosts": gen.stats.get("hosts"), "services": gen.stats.get("services"),
               "errors": len(gen.errors)}, result="success" if not gen.errors else "failure")
    db.commit()
    return v


def _store_validation(v: ConfigurationVersion, validation: dict | None) -> None:
    if not validation:
        return
    v.validation_output = (validation.get("output") or "")[:500000]
    v.validation_errors = validation.get("errors") or None
    v.validation_warnings = (v.validation_warnings or []) + (validation.get("warnings") or []) or None


def validate_version(db: Session, ctx: AuditContext, v: ConfigurationVersion) -> ConfigurationVersion:
    if v.status == "validation_failed" and v.validation_errors and not Path(get_settings().staging_dir, f"v{v.id}").exists():
        return v
    try:
        res = privileged.run("validate", str(v.id))
    except privileged.PrivilegedError as exc:
        v.status = "validation_failed"
        v.validation_errors = [{"message": str(exc), "file": None, "line": None, "object": None, "suggestion": None}]
        audit(db, ctx, "config.validate", entity_type="config_version", entity_id=v.id, entity_name=f"v{v.id}",
              result="failure", detail=str(exc))
        db.commit()
        return v
    validation = res.get("validation") or {}
    _store_validation(v, validation)
    if not res.get("ok") and not validation:
        v.validation_errors = [{"message": res.get("error", "validation failed"), "file": None, "line": None,
                                "object": None, "suggestion": None}]
    v.status = "validated" if res.get("ok") else "validation_failed"
    audit(db, ctx, "config.validate", entity_type="config_version", entity_id=v.id, entity_name=f"v{v.id}",
          result="success" if res.get("ok") else "failure",
          detail=f"errors={len(v.validation_errors or [])}")
    db.commit()
    return v


def apply_version(db: Session, ctx: AuditContext, v: ConfigurationVersion) -> ConfigurationVersion:
    if v.status not in ("generated", "validated"):
        raise ValueError(f"version {v.id} cannot be applied in status '{v.status}'")
    v.status = "applying"
    db.commit()
    try:
        res = privileged.run("apply", str(v.id))
    except privileged.PrivilegedError as exc:
        res = {"ok": False, "error": str(exc)}
    _store_validation(v, res.get("validation"))
    v.apply_log = res.get("steps") or None
    backup = res.get("backup")
    if backup:
        b = ConfigBackup(name=backup["name"], created_by=ctx.user_id, reason=backup.get("reason", "pre-apply"),
                         size_bytes=backup.get("size_bytes", 0), sha256=backup.get("sha256"), version_id=v.id,
                         files=[x["target"] for x in backup.get("legacy", [])])
        db.add(b)
        db.flush()
        v.backup_id = b.id
    if res.get("ok"):
        now = utcnow()
        db.execute(update(ConfigurationVersion).where(ConfigurationVersion.status == "applied",
                                                      ConfigurationVersion.id != v.id).values(status="superseded"))
        v.status = "applied"
        v.applied_at = now
        v.applied_by = ctx.user_id
        db.execute(update(ConfigurationChange).where(ConfigurationChange.version_id.is_(None),
                                                     ConfigurationChange.created_at <= v.created_at)
                   .values(version_id=v.id))
        db.execute(update(Server).where(Server.deleted_token == 0, Server.managed_by == "portal",
                                        Server.config_state.in_(("pending", "error")))
                   .values(config_state="applied"))
        audit(db, ctx, "config.apply", entity_type="config_version", entity_id=v.id, entity_name=f"v{v.id}",
              new={"summary": v.summary, "backup": backup and backup.get("name")})
    else:
        failed_validation = bool(v.validation_errors) or (res.get("validation") and not res["validation"].get("ok"))
        v.status = "validation_failed" if failed_validation else "apply_failed"
        if not v.validation_errors:
            v.validation_errors = [{"message": res.get("error", "apply failed"), "file": None, "line": None,
                                    "object": None, "suggestion": "The previous configuration was kept/restored."}]
        audit(db, ctx, "config.apply", entity_type="config_version", entity_id=v.id, entity_name=f"v{v.id}",
              result="failure", detail=res.get("error"))
    db.commit()
    return v


def run_pipeline(db: Session, ctx: AuditContext, summary: str, apply: bool, **kw) -> ConfigurationVersion:
    with config_lock(db):
        v = generate_version(db, ctx, summary, **kw)
        if v.status == "validation_failed":
            return v
        if not apply:
            return validate_version(db, ctx, v)
        return apply_version(db, ctx, v)


def rollback_to(db: Session, ctx: AuditContext, target: ConfigurationVersion) -> ConfigurationVersion:
    if not target.snapshot:
        raise ValueError("this version has no snapshot to roll back to")
    with config_lock(db):
        counts = restore_snapshot(db, target.snapshot)
        db.execute(update(Server).where(Server.deleted_token == 0, Server.config_state == "applied")
                   .values(config_state="pending"))
        audit(db, ctx, "config.rollback", entity_type="config_version", entity_id=target.id,
              entity_name=f"v{target.id}", new={"restored_rows": counts})
        record_change(db, ctx, "config_version", target.id, f"v{target.id}", "rollback",
                      new={"restored_rows": counts})
        db.flush()
        v = generate_version(db, ctx, f"Rollback to version {target.id}", rollback_of=target.id)
        if v.status == "validation_failed":
            # database now reflects version N; it stays as pending changes until fixed
            return v
        v = apply_version(db, ctx, v)
        if v.status != "applied":
            log.warning("rollback to v%s failed to apply; database restored rows remain pending", target.id)
        return v


def diff_versions(db: Session, a: ConfigurationVersion, b: ConfigurationVersion) -> list[dict]:
    fa = {f.path: f.content for f in db.scalars(select(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id == a.id))}
    fb = {f.path: f.content for f in db.scalars(select(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id == b.id))}
    out = []
    for path in sorted(set(fa) | set(fb)):
        if fa.get(path) == fb.get(path):
            continue
        status = "added" if path not in fa else "removed" if path not in fb else "modified"
        diff = "".join(difflib.unified_diff(
            (fa.get(path) or "").splitlines(keepends=True), (fb.get(path) or "").splitlines(keepends=True),
            fromfile=f"v{a.id}/{path}", tofile=f"v{b.id}/{path}", n=3))
        out.append({"path": path, "status": status, "diff": diff})
    return out
