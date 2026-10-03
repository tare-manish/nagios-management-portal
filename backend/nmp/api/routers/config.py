"""Configuration pipeline: pending changes, validate, apply, versions, compare, rollback, backups, import."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...audit import audit
from ...config import get_settings
from ...db import get_db
from ...models import (ConfigBackup, ConfigurationChange, ConfigurationVersion, ConfigurationVersionFile, Server,
                       User)
from ...nagios import importer, pipeline, privileged
from ...nagios.legacy import load_legacy
from ..deps import Principal, ctx_from, require
from .. import scope
from ..errors import ApiError
from ..util import iso, ok, paginate

router = APIRouter(prefix="/api/config", tags=["configuration"])
backups_router = APIRouter(prefix="/api/backups", tags=["backups"])
import_router = APIRouter(prefix="/api/import", tags=["import"])


def _username(db: Session, uid: int | None) -> str | None:
    if not uid:
        return None
    u = db.get(User, uid)
    return u.username if u else None


def version_payload(v: ConfigurationVersion, db: Session | None = None, detail: bool = False) -> dict:
    d = {
        "id": v.id, "created_at": iso(v.created_at), "summary": v.summary, "status": v.status,
        "config_hash": v.config_hash, "applied_at": iso(v.applied_at), "rollback_of_version": v.rollback_of_version,
        "backup_id": v.backup_id, "errors": v.validation_errors or [], "warnings": v.validation_warnings or [],
        "steps": v.apply_log or [],
    }
    if db is not None:
        d["created_by"] = _username(db, v.created_by)
        d["applied_by"] = _username(db, v.applied_by)
        d["change_count"] = db.scalar(select(func.count()).select_from(ConfigurationChange)
                                      .where(ConfigurationChange.version_id == v.id)) or 0
    if detail:
        d["validation_output"] = v.validation_output
        d["legacy_overrides"] = v.legacy_overrides
    return d


def _redact(items: list, hidden: set[str]) -> list:
    """Drop validation messages that mention hosts outside the user's locations."""
    if not hidden:
        return items
    out = []
    for it in items:
        text_ = " ".join(str(v) for v in (it.values() if isinstance(it, dict) else [it]))
        if not any(h and h in text_ for h in hidden):
            out.append(it)
    return out


def version_view(v: ConfigurationVersion, db: Session | None, p: Principal, detail: bool = False) -> dict:
    """version_payload limited to what a company-scoped user may see (Super Admin: everything)."""
    d = version_payload(v, db, detail)
    if p.is_super:
        return d
    from sqlalchemy.orm import object_session
    sess = db or object_session(v)
    allowed = scope.hostnames(sess, p) or set()
    hidden = set(sess.scalars(select(Server.hostname))) - allowed
    d["errors"] = _redact(d["errors"], hidden)
    d["warnings"] = _redact(d["warnings"], hidden)
    d.pop("validation_output", None)
    d.pop("legacy_overrides", None)
    if v.created_by != p.user.id:
        d["summary"] = "Configuration change (another company or Super Admin)"
    return d


def change_payload(c: ConfigurationChange, db: Session) -> dict:
    return {"id": c.id, "time": iso(c.created_at), "entity_type": c.entity_type, "entity_id": c.entity_id,
            "entity_name": c.entity_name, "action": c.action, "old": c.old_value, "new": c.new_value,
            "user": _username(db, c.user_id), "version_id": c.version_id}


class RunIn(BaseModel):
    summary: str | None = Field(None, max_length=200)


# ------------------------------------------------------------ pipeline --
@router.get("/pending")
def pending(principal: Principal = Depends(require("config.view")), db: Session = Depends(get_db)):
    changes, others = scope.split_pending(db, principal, pipeline.pending_changes(db))
    applied = db.scalar(select(ConfigurationVersion).where(ConfigurationVersion.status == "applied")
                        .order_by(ConfigurationVersion.id.desc()))
    dstmt = select(func.count()).select_from(Server).where(Server.deleted_token == 0, Server.config_state == "draft")
    cond = scope.server_filter(principal)
    if cond is not None:
        dstmt = dstmt.where(cond)
    drafts = db.scalar(dstmt) or 0
    return ok({"changes": [change_payload(c, db) for c in changes], "count": len(changes),
               "other_changes": len(others), "can_apply": principal.is_super or not others,
               "current_version": version_view(applied, db, principal) if applied else None, "drafts": drafts})


def _summary(db: Session, body: RunIn | None) -> str:
    if body and body.summary:
        from ... import validators as V
        return V.check_free_text(body.summary, "summary", 200) or "Configuration change"
    changes = pipeline.pending_changes(db)
    if not changes:
        return "Regenerate configuration"
    parts = [f"{c.action} {c.entity_type.replace('_', ' ')} {c.entity_name}" for c in changes[:3]]
    more = f" (+{len(changes) - 3} more)" if len(changes) > 3 else ""
    return ("; ".join(parts) + more)[:255]


@router.post("/validate")
def validate(request: Request, body: RunIn | None = None, principal: Principal = Depends(require("config.validate")),
             db: Session = Depends(get_db)):
    scope.assert_can_run_pipeline(db, principal)
    try:
        v = pipeline.run_pipeline(db, ctx_from(request, principal), _summary(db, body), apply=False)
    except pipeline.PipelineBusy as exc:
        raise ApiError(409, "busy", str(exc))
    return ok(version_view(v, db, principal, detail=True))


@router.post("/apply")
def apply(request: Request, body: RunIn | None = None, principal: Principal = Depends(require("config.apply")),
          db: Session = Depends(get_db)):
    scope.assert_can_run_pipeline(db, principal)
    try:
        v = pipeline.run_pipeline(db, ctx_from(request, principal), _summary(db, body), apply=True)
    except pipeline.PipelineBusy as exc:
        raise ApiError(409, "busy", str(exc))
    return ok(version_view(v, db, principal, detail=True))


# ------------------------------------------------------------ versions --
@router.get("/versions")
def versions(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
             status: str | None = Query(None, max_length=30),
             principal: Principal = Depends(require("config.view")), db: Session = Depends(get_db)):
    stmt = select(ConfigurationVersion).order_by(ConfigurationVersion.id.desc())
    if not principal.is_super:  # company-scoped users see the versions they generated themselves
        stmt = stmt.where(ConfigurationVersion.created_by == principal.user.id)
    if status:
        stmt = stmt.where(ConfigurationVersion.status == status)
    rows = list(db.scalars(stmt))
    items, meta = paginate(rows, page, page_size)
    return ok([version_view(v, db, principal) for v in items], meta)


def _version(db: Session, vid: int, p: Principal | None = None) -> ConfigurationVersion:
    v = db.get(ConfigurationVersion, vid)
    if v is None or (p is not None and not p.is_super and v.created_by != p.user.id):
        raise ApiError(404, "not_found", "version not found")
    return v


@router.get("/versions/{vid}")
def version_detail(vid: int, principal: Principal = Depends(require("config.view")), db: Session = Depends(get_db)):
    v = _version(db, vid, principal)
    d = version_view(v, db, principal, detail=True)
    d["changes"] = [change_payload(c, db) for c in db.scalars(
        select(ConfigurationChange).where(ConfigurationChange.version_id == v.id).order_by(ConfigurationChange.id))
        if scope.change_in_scope(db, principal, c.entity_type, c.entity_id)]
    # generated files contain every site's configuration: Super Admin only
    d["files"] = [{"path": f.path, "sha256": f.sha256, "size": len(f.content)} for f in db.scalars(
        select(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id == v.id)
        .order_by(ConfigurationVersionFile.path))] if principal.is_super else []
    if v.backup_id:
        b = db.get(ConfigBackup, v.backup_id)
        d["backup"] = {"id": b.id, "name": b.name} if b else None
    return ok(d)


@router.get("/versions/{vid}/file")
def version_file(vid: int, path: str = Query(..., max_length=300), principal: Principal = Depends(require("config.view")),
                 db: Session = Depends(get_db)):
    scope.require_super(principal)
    f = db.scalar(select(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id == vid,
                                                         ConfigurationVersionFile.path == path))
    if f is None:
        raise ApiError(404, "not_found", "file not found in this version")
    return ok({"path": f.path, "content": f.content, "sha256": f.sha256})


@router.get("/versions/{a}/diff/{b}")
def version_diff(a: int, b: int, principal: Principal = Depends(require("config.view")), db: Session = Depends(get_db)):
    scope.require_super(principal)
    va, vb = _version(db, a), _version(db, b)
    return ok({"from": a, "to": b, "files": pipeline.diff_versions(db, va, vb)})


@router.get("/versions/{vid}/download")
def version_download(vid: int, request: Request, principal: Principal = Depends(require("config.view")),
                     db: Session = Depends(get_db)):
    scope.require_super(principal)
    v = _version(db, vid)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in db.scalars(select(ConfigurationVersionFile).where(ConfigurationVersionFile.version_id == v.id)):
            name = f.path.replace("override:", "overrides").replace("//", "/")
            zf.writestr(name, f.content)
        zf.writestr("VERSION.txt", f"Version {v.id}\nStatus: {v.status}\nSummary: {v.summary}\n"
                                   f"Created: {iso(v.created_at)}\nHash: {v.config_hash}\n"
                                   "Agent credentials are never included in downloads.\n")
    audit(db, ctx_from(request, principal), "config.download", entity_type="config_version", entity_id=v.id,
          entity_name=f"v{v.id}")
    db.commit()
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="nagios-config-v{v.id}.zip"'})


@router.post("/versions/{vid}/apply")
def apply_existing(vid: int, request: Request, principal: Principal = Depends(require("config.apply")),
                   db: Session = Depends(get_db)):
    v = _version(db, vid, principal)
    scope.assert_can_run_pipeline(db, principal)
    latest = db.scalar(select(func.max(ConfigurationVersion.id)))
    if v.id != latest:
        raise ApiError(409, "stale_version", "Only the most recent generated version can be applied. Generate a new one.")
    if v.status not in ("generated", "validated"):
        raise ApiError(409, "invalid_state", f"Version is '{v.status}' and cannot be applied")
    with pipeline.config_lock(db):
        v = pipeline.apply_version(db, ctx_from(request, principal), v)
    return ok(version_view(v, db, principal, detail=True))


@router.post("/versions/{vid}/rollback")
def rollback(vid: int, request: Request, principal: Principal = Depends(require("config.rollback")),
             db: Session = Depends(get_db)):
    v = _version(db, vid)
    if v.status not in ("applied", "superseded", "rolled_back"):
        raise ApiError(409, "invalid_state", "Only versions that were applied can be rolled back to")
    try:
        nv = pipeline.rollback_to(db, ctx_from(request, principal), v)
    except pipeline.PipelineBusy as exc:
        raise ApiError(409, "busy", str(exc))
    except ValueError as exc:
        raise ApiError(409, "invalid_state", str(exc))
    return ok(version_payload(nv, db, detail=True))


# ------------------------------------------------------------- backups --
def backup_payload(b: ConfigBackup, db: Session) -> dict:
    return {"id": b.id, "name": b.name, "created_at": iso(b.created_at), "reason": b.reason,
            "size_bytes": b.size_bytes, "sha256": b.sha256, "version_id": b.version_id,
            "created_by": _username(db, b.created_by), "files": b.files or []}


@backups_router.get("")
def list_backups(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
                 principal: Principal = Depends(require("backups.manage")), db: Session = Depends(get_db)):
    rows = list(db.scalars(select(ConfigBackup).order_by(ConfigBackup.id.desc())))
    items, meta = paginate(rows, page, page_size)
    return ok([backup_payload(b, db) for b in items], meta)


@backups_router.post("", status_code=201)
def create_backup(request: Request, principal: Principal = Depends(require("backups.manage")),
                  db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    try:
        res = privileged.run("backup", "manual")
    except privileged.PrivilegedError as exc:
        raise ApiError(502, "privileged_error", str(exc))
    if not res.get("ok"):
        raise ApiError(502, "backup_failed", res.get("error", "backup failed"))
    meta = res["backup"]
    b = ConfigBackup(name=meta["name"], created_by=ctx.user_id, reason="manual", size_bytes=meta.get("size_bytes", 0),
                     sha256=meta.get("sha256"), files=[x["target"] for x in meta.get("legacy", [])])
    db.add(b)
    audit(db, ctx, "backup.create", entity_type="backup", entity_name=b.name)
    db.commit()
    return ok(backup_payload(b, db))


@backups_router.get("/{bid}/download")
def download_backup(bid: int, request: Request, principal: Principal = Depends(require("backups.manage")),
                    db: Session = Depends(get_db)):
    b = db.get(ConfigBackup, bid)
    if b is None:
        raise ApiError(404, "not_found", "backup not found")
    path = Path(get_settings().backup_dir) / f"{b.name}.tar.gz"
    if not path.is_file() or path.is_symlink():
        raise ApiError(404, "not_found", "backup archive no longer exists on disk")
    audit(db, ctx_from(request, principal), "backup.download", entity_type="backup", entity_id=b.id, entity_name=b.name)
    db.commit()
    return FileResponse(path, media_type="application/gzip", filename=f"{b.name}.tar.gz")


@backups_router.post("/{bid}/restore")
def restore_backup(bid: int, request: Request, principal: Principal = Depends(require("backups.manage", "config.rollback")),
                   db: Session = Depends(get_db)):
    """Emergency file-level restore (does not change the database - portal shows drift afterwards)."""
    b = db.get(ConfigBackup, bid)
    if b is None:
        raise ApiError(404, "not_found", "backup not found")
    ctx = ctx_from(request, principal)
    try:
        res = privileged.run("rollback", b.name)
    except privileged.PrivilegedError as exc:
        raise ApiError(502, "privileged_error", str(exc))
    audit(db, ctx, "backup.restore", entity_type="backup", entity_id=b.id, entity_name=b.name,
          result="success" if res.get("ok") else "failure", detail=res.get("error"))
    if res.get("backup"):
        meta = res["backup"]
        db.add(ConfigBackup(name=meta["name"], created_by=ctx.user_id, reason=meta.get("reason", "pre-restore"),
                            size_bytes=meta.get("size_bytes", 0), sha256=meta.get("sha256")))
    db.commit()
    return ok({"ok": res.get("ok", False), "error": res.get("error"), "steps": res.get("steps", []),
               "validation": res.get("validation")})


# -------------------------------------------------------------- import --
class ImportSelection(BaseModel):
    hostname: str = Field(max_length=64)
    environment: Literal["production", "uat", "development", "dr", "test"] = "production"
    os_type: Literal["windows", "linux", "unix", "network", "other"] | None = None
    location: str | None = Field(None, max_length=120)


class ImportIn(BaseModel):
    mode: Literal["takeover", "readonly"] = "takeover"
    hosts: list[ImportSelection] = Field(min_length=1, max_length=500)
    apply: bool = True


@import_router.get("/scan")
def scan(principal: Principal = Depends(require("config.import")), db: Session = Depends(get_db)):
    legacy = load_legacy()
    plans = importer.plan_imports(db, legacy)
    return ok({"hosts": [p.as_dict() for p in plans], "errors": legacy.errors,
               "files": sorted(legacy.files), "object_count": len(legacy.objects)})


@import_router.post("")
def run_import(body: ImportIn, request: Request, principal: Principal = Depends(require("config.import")),
               db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    try:
        servers, overrides = importer.import_hosts(db, ctx, [h.model_dump() for h in body.hosts], body.mode)
    except ValueError as exc:
        db.rollback()
        raise ApiError(422, "import_error", str(exc))
    names = [s.hostname for s in servers]
    if body.mode == "readonly":
        db.commit()
        return ok({"imported": names, "mode": body.mode, "version": None})
    if not principal.has("config.apply") and body.apply:
        db.rollback()
        raise ApiError(403, "forbidden", "Taking over hosts requires the config.apply permission")
    db.commit()
    try:
        v = pipeline.run_pipeline(db, ctx, f"Import (take over) {', '.join(names)[:200]}", apply=body.apply,
                                  overrides=overrides, takeover_hosts=set(names))
    except pipeline.PipelineBusy as exc:
        v = None
        err = str(exc)
    else:
        err = None
    success = v is not None and (v.status == "applied" or (not body.apply and v.status == "validated"))
    if not success or not body.apply:
        # never leave half-imported hosts behind: remove them so the manual config stays authoritative
        for s in servers:
            db.delete(db.get(Server, s.id))
        db.execute(ConfigurationChange.__table__.delete().where(
            ConfigurationChange.version_id.is_(None), ConfigurationChange.action == "import_takeover"))
        audit(db, ctx, "server.import_takeover", entity_name=", ".join(names)[:190],
              result="success" if success else "failure",
              detail="validation only - nothing imported" if success else (err or "validation/apply failed - import reverted"))
        db.commit()
    return ok({"imported": names if success and body.apply else [], "mode": body.mode,
               "version": version_payload(v, db, detail=True) if v else None, "error": err})
