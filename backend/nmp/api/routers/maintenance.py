"""Super Admin data cleanup: preview and purge junk / stale portal data."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from ... import maintenance
from ...audit import audit
from ...db import get_db
from ...nagios.pipeline import PipelineBusy, config_lock
from ..deps import Principal, ctx_from, require
from ..errors import ApiError
from ..util import ok

router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])
CONFIRM_WORD = "DELETE"


def require_super_admin(request: Request, principal: Principal = Depends(require("maintenance.cleanup")),
                        db: Session = Depends(get_db)) -> Principal:
    """The permission alone is not enough: the user must hold the Super Admin role itself."""
    if "super_admin" not in principal.role_names:
        audit(db, ctx_from(request, principal), "access.denied", result="denied",
              detail=f"{request.method} {request.url.path} needs the Super Admin role")
        db.commit()
        raise ApiError(403, "forbidden", "Data cleanup is restricted to Super Admins")
    return principal


class CleanupItem(BaseModel):
    category: str
    older_than_days: int = Field(0, ge=0, le=3650)

    @field_validator("category")
    @classmethod
    def _c(cls, v):
        if v not in maintenance.CATEGORY_MAP:
            raise ValueError("unknown category")
        return v


class CleanupIn(BaseModel):
    items: list[CleanupItem] = Field(min_length=1, max_length=len(maintenance.CATEGORIES))
    confirm: str = Field("", max_length=16)

    def as_map(self) -> dict[str, int]:
        return {i.category: i.older_than_days for i in self.items}


@router.get("/cleanup/categories")
def categories(principal: Principal = Depends(require_super_admin), db: Session = Depends(get_db)):
    return ok(maintenance.category_payload(db))


@router.post("/cleanup/preview")
def preview(body: CleanupIn, principal: Principal = Depends(require_super_admin), db: Session = Depends(get_db)):
    res = maintenance.run_cleanup(db, body.as_map(), execute=False)
    db.rollback()
    return ok({"results": res, "total": sum(r["count"] for r in res.values())})


@router.post("/cleanup")
def cleanup(body: CleanupIn, request: Request, principal: Principal = Depends(require_super_admin),
            db: Session = Depends(get_db)):
    ctx = ctx_from(request, principal)
    if body.confirm != CONFIRM_WORD:
        raise ApiError(422, "confirmation_required", f"Type {CONFIRM_WORD} to confirm the cleanup",
                       [{"field": "confirm", "message": f"must be {CONFIRM_WORD}"}])
    try:
        with config_lock(db):   # never runs at the same time as validate / apply / rollback
            res = maintenance.run_cleanup(db, body.as_map(), execute=True)
    except PipelineBusy as exc:
        raise ApiError(409, "busy", str(exc))
    total = sum(r["count"] for r in res.values())
    errors = sum(len(r["errors"]) for r in res.values())
    summary = {k: {kk: vv for kk, vv in v.items() if kk in ("count", "older_than_days", "protected", "errors")}
               for k, v in res.items()}
    audit(db, ctx, "maintenance.cleanup", entity_type="maintenance", entity_name="data-cleanup", new=summary,
          result="success" if not errors else "failure", detail=f"removed {total} item(s), {errors} error(s)")
    db.commit()
    return ok({"results": res, "total": total, "errors": errors})
