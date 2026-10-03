"""Companies and locations (Super Admin managed).

Super Admin sees and manages all of them. Other users get only the companies assigned
to them, and either their assigned locations or (if not limited by site) every active location.
Neither is ever hard-deleted (configuration snapshots reference them): retire with is_active=false.
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import validators as V
from ...audit import audit
from ...db import get_db
from ...models import Company, Location, Server, UserCompany, UserLocation
from ..deps import Principal, ctx_from, require
from ..errors import ApiError
from ..util import iso, ok

router = APIRouter(tags=["organisation"])
CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,15}$")


class OrgIn(BaseModel):
    name: str
    code: str
    description: Optional[str] = None
    is_active: bool = True

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        v = V.check_free_text(v, "name", 120, required=True)
        if len(v) < 2:
            raise ValueError("at least 2 characters")
        return v

    @field_validator("code")
    @classmethod
    def _c(cls, v):
        v = (v or "").strip().upper()
        if not CODE_RE.match(v):
            raise ValueError("2-16 characters: letters, digits, '-' or '_'")
        return v

    @field_validator("description")
    @classmethod
    def _d(cls, v):
        return V.check_free_text(v, "description", 255)


def _counts(db: Session, col) -> dict:
    return dict(db.execute(select(col, func.count()).where(Server.deleted_token == 0).group_by(col)).all())


def _payload(o, servers: int = 0, users: int | None = None) -> dict:
    d = {"id": o.id, "name": o.name, "code": o.code, "description": o.description, "is_active": o.is_active,
         "servers": servers, "created_at": iso(o.created_at), "updated_at": iso(o.updated_at)}
    if users is not None:
        d["users"] = users
    return d


def _write(db: Session, request: Request, principal: Principal, model, kind: str, body: OrgIn, obj=None, max_name=120):
    if len(body.name) > max_name:
        raise ApiError(422, "validation_error", f"Name is longer than {max_name} characters",
                       [{"field": "name", "message": "too long"}])
    for field in ("name", "code"):
        clash = db.scalar(select(model).where(getattr(model, field) == getattr(body, field)))
        if clash is not None and (obj is None or clash.id != obj.id):
            raise ApiError(409, "conflict", f"A {kind} with this {field} already exists")
    ctx = ctx_from(request, principal)
    creating = obj is None
    old = None if creating else _payload(obj)
    if creating:
        obj = model(created_by=ctx.user_id)
        db.add(obj)
    obj.name, obj.code, obj.description, obj.is_active = body.name, body.code, body.description, body.is_active
    obj.updated_by = ctx.user_id
    db.flush()
    audit(db, ctx, f"{kind}.{'create' if creating else 'update'}", entity_type=kind, entity_id=obj.id,
          entity_name=obj.name, old=old, new=_payload(obj))
    db.commit()
    return obj


# --------------------------------------------------------------- companies --
@router.get("/api/companies")
def list_companies(principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    """Super Admin: every company with server and user counts. Others: only their own active companies."""
    if not principal.is_super:
        mine = [c for c in principal.user.companies if c.is_active]
        return ok([{"id": c.id, "name": c.name, "code": c.code, "is_active": True} for c in mine])
    counts = _counts(db, Server.company_id)
    users = dict(db.execute(select(UserCompany.company_id, func.count()).group_by(UserCompany.company_id)).all())
    rows = db.scalars(select(Company).order_by(Company.is_active.desc(), Company.name))
    return ok([_payload(c, counts.get(c.id, 0), users.get(c.id, 0)) for c in rows],
              {"unassigned_servers": counts.get(None, 0)})


@router.post("/api/companies", status_code=201)
def create_company(body: OrgIn, request: Request, principal: Principal = Depends(require("companies.manage")),
                   db: Session = Depends(get_db)):
    return ok(_payload(_write(db, request, principal, Company, "company", body)))


@router.put("/api/companies/{cid}")
def update_company(cid: int, body: OrgIn, request: Request, principal: Principal = Depends(require("companies.manage")),
                   db: Session = Depends(get_db)):
    c = db.get(Company, cid)
    if c is None:
        raise ApiError(404, "not_found", "company not found")
    c = _write(db, request, principal, Company, "company", body, c)
    return ok(_payload(c, _counts(db, Server.company_id).get(c.id, 0)))


# --------------------------------------------------------------- locations --
@router.get("/api/locations")
def list_locations(principal: Principal = Depends(require("servers.view")), db: Session = Depends(get_db)):
    """Super Admin: all locations with server and user counts.
    Others: their assigned locations, or every active location when they are not limited by site."""
    if not principal.is_super:
        mine = [l for l in principal.user.locations if l.is_active] if principal.user.locations else \
            list(db.scalars(select(Location).where(Location.is_active.is_(True)).order_by(Location.name)))
        return ok([{"id": l.id, "name": l.name, "code": l.code, "is_active": True} for l in mine],
                  {"limited": bool(principal.user.locations)})
    counts = _counts(db, Server.location_id)
    users = dict(db.execute(select(UserLocation.location_id, func.count()).group_by(UserLocation.location_id)).all())
    rows = db.scalars(select(Location).order_by(Location.is_active.desc(), Location.name))
    return ok([_payload(l, counts.get(l.id, 0), users.get(l.id, 0)) for l in rows],
              {"unassigned_servers": counts.get(None, 0)})


@router.post("/api/locations", status_code=201)
def create_location(body: OrgIn, request: Request, principal: Principal = Depends(require("locations.manage")),
                    db: Session = Depends(get_db)):
    return ok(_payload(_write(db, request, principal, Location, "location", body, max_name=64)))


@router.put("/api/locations/{lid}")
def update_location(lid: int, body: OrgIn, request: Request, principal: Principal = Depends(require("locations.manage")),
                    db: Session = Depends(get_db)):
    loc = db.get(Location, lid)
    if loc is None:
        raise ApiError(404, "not_found", "location not found")
    loc = _write(db, request, principal, Location, "location", body, loc, max_name=64)
    return ok(_payload(loc, _counts(db, Server.location_id).get(loc.id, 0)))
