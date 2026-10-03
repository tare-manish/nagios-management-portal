"""Request dependencies: DB session, authentication, CSRF, RBAC, audit context."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from ..audit import AuditContext
from ..db import get_db
from ..models import User, UserSession
from ..security.sessions import CSRF_HEADER, SESSION_COOKIE, csrf_valid, load_session
from .errors import ApiError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
TRUSTED_PROXIES = {"127.0.0.1", "::1"}


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if peer in TRUSTED_PROXIES:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            cand = xff.split(",")[-1].strip()
            try:
                ipaddress.ip_address(cand)
                return cand
            except ValueError:
                pass
    return peer or "unknown"


@dataclass
class Principal:
    user: User
    session: UserSession
    permissions: frozenset[str]

    def has(self, perm: str) -> bool:
        return perm in self.permissions

    @property
    def role_names(self) -> list[str]:
        return [r.name for r in self.user.roles]

    @property
    def is_super(self) -> bool:
        return "super_admin" in self.role_names

    @property
    def company_ids(self) -> frozenset[int]:
        """Companies this user may monitor. Ignored for Super Admin (sees everything)."""
        return frozenset(c.id for c in self.user.companies if c.is_active)

    @property
    def location_ids(self) -> frozenset[int]:
        """Optional site restriction within those companies (empty = every site). Ignored for Super Admin."""
        return frozenset(loc.id for loc in self.user.locations if loc.is_active)


def user_permissions(user: User) -> frozenset[str]:
    """Effective permissions. Super-Admin-only permissions count only for holders of the super_admin role."""
    from ..security.rbac import SUPER_ADMIN_ONLY

    perms: set[str] = set()
    for r in user.roles:
        perms.update(p.code for p in r.permissions)
    if not any(r.name == "super_admin" for r in user.roles):
        perms -= SUPER_ADMIN_ONLY
    return frozenset(perms)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    token = request.cookies.get(SESSION_COOKIE)
    loaded = load_session(db, token)
    if loaded is None:
        raise ApiError(401, "unauthenticated", "Authentication required")
    sess, user = loaded
    if request.method not in SAFE_METHODS:
        if not csrf_valid(sess, request.headers.get(CSRF_HEADER)):
            raise ApiError(403, "csrf_failed", "Missing or invalid CSRF token")
    principal = Principal(user=user, session=sess, permissions=user_permissions(user))
    request.state.principal = principal
    if user.must_change_password and request.url.path not in (
            "/api/auth/me", "/api/auth/change-password", "/api/auth/logout"):
        raise ApiError(403, "password_change_required", "You must change your password before continuing")
    return principal


def require(*perms: str) -> Callable[..., Principal]:
    def dep(request: Request, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Principal:
        missing = [p for p in perms if not principal.has(p)]
        if missing:
            from ..audit import audit

            audit(db, ctx_from(request, principal), "access.denied", detail=f"{request.method} {request.url.path} needs {','.join(missing)}",
                  result="denied")
            db.commit()
            raise ApiError(403, "forbidden", "You do not have permission to perform this action",
                           {"required": missing})
        return principal

    return dep


def ctx_from(request: Request, principal: Principal | None) -> AuditContext:
    return AuditContext(
        user_id=principal.user.id if principal else None,
        username=principal.user.username if principal else None,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:255],
    )


def audit_ctx(request: Request, principal: Principal = Depends(get_principal)) -> AuditContext:
    return ctx_from(request, principal)
