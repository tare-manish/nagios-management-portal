"""Authentication: login / logout / current user / change password."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audit import AuditContext, audit
from ...config import get_settings
from ...db import get_db, utcnow
from ...models import User
from ...security import passwords
from ...security.sessions import (CSRF_COOKIE, SESSION_COOKIE, create_session, db_rate_count, db_rate_hit,
                                  db_rate_reset, revoke_session, revoke_user_sessions)
from ..deps import Principal, client_ip, get_principal, user_permissions
from ..errors import ApiError
from ..util import iso, ok

router = APIRouter(prefix="/api/auth", tags=["auth"])
seclog = logging.getLogger("nmp.security")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


def user_payload(user: User) -> dict:
    return {
        "id": user.id, "username": user.username, "full_name": user.full_name, "email": user.email,
        "roles": [{"name": r.name, "display_name": r.display_name} for r in user.roles],
        "permissions": sorted(user_permissions(user)), "must_change_password": user.must_change_password,
        "last_login_at": iso(user.last_login_at),
    }


def _set_cookies(response: Response, token: str, csrf: str) -> None:
    s = get_settings()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=s.cookie_secure, samesite="strict", path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=s.cookie_secure, samesite="strict", path="/")


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request)
    uname = body.username.strip().lower()
    window = s.login_lockout_minutes * 60
    ctx = AuditContext(None, uname, ip, request.headers.get("user-agent"))
    # per-IP throttle (protects against password spraying across usernames)
    if db_rate_count(db, f"login-ip:{ip}", window) >= s.login_max_failures * 4:
        audit(db, ctx, "auth.login", result="denied", detail="rate limited (ip)")
        db.commit()
        raise ApiError(429, "rate_limited", "Too many failed login attempts. Try again later.")
    user = db.scalar(select(User).where(User.username == uname))
    now = utcnow()
    if user and user.locked_until and user.locked_until > now:
        passwords.verify_password(None, body.password)  # equalise timing
        audit(db, ctx, "auth.login", entity_type="user", entity_id=user.id, entity_name=uname, result="denied",
              detail="account locked")
        db.commit()
        raise ApiError(423, "account_locked", "Account temporarily locked after repeated failed logins.")
    valid = passwords.verify_password(user.password_hash if user else None, body.password)
    if not valid or not user or not user.is_active:
        db_rate_hit(db, f"login-ip:{ip}", window)
        if user:
            user.failed_logins += 1
            if user.failed_logins >= s.login_max_failures:
                from datetime import timedelta

                user.locked_until = now + timedelta(minutes=s.login_lockout_minutes)
                user.failed_logins = 0
                seclog.warning("account locked user=%s ip=%s", uname, ip)
        audit(db, ctx, "auth.login", entity_type="user", entity_id=user.id if user else None, entity_name=uname,
              result="failure", detail="invalid credentials" if (user is None or user.is_active) else "inactive user")
        seclog.warning("login failed user=%s ip=%s", uname, ip)
        db.commit()
        raise ApiError(401, "invalid_credentials", "Invalid username or password")
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    user.last_login_ip = ip
    db_rate_reset(db, f"login-ip:{ip}")
    token, csrf = create_session(db, user, ip, request.headers.get("user-agent"))
    audit(db, AuditContext(user.id, user.username, ip, request.headers.get("user-agent")), "auth.login",
          entity_type="user", entity_id=user.id, entity_name=user.username)
    seclog.info("login ok user=%s ip=%s", uname, ip)
    db.commit()
    _set_cookies(response, token, csrf)
    return ok({"user": user_payload(user), "csrf_token": csrf, "session_idle_minutes": s.session_idle_minutes})


@router.post("/logout")
def logout(request: Request, response: Response, principal: Principal = Depends(get_principal),
           db: Session = Depends(get_db)):
    revoke_session(db, request.cookies.get(SESSION_COOKIE))
    audit(db, AuditContext(principal.user.id, principal.user.username, client_ip(request), None), "auth.logout",
          entity_type="user", entity_id=principal.user.id, entity_name=principal.user.username)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return ok({"logged_out": True})


@router.get("/me")
def me(request: Request, principal: Principal = Depends(get_principal)):
    return ok({"user": user_payload(principal.user), "csrf_token": principal.session.csrf_token,
               "session_idle_minutes": get_settings().session_idle_minutes})


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, principal: Principal = Depends(get_principal),
                    db: Session = Depends(get_db)):
    user = db.get(User, principal.user.id)
    ctx = AuditContext(user.id, user.username, client_ip(request), request.headers.get("user-agent"))
    if not passwords.verify_password(user.password_hash, body.current_password):
        audit(db, ctx, "auth.change_password", entity_type="user", entity_id=user.id, result="failure",
              detail="wrong current password")
        db.commit()
        raise ApiError(400, "invalid_password", "Current password is incorrect")
    errs = passwords.password_policy_errors(body.new_password, user.username)
    if body.new_password == body.current_password:
        errs.append("New password must differ from the current password.")
    if errs:
        raise ApiError(422, "weak_password", "Password does not meet the policy",
                       [{"field": "new_password", "message": e} for e in errs])
    user.password_hash = passwords.hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    revoke_user_sessions(db, user.id, except_id=principal.session.id)
    audit(db, ctx, "auth.change_password", entity_type="user", entity_id=user.id, entity_name=user.username)
    db.commit()
    return ok({"changed": True})
