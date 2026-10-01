"""Server-side sessions with CSRF tokens and rate limiting.

Why server-side sessions rather than JWT: an infrastructure admin portal
needs instant revocation (logout, disable user, role change), idle timeout
and a server-side record of active sessions. The browser only holds an
opaque random token in an HttpOnly/Secure/SameSite=Strict cookie; the DB
stores its SHA-256 hash.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import utcnow
from ..models import RateLimitBucket, User, UserSession

SESSION_COOKIE = "nmp_session"
CSRF_COOKIE = "nmp_csrf"
CSRF_HEADER = "x-csrf-token"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User, ip: str | None, user_agent: str | None) -> tuple[str, str]:
    s = get_settings()
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(UserSession(
        id=_hash(token), user_id=user.id, csrf_token=csrf, created_at=now, last_seen_at=now,
        expires_at=now + timedelta(hours=s.session_absolute_hours),
        ip_address=(ip or "")[:45], user_agent=(user_agent or "")[:255],
    ))
    return token, csrf


def load_session(db: Session, token: str | None) -> tuple[UserSession, User] | None:
    if not token or len(token) > 200:
        return None
    s = get_settings()
    sess = db.get(UserSession, _hash(token))
    if sess is None or sess.revoked:
        return None
    now = utcnow()
    if sess.expires_at <= now or sess.last_seen_at + timedelta(minutes=s.session_idle_minutes) <= now:
        sess.revoked = True
        db.commit()
        return None
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        return None
    # throttle last_seen writes to once per minute
    if (now - sess.last_seen_at).total_seconds() >= 60:
        sess.last_seen_at = now
        db.commit()
    return sess, user


def revoke_session(db: Session, token: str | None) -> None:
    if not token:
        return
    sess = db.get(UserSession, _hash(token))
    if sess:
        sess.revoked = True


def revoke_user_sessions(db: Session, user_id: int, except_id: str | None = None) -> None:
    for sess in db.scalars(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked.is_(False))):
        if sess.id != except_id:
            sess.revoked = True


def purge_expired_sessions(db: Session) -> int:
    cutoff = utcnow() - timedelta(days=7)
    res = db.execute(delete(UserSession).where(UserSession.expires_at < cutoff))
    return res.rowcount or 0


def csrf_valid(session: UserSession, header_value: str | None) -> bool:
    return bool(header_value) and hmac.compare_digest(session.csrf_token, header_value)


# ------------------------------------------------------------- rate limits --
def db_rate_hit(db: Session, key: str, window_seconds: int) -> int:
    """Increment a fixed-window counter stored in MariaDB (shared across workers)."""
    now = utcnow()
    b = db.get(RateLimitBucket, key)
    if b is None:
        b = RateLimitBucket(bucket_key=key, window_start=now, hits=0)
        db.add(b)
    elif (now - b.window_start).total_seconds() >= window_seconds:
        b.window_start = now
        b.hits = 0
    b.hits += 1
    db.flush()
    return b.hits


def db_rate_count(db: Session, key: str, window_seconds: int) -> int:
    b = db.get(RateLimitBucket, key)
    if b is None or (utcnow() - b.window_start).total_seconds() >= window_seconds:
        return 0
    return b.hits


def db_rate_reset(db: Session, key: str) -> None:
    b = db.get(RateLimitBucket, key)
    if b is not None:
        db.delete(b)


class SlidingWindowLimiter:
    """In-process limiter for general API traffic (per client key)."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10000:  # bound memory
                for k in list(self._hits)[:5000]:
                    if not self._hits[k]:
                        del self._hits[k]
            return True
