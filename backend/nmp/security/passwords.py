"""Password hashing (Argon2id) and password policy."""
from __future__ import annotations

import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from ..config import get_settings

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Pre-computed hash used to equalise timing for unknown usernames.
_DUMMY_HASH = _hasher.hash("nmp-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def password_policy_errors(password: str, username: str | None = None) -> list[str]:
    errs: list[str] = []
    min_len = get_settings().password_min_length
    if len(password) < min_len:
        errs.append(f"Password must be at least {min_len} characters.")
    if len(password) > 256:
        errs.append("Password is too long.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes < 3:
        errs.append("Password must contain at least 3 of: lowercase, uppercase, digit, symbol.")
    if username and username.lower() in password.lower():
        errs.append("Password must not contain the username.")
    return errs
