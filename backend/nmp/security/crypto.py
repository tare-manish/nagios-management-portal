"""Secret encryption (AES-256-GCM).

The 32-byte master key lives in /etc/nagios-management/master.key
(root:nagmgmt 0440). Ciphertext format:  v1:<base64(nonce(12) || ciphertext+tag)>
An associated-data string binds a ciphertext to its purpose, so a token
copied into another column will not decrypt.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import get_settings

PREFIX = "v1:"


class CryptoError(Exception):
    pass


def generate_key_file(path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(fd, "wb") as fh:
        fh.write(base64.b64encode(secrets.token_bytes(32)))


@lru_cache(maxsize=1)
def _key() -> bytes:
    path = get_settings().master_key_file
    try:
        raw = Path(path).read_bytes().strip()
    except OSError as exc:
        raise CryptoError(f"master key not readable: {path}") from exc
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise CryptoError("master key must be 32 bytes (base64 encoded)")
    return key


def reset_key_cache() -> None:
    _key.cache_clear()


def encrypt(plaintext: str, purpose: str) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_key()).encrypt(nonce, plaintext.encode("utf-8"), purpose.encode("utf-8"))
    return PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token: str, purpose: str) -> str:
    if not token or not token.startswith(PREFIX):
        raise CryptoError("unsupported ciphertext format")
    blob = base64.b64decode(token[len(PREFIX):])
    try:
        pt = AESGCM(_key()).decrypt(blob[:12], blob[12:], purpose.encode("utf-8"))
    except Exception as exc:  # InvalidTag
        raise CryptoError("decryption failed") from exc
    return pt.decode("utf-8")


def encrypt_json(data: dict, purpose: str) -> str:
    return encrypt(json.dumps(data, separators=(",", ":")), purpose)


def decrypt_json(token: str | None, purpose: str) -> dict:
    if not token:
        return {}
    return json.loads(decrypt(token, purpose))
