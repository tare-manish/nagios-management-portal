"""Per-version snapshots of the desired configuration (DB rows).

Rollback to version N restores these rows and regenerates, so the database
(source of truth) and Nagios stay consistent.
"""
from __future__ import annotations

import json
import zlib
from datetime import datetime

from sqlalchemy import delete, insert, select, text
from sqlalchemy.orm import Session

from ..db import Base
from ..models import SNAPSHOT_TABLES

# Catalogue-like tables are merged (rows restored/updated, extra rows kept) so that
# templates and later objects that reference them never lose their parents.
MERGE_TABLES = {"commands", "services", "server_groups", "contacts", "contact_groups"}


def _encode(v):
    if isinstance(v, datetime):
        return {"__dt__": v.isoformat()}
    if isinstance(v, bytes):
        return {"__b__": v.hex()}
    return v


def _decode(v):
    if isinstance(v, dict) and "__dt__" in v:
        return datetime.fromisoformat(v["__dt__"])
    if isinstance(v, dict) and "__b__" in v:
        return bytes.fromhex(v["__b__"])
    return v


def take_snapshot(db: Session) -> bytes:
    data = {}
    for name in SNAPSHOT_TABLES:
        table = Base.metadata.tables[name]
        rows = db.execute(select(table)).mappings().all()
        data[name] = [{k: _encode(v) for k, v in r.items()} for r in rows]
    return zlib.compress(json.dumps(data, default=str).encode("utf-8"), 6)


def load_snapshot(blob: bytes) -> dict:
    return json.loads(zlib.decompress(blob).decode("utf-8"))


def restore_snapshot(db: Session, blob: bytes) -> dict:
    data = load_snapshot(blob)
    dialect = db.bind.dialect.name if db.bind is not None else ""
    counts = {}
    if dialect in ("mysql", "mariadb"):
        db.execute(text("SET FOREIGN_KEY_CHECKS=0"))
    try:
        # replace tables: delete children first
        for name in reversed(SNAPSHOT_TABLES):
            if name in MERGE_TABLES:
                continue
            db.execute(delete(Base.metadata.tables[name]))
        for name in SNAPSHOT_TABLES:
            table = Base.metadata.tables[name]
            rows = [{k: _decode(v) for k, v in r.items() if k in table.c} for r in data.get(name, [])]
            if name in MERGE_TABLES:
                pk = [c.name for c in table.primary_key.columns]
                for r in rows:
                    cond = [table.c[k] == r[k] for k in pk]
                    exists = db.execute(select(table.c[pk[0]]).where(*cond)).first()
                    if exists:
                        db.execute(table.update().where(*cond).values(**r))
                    else:
                        db.execute(insert(table).values(**r))
            elif rows:
                db.execute(insert(table), rows)
            counts[name] = len(rows)
    finally:
        if dialect in ("mysql", "mariadb"):
            db.execute(text("SET FOREIGN_KEY_CHECKS=1"))
    return counts
