"""Response helpers."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Iterable

from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .errors import ApiError


def ok(data: Any = None, meta: dict | None = None) -> dict:
    body: dict = {"data": data}
    if meta is not None:
        body["meta"] = meta
    return body


def paginate(items: list, page: int, page_size: int) -> tuple[list, dict]:
    page = max(1, page)
    page_size = max(1, min(500, page_size))
    total = len(items)
    start = (page - 1) * page_size
    return items[start:start + page_size], {"total": total, "page": page, "page_size": page_size,
                                            "pages": (total + page_size - 1) // page_size}


def get_or_404(db: Session, model, obj_id: int, what: str = "object"):
    obj = db.get(model, obj_id)
    if obj is None or getattr(obj, "deleted_token", 0):
        raise ApiError(404, "not_found", f"{what} not found")
    return obj


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat() + ("Z" if dt.tzinfo is None else "")


def ts_iso(ts: int | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def csv_response(filename: str, header: list[str], rows: Iterable[list]) -> StreamingResponse:
    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        yield buf.getvalue()
        for r in rows:
            buf.seek(0)
            buf.truncate()
            # neutralise spreadsheet formula injection
            w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in r])
            yield buf.getvalue()

    return StreamingResponse(gen(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})
