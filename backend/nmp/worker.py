"""Background worker (separate systemd service: nagios-management-worker).

Every cycle:
  * performance sampler  - perf data of new check results -> perf_samples
  * notification engine  - HARD state transitions -> rules -> providers
Hourly housekeeping: retention of perf samples, sessions, notifications.
"""
from __future__ import annotations

import logging
import signal
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, insert, select

from .db import SessionLocal, utcnow
from .logging_setup import setup_logging
from .models import (Notification, PerfSample, RateLimitBucket, Server, SystemSetting, UserSession,
                     WorkerHeartbeat)
from .nagios.status import get_status, parse_perfdata
from .notifications.engine import detect_events, dispatch

log = logging.getLogger("nmp.worker")
_stop = False


def _handle(sig, frame):  # pragma: no cover
    global _stop
    _stop = True


class Worker:
    def __init__(self, interval: int = 30):
        self.interval = interval
        self.watermark: dict[tuple[str, str], int] = {}
        self.last_housekeeping = 0.0
        self.started = int(time.time()) - 600

    def sample_perf(self, db, snap) -> int:
        servers = {s.hostname: s for s in db.scalars(select(Server).where(Server.deleted_token == 0))}
        rows = []
        for (host, desc), sv in snap.services.items():
            srv = servers.get(host)
            if srv is None or not sv.get("has_been_checked"):
                continue
            last = int(sv.get("last_check") or 0)
            key = (host, desc)
            if last <= self.watermark.get(key, self.started):
                continue
            self.watermark[key] = last
            ss = next((x for x in srv.services if x.service_description == desc), None)
            category = ss.service.category if ss else None
            ts = datetime.fromtimestamp(last, tz=timezone.utc).replace(tzinfo=None)
            for p in parse_perfdata(sv.get("performance_data"))[:20]:
                rows.append({"server_id": srv.id, "service_description": desc[:100], "category": category,
                             "label": p["label"], "value": p["value"], "uom": p["uom"] or None, "warn": p["warn"],
                             "crit": p["crit"], "sampled_at": ts})
        if rows:
            dialect = db.bind.dialect.name
            stmt = insert(PerfSample)
            stmt = stmt.prefix_with("IGNORE") if dialect in ("mysql", "mariadb") else stmt.prefix_with("OR IGNORE")
            for i in range(0, len(rows), 500):
                db.execute(stmt, rows[i:i + 500])
        return len(rows)

    def housekeeping(self, db) -> None:
        s = db.get(SystemSetting, "perf_retention_days")
        days = int(s.value) if s else 90
        now = utcnow()
        n = db.execute(delete(PerfSample).where(PerfSample.sampled_at < now - timedelta(days=days))).rowcount
        db.execute(delete(UserSession).where(UserSession.expires_at < now - timedelta(days=7)))
        db.execute(delete(RateLimitBucket).where(RateLimitBucket.window_start < now - timedelta(days=1)))
        db.execute(delete(Notification).where(Notification.created_at < now - timedelta(days=180)))
        log.info("housekeeping: removed %s perf samples older than %s days", n, days)

    def cycle(self) -> dict:
        snap = get_status()
        detail: dict = {"status_error": snap.error}
        with SessionLocal() as db:
            if not snap.error:
                detail["perf_samples"] = self.sample_perf(db, snap)
                db.commit()
                events = detect_events(db, snap)
                detail["events"] = len(events)
                detail["notifications_sent"] = dispatch(db, events)
                db.commit()
            if time.time() - self.last_housekeeping > 3600:
                self.housekeeping(db)
                self.last_housekeeping = time.time()
                db.commit()
            hb = db.get(WorkerHeartbeat, "worker")
            if hb is None:
                hb = WorkerHeartbeat(name="worker", last_run_at=utcnow())
                db.add(hb)
            hb.last_run_at, hb.detail = utcnow(), detail
            db.commit()
        return detail

    def run(self) -> None:
        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
        log.info("worker started (interval %ss)", self.interval)
        while not _stop:
            t0 = time.time()
            try:
                self.cycle()
            except Exception:
                log.exception("worker cycle failed")
            while not _stop and time.time() - t0 < self.interval:
                time.sleep(1)
        log.info("worker stopped")


def main() -> None:  # pragma: no cover
    setup_logging()
    Worker().run()


if __name__ == "__main__":  # pragma: no cover
    main()
