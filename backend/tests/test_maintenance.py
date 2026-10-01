"""Super Admin data cleanup: access control, preview, protections, execution, audit."""
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from nmp.db import SessionLocal, utcnow
from nmp.models import (AuditLog, ConfigBackup, ConfigurationChange, ConfigurationVersion, Notification, PerfSample,
                        Role, Server, UserSession)

ROOT = Path(__file__).resolve().parents[2]


def _items(*cats, days=0):
    return [{"category": c, "older_than_days": days} for c in cats]


# ------------------------------------------------------------ access control --
def test_only_super_admin_can_clean(administrator, operator, viewer, anon):
    for api in (administrator, operator, viewer):
        assert api.get("/api/maintenance/cleanup/categories").status_code == 403
        assert api.post("/api/maintenance/cleanup/preview", json={"items": _items("sessions")}).status_code == 403
        assert api.post("/api/maintenance/cleanup", json={"items": _items("sessions"), "confirm": "DELETE"}).status_code == 403
    assert anon.get("/api/maintenance/cleanup/categories").status_code == 401


def test_permission_is_super_admin_only(admin):
    with SessionLocal() as db:
        for name in ("administrator", "operator", "viewer"):
            role = db.scalar(select(Role).where(Role.name == name))
            assert "maintenance.cleanup" not in {p.code for p in role.permissions}
        sa = db.scalar(select(Role).where(Role.name == "super_admin"))
        assert "maintenance.cleanup" in {p.code for p in sa.permissions}
    # cannot be put into a custom role
    r = admin.post("/api/roles", json={"name": "cleaner", "display_name": "Cleaner",
                                       "permissions": ["dashboard.view", "maintenance.cleanup"]})
    assert r.status_code == 422, r.text


def test_categories_and_validation(admin):
    cats = admin.get("/api/maintenance/cleanup/categories").json()["data"]
    keys = {c["key"] for c in cats}
    assert {"sessions", "perf_samples", "audit_logs", "backups", "config_versions", "deleted_servers"} <= keys
    assert admin.post("/api/maintenance/cleanup/preview", json={"items": _items("bogus")}).status_code == 422
    assert admin.post("/api/maintenance/cleanup/preview", json={"items": []}).status_code == 422
    # execution needs the confirmation word
    r = admin.post("/api/maintenance/cleanup", json={"items": _items("sessions")})
    assert r.status_code == 422 and r.json()["error"]["code"] == "confirmation_required"


# ------------------------------------------------------------------- data --
_N = iter(range(1, 10000))


def _seed():
    now = utcnow()
    n = next(_N)
    with SessionLocal() as db:
        srv = Server(hostname=f"CLEAN-GONE-{n}", display_name="gone", address="10.9.9.9", environment="test",
                     os_type="linux", monitoring_method="ping", deleted_token=1000 + n,
                     deleted_at=now - timedelta(days=60))
        live = Server(hostname=f"CLEAN-LIVE-{n}", display_name="live", address="10.9.9.10", environment="test",
                      os_type="linux", monitoring_method="ping")
        db.add_all([srv, live])
        db.flush()
        db.add_all([
            PerfSample(server_id=live.id, service_description="CPU", label="old", value=1, sampled_at=now - timedelta(days=400)),
            PerfSample(server_id=live.id, service_description="CPU", label="new", value=1, sampled_at=now),
            PerfSample(server_id=srv.id, service_description="CPU", label="orphan", value=1, sampled_at=now),
            Notification(created_at=now - timedelta(days=400), object_key="x/", event_type="recovery", title="t",
                         message="m", status="sent"),
            AuditLog(occurred_at=now - timedelta(days=4000), action="test.ancient", result="success"),
            AuditLog(occurred_at=now - timedelta(days=1), action="test.recent", result="success"),
        ])
        old = now - timedelta(days=400)
        v_failed = ConfigurationVersion(summary="failed", status="validation_failed", created_at=old)
        v_super = ConfigurationVersion(summary="old superseded", status="superseded", created_at=old)
        db.add_all([v_failed, v_super])
        db.flush()
        db.add(ConfigurationChange(version_id=v_super.id, entity_type="server", entity_name="x", action="update",
                                   created_at=old))
        b_missing = ConfigBackup(name=f"20200101-000000-pre-apply-v{n}", reason="pre-apply", created_at=old)
        db.add(b_missing)
        # current live version, applied after the server was deleted
        v_live = ConfigurationVersion(summary="live", status="applied", created_at=now - timedelta(days=1),
                                      applied_at=now - timedelta(days=1))
        db.add(v_live)
        db.commit()
        return {"srv": srv.id, "live": live.id, "v_failed": v_failed.id, "v_super": v_super.id,
                "v_live": v_live.id, "b_missing": b_missing.id}


@pytest.fixture()
def seeded():
    ids = _seed()
    yield ids
    with SessionLocal() as db:   # do not leave a fake "applied" version for later test modules
        v = db.get(ConfigurationVersion, ids["v_live"])
        if v is not None:
            v.status = "superseded"
            db.commit()


def test_preview_deletes_nothing(admin, seeded):
    with SessionLocal() as db:
        before = db.scalar(select(func.count()).select_from(PerfSample))
    r = admin.post("/api/maintenance/cleanup/preview",
                   json={"items": _items("perf_samples", days=90) + _items("orphan_data", "failed_versions")})
    assert r.status_code == 200, r.text
    res = r.json()["data"]["results"]
    assert res["perf_samples"]["count"] >= 1
    assert res["orphan_data"]["detail"]["perf_samples"] >= 1
    assert res["failed_versions"]["count"] >= 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(PerfSample)) == before
        assert db.get(ConfigurationVersion, seeded["v_failed"]) is not None


def test_minimum_age_is_enforced(admin, seeded):
    r = admin.post("/api/maintenance/cleanup/preview", json={"items": _items("audit_logs", days=1)})
    assert r.json()["data"]["results"]["audit_logs"]["older_than_days"] == 30


def test_cleanup_executes_with_protections(admin, seeded):
    items = (_items("perf_samples", days=90) + _items("orphan_data", "failed_versions", "sessions")
             + _items("notifications", days=90) + _items("audit_logs", days=365)
             + _items("config_versions", days=30) + _items("backups", days=30) + _items("deleted_servers", days=30))
    r = admin.post("/api/maintenance/cleanup", json={"items": items, "confirm": "DELETE"})
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    with SessionLocal() as db:
        labels = set(db.scalars(select(PerfSample.label).where(PerfSample.server_id.in_([seeded["live"], seeded["srv"]]))))
        assert labels == {"new"}                                   # old + orphan removed, recent kept
        assert db.get(ConfigurationVersion, seeded["v_failed"]) is None
        assert db.get(ConfigurationVersion, seeded["v_live"]) is not None   # live version never deleted
        assert db.get(Server, seeded["srv"]) is None                   # purged (deletion was applied)
        assert db.get(Server, seeded["live"]) is not None
        assert db.get(ConfigBackup, seeded["b_missing"]) is None       # record without archive
        assert db.scalar(select(AuditLog).where(AuditLog.action == "test.ancient")) is None
        assert db.scalar(select(AuditLog).where(AuditLog.action == "test.recent")) is not None
        # old superseded version is within the newest-10 protection or removed; its changes never become "pending"
        assert db.scalar(select(func.count()).select_from(ConfigurationChange)
                         .where(ConfigurationChange.entity_name == "x", ConfigurationChange.version_id.is_(None))) == 0
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "maintenance.cleanup").order_by(AuditLog.id.desc()))
        assert entry is not None and entry.username == "admin"
    assert data["total"] >= 5


def test_newest_versions_are_protected(admin):
    with SessionLocal() as db:
        db.add(ConfigurationVersion(summary="newest failed", status="validation_failed",
                                    created_at=utcnow() - timedelta(days=400)))
        db.commit()
        newest = db.scalar(select(func.max(ConfigurationVersion.id)))
    admin.post("/api/maintenance/cleanup", json={"items": _items("config_versions", "failed_versions", days=7),
                                                  "confirm": "DELETE"})
    with SessionLocal() as db:
        assert db.get(ConfigurationVersion, newest) is not None


def test_recent_deleted_server_not_purged(admin):
    now = utcnow()
    with SessionLocal() as db:
        s = Server(hostname="CLEAN-RECENT-01", display_name="r", address="10.9.9.11", environment="test",
                   os_type="linux", monitoring_method="ping", deleted_token=int(time.time()) + 7,
                   deleted_at=now)   # deleted after the live version was applied -> not yet live in Nagios
        db.add(s)
        db.commit()
        sid = s.id
    admin.post("/api/maintenance/cleanup", json={"items": _items("deleted_servers", days=0), "confirm": "DELETE"})
    with SessionLocal() as db:
        assert db.get(Server, sid) is not None


# --------------------------------------------------- privileged helper rules --
def _priv():
    sys.path.insert(0, str(ROOT / "privileged"))
    from nmp_priv import common
    return common


def test_privileged_backup_delete_rules(tmp_path):
    common = _priv()
    bdir = tmp_path / "backups"
    bdir.mkdir()
    conf = {"backup_dir": str(bdir), "log_file": None}
    old = time.time() - 10 * 86400
    names = [f"2026010{i}-000000-pre-apply-v{i}" for i in range(1, 8)]   # 7 portal backups
    for n in names:
        (bdir / f"{n}.tar.gz").write_bytes(b"x")
        (bdir / f"{n}.json").write_text("{}")
        os.utime(bdir / f"{n}.tar.gz", (old, old))
    (bdir / "pre-install-20260101.tar.gz").write_bytes(b"x")
    log = common.Logger(conf)
    # oldest one can go, together with its metadata
    common.delete_backup(conf, names[0], log)
    assert not (bdir / f"{names[0]}.tar.gz").exists() and not (bdir / f"{names[0]}.json").exists()
    # the newest five are refused
    with pytest.raises(common.PipelineError):
        common.delete_backup(conf, names[-1], log)
    # installer backups and traversal never match
    for bad in ("pre-install-20260101", "../etc/passwd", "20260101-000000-x/../../y"):
        with pytest.raises(common.PipelineError):
            common.delete_backup(conf, bad, log)
    # younger than 24h is refused
    (bdir / f"{names[1]}.tar.gz").touch()
    with pytest.raises(common.PipelineError):
        common.delete_backup(conf, names[1], log)
    assert (bdir / "pre-install-20260101.tar.gz").exists()
    inst = "20250101-000000-install"
    (bdir / f"{inst}.tar.gz").write_bytes(b"x")
    os.utime(bdir / f"{inst}.tar.gz", (old, old))
    with pytest.raises(common.PipelineError, match="installation"):
        common.delete_backup(conf, inst, log)
