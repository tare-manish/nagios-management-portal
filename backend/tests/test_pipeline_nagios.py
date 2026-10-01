"""Integration: full configuration pipeline against a REAL Nagios Core.

Add Windows server -> NCPA -> template -> generate -> validate -> apply -> reload ->
host appears in Nagios -> services execute through the NCPA wrapper; plus modify,
disable, delete, validation failure, rollback, import/take-over, backups.
"""
import hashlib
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.nagios

ETC = Path("/usr/local/nagios/etc")
MANAGED = ETC / "managed"
SECRETS = ETC / "managed-secrets" / "nmp-secrets.tsv"
OBJECTS_CACHE = Path("/usr/local/nagios/var/objects.cache")
STATUS = Path("/usr/local/nagios/var/status.dat")
GOOD_TOKEN = "GoodToken123"


def _tree_hash(p: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(p.rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(p)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def _nagios_pid() -> int | None:
    try:
        pid = int(Path("/run/nagios.lock").read_text().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


@pytest.fixture(scope="module", autouse=True)
def nagios_env():
    """Snapshot /usr/local/nagios/etc and restore it afterwards (and reload Nagios)."""
    snap = Path("/tmp/nmp-etc-snapshot.tar")
    with tarfile.open(snap, "w") as t:
        t.add(ETC, arcname="etc")
    assert _nagios_pid(), "Nagios must be running for integration tests"
    yield
    shutil.rmtree(ETC)
    with tarfile.open(snap) as t:
        t.extractall("/usr/local/nagios", filter="data")
    subprocess.run(["chown", "-R", "nagios:nagios", str(ETC)])
    subprocess.run(["chown", "-R", "root:nagios", str(MANAGED)])
    pid = _nagios_pid()
    if pid:
        os.kill(pid, 1)
    time.sleep(3)


def _svc(api, code):
    return next(s for s in api.get("/api/services").json()["data"] if s["code"] == code)


def _tpl(api, name):
    return next(t for t in api.get("/api/templates").json()["data"] if t["name"] == name)


def _wait_status(pred, timeout=90):
    from nmp.nagios.status import get_status
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = get_status()
        if not s.error and pred(s):
            return s
        time.sleep(2)
    return None


def _in_objects_cache(host: str) -> bool:
    return f"host_name\t{host}\n" in OBJECTS_CACHE.read_text() or f"host_name {host}\n" in OBJECTS_CACHE.read_text()


def win_server(api, hostname, action="apply", **kw):
    tpl = _tpl(api, "Windows Standard")
    body = {"hostname": hostname, "display_name": f"{hostname} (test)", "address": "127.0.0.1",
            "environment": "production", "os_type": "windows", "monitoring_method": "ncpa", "template_id": tpl["id"],
            "ncpa": {"port": 5693, "token": GOOD_TOKEN}, "location": "Test Lab", "action": action}
    body.update(kw)
    return api.post("/api/servers", json=body)


def test_01_validate_clean_config(admin):
    r = admin.post("/api/config/validate")
    assert r.status_code == 200, r.text
    v = r.json()["data"]
    assert v["status"] == "validated", v["errors"]


def test_02_add_windows_server_apply_and_monitor(admin):
    pid_before = _nagios_pid()
    r = win_server(admin, "IT-WIN-01")
    assert r.status_code == 201, r.text
    v = r.json()["data"]["version"]
    assert v["status"] == "applied", v
    steps = [s["step"] for s in v["steps"]]
    for expected in ("validate", "backup", "install", "validate-live", "reload", "verify"):
        assert expected in steps, steps
    assert steps.index("validate") < steps.index("backup") < steps.index("install") < steps.index("reload")
    # config on disk
    host_cfg = (MANAGED / "hosts" / "IT-WIN-01.cfg").read_text()
    assert "host_name                       IT-WIN-01" in host_cfg
    assert "nmp_check_ncpa!-M system/agent_version" in host_cfg
    svc_cfg = (MANAGED / "services" / "IT-WIN-01.cfg").read_text()
    assert "disk/logical/C:|/used_percent" in svc_cfg
    # token never in object files, only in the secured secrets file
    for f in MANAGED.rglob("*.cfg"):
        assert GOOD_TOKEN not in f.read_text()
    st = SECRETS.stat()
    assert oct(st.st_mode & 0o777) == "0o400"
    assert SECRETS.owner() == "nagios"
    # Nagios reloaded (same daemon) and knows the host
    assert _nagios_pid() == pid_before
    assert _in_objects_cache("IT-WIN-01")
    # force checks and wait for the NCPA wrapper to produce real results
    admin.post("/api/monitoring/recheck", json={"host_name": "IT-WIN-01", "all_services": True})
    s = _wait_status(lambda s: s.services.get(("IT-WIN-01", "CPU Usage"), {}).get("has_been_checked") == 1)
    assert s is not None, "service was not checked"
    cpu = s.services[("IT-WIN-01", "CPU Usage")]
    assert cpu["current_state"] == 0, cpu.get("plugin_output")
    assert "cpu/percent" in cpu["plugin_output"]
    # the API merges live data
    srv = admin.get("/api/servers", params={"q": "IT-WIN-01"}).json()["data"][0]
    assert srv["live"]["in_nagios"] is True
    assert srv["config_state"] == "applied"


def test_03_validation_failure_is_not_applied(admin):
    from nmp.db import SessionLocal
    from nmp.models import Contact
    before = _tree_hash(MANAGED)
    with SessionLocal() as db:
        db.add(Contact(name="ghost-contact", alias="ghost", is_managed=False))
        db.commit()
        ghost_id = db.query(Contact).filter_by(name="ghost-contact").one().id
    cg = admin.post("/api/contact-groups", json={"name": "broken-cg", "alias": "Broken", "member_ids": [ghost_id]})
    assert cg.status_code == 201, cg.text
    r = admin.post("/api/config/apply")
    v = r.json()["data"]
    assert v["status"] == "validation_failed", v
    err = next(e for e in v["errors"] if "ghost-contact" in e["message"])
    assert err["file"] and "nmp-contacts.cfg" in err["file"]
    assert err["line"] is not None
    assert _tree_hash(MANAGED) == before, "live configuration must be untouched"
    # clean up and verify we can apply again
    admin.delete(f"/api/contact-groups/{cg.json()['data']['id']}")
    with SessionLocal() as db:
        db.query(Contact).filter_by(name="ghost-contact").delete()
        db.commit()
    assert admin.post("/api/config/apply").json()["data"]["status"] == "applied"


def test_04_modify_disable_delete(admin):
    sid = admin.get("/api/servers", params={"q": "IT-WIN-01"}).json()["data"][0]["id"]
    srv = admin.get(f"/api/servers/{sid}").json()["data"]
    items = []
    for s in srv["services"]:
        it = {k: s[k] for k in ("id", "service_id", "service_description", "params", "is_enabled", "warning", "critical",
                                "check_interval", "retry_interval", "max_check_attempts", "notification_interval",
                                "notifications_enabled")}
        if s["service_code"] == "ncpa_disk_windows" and s["params"]["drive"] == "C":
            it["warning"], it["critical"] = "85", "95"
        items.append(it)
    assert admin.put(f"/api/servers/{sid}/services", json=items).status_code == 200
    assert admin.post(f"/api/servers/{sid}/apply").json()["data"]["version"]["status"] == "applied"
    assert "-w 85 -c 95" in (MANAGED / "services" / "IT-WIN-01.cfg").read_text()
    # disable
    r = admin.post(f"/api/servers/{sid}/disable", json={"action": "apply"})
    assert r.json()["data"]["version"]["status"] == "applied"
    assert "active_checks_enabled           0" in (MANAGED / "hosts" / "IT-WIN-01.cfg").read_text()
    r = admin.post(f"/api/servers/{sid}/enable", json={"action": "apply"})
    assert "active_checks_enabled           1" in (MANAGED / "hosts" / "IT-WIN-01.cfg").read_text()
    # delete
    r = admin.delete(f"/api/servers/{sid}", params={"apply": "true"})
    assert r.json()["data"]["version"]["status"] == "applied"
    assert not (MANAGED / "hosts" / "IT-WIN-01.cfg").exists()
    assert not _in_objects_cache("IT-WIN-01")


def test_05_rollback(admin):
    r1 = win_server(admin, "RB-ONE")
    v1 = r1.json()["data"]["version"]
    assert v1["status"] == "applied"
    r2 = win_server(admin, "RB-TWO")
    assert r2.json()["data"]["version"]["status"] == "applied"
    assert _in_objects_cache("RB-TWO")
    # compare
    diff = admin.get(f"/api/config/versions/{v1['id']}/diff/{r2.json()['data']['version']['id']}").json()["data"]
    assert any(f["path"] == "managed/hosts/RB-TWO.cfg" and f["status"] == "added" for f in diff["files"])
    # rollback to v1
    r = admin.post(f"/api/config/versions/{v1['id']}/rollback")
    v = r.json()["data"]
    assert v["status"] == "applied", v
    assert v["rollback_of_version"] == v1["id"]
    assert _in_objects_cache("RB-ONE") and not _in_objects_cache("RB-TWO")
    names = [s["hostname"] for s in admin.get("/api/servers", params={"q": "RB-"}).json()["data"]]
    assert names == ["RB-ONE"]
    # download zip has no secrets
    z = admin.get(f"/api/config/versions/{v1['id']}/download")
    assert z.status_code == 200 and GOOD_TOKEN.encode() not in z.content


def test_06_invalid_ncpa_token_service_state(admin):
    r = win_server(admin, "BADTOKEN-01", ncpa={"port": 5693, "token": "WrongToken"})
    assert r.json()["data"]["version"]["status"] == "applied"
    admin.post("/api/monitoring/recheck", json={"host_name": "BADTOKEN-01", "all_services": True})
    s = _wait_status(lambda s: s.services.get(("BADTOKEN-01", "CPU Usage"), {}).get("has_been_checked") == 1)
    assert s is not None
    assert s.services[("BADTOKEN-01", "CPU Usage")]["current_state"] == 3
    assert "Incorrect credentials" in s.services[("BADTOKEN-01", "CPU Usage")]["plugin_output"]


def test_07_import_takeover_existing_hosts(admin):
    """Takes over the NCPA hosts that are defined by hand in the test server's legacy object files."""
    scan = admin.get("/api/import/scan").json()["data"]
    cands = [h for h in scan["hosts"] if h["method"] == "ncpa" and h["token_found"] and h["can_take_over"]]
    if not cands:
        pytest.skip("no manually defined NCPA hosts with inline tokens to import on this test server")
    picked = cands[:2]
    first = picked[0]["hostname"]
    assert all(s["catalog_code"] for h in picked for s in h["services"])
    src = Path(picked[0]["file"])
    before = src.read_text()
    r = admin.post("/api/import", json={"mode": "takeover", "apply": True, "hosts": [
        {"hostname": h["hostname"], "environment": "production", "os_type": "windows"} for h in picked]})
    body = r.json()["data"]
    assert body["version"]["status"] == "applied", body
    after = src.read_text()
    assert after != before and "#NMP-MIGRATED# define host {" in after
    assert (MANAGED / "hosts" / f"{first}.cfg").exists()
    assert _in_objects_cache(first)
    srv = admin.get("/api/servers", params={"q": first}).json()["data"][0]
    assert srv["managed_by"] == "portal" and ".cfg:" in srv["imported_from"]
    # nothing importable left for those hosts
    left = {h["hostname"] for h in admin.get("/api/import/scan").json()["data"]["hosts"]}
    assert first not in left


def test_08_backups_and_emergency_restore(admin):
    r = admin.post("/api/backups")
    assert r.status_code == 201, r.text
    backups = admin.get("/api/backups").json()["data"]
    assert backups and backups[0]["reason"] == "manual"
    d = admin.get(f"/api/backups/{backups[0]['id']}/download")
    assert d.status_code == 200 and d.content[:2] == b"\x1f\x8b"
    with tarfile.open(fileobj=__import__("io").BytesIO(d.content)) as t:
        names = t.getnames()
        assert "nagios.cfg" in names and not any(n.startswith("secrets") for n in names)
    r = admin.post(f"/api/backups/{backups[0]['id']}/restore")
    assert r.json()["data"]["ok"] is True, r.json()


def test_09_health_and_status_check(admin):
    h = admin.get("/api/health", params={"deep": "true"}).json()["data"]
    names = {c["name"]: c for c in h["checks"]}
    assert names["Live configuration validation"]["status"] == "ok", names["Live configuration validation"]
    assert names["Configuration"]["status"] in ("ok", "warning")


def test_10_audit_trail_complete(admin):
    acts = {a["action"] for a in admin.get("/api/audit", params={"page_size": 500}).json()["data"]}
    assert {"config.generate", "config.apply", "config.rollback", "server.create", "server.delete",
            "server.import_takeover", "backup.create"} <= acts


def test_11_pipeline_lock_released(admin):
    """GET_LOCK is connection-scoped: it must never leak into the connection pool."""
    from sqlalchemy import text
    from nmp.db import SessionLocal
    admin.post("/api/config/validate")
    with SessionLocal() as db:
        assert db.execute(text("SELECT IS_USED_LOCK('nmp_config_pipeline')")).scalar() is None
    assert admin.post("/api/config/validate").json()["data"]["status"] == "validated"
