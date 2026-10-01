"""API CRUD: servers, services, templates, groups, contacts, catalog, users, settings, notifications."""
import pytest


def _svc(admin, code):
    return next(s for s in admin.get("/api/services").json()["data"] if s["code"] == code)


def _tpl(admin, name):
    return next(t for t in admin.get("/api/templates").json()["data"] if t["name"] == name)


def test_catalog_and_templates_seeded(admin):
    codes = {s["code"] for s in admin.get("/api/services").json()["data"]}
    assert {"ping", "ncpa_cpu", "ncpa_memory", "ncpa_disk_windows", "ncpa_windows_service", "snmp_ifutil"} <= codes
    names = {t["name"] for t in admin.get("/api/templates").json()["data"]}
    assert {"Windows Standard", "Windows Application Server", "Linux Standard"} <= names
    ws = _tpl(admin, "Windows Standard")
    assert [i["service_description"] for i in ws["items"]][:3] == ["Ping", "CPU Usage", "Memory Usage"]


def test_server_crud_with_template(admin):
    tpl = _tpl(admin, "Windows Standard")
    body = {"hostname": "CRUD-WIN-01", "display_name": "CRUD Windows", "address": "10.1.1.10",
            "environment": "production", "os_type": "windows", "monitoring_method": "ncpa", "template_id": tpl["id"],
            "ncpa": {"port": 5693, "token": "abc", "verify_ssl": False}, "location": "Main DC", "action": "draft"}
    r = admin.post("/api/servers", json=body)
    assert r.status_code == 201, r.text
    srv = r.json()["data"]["server"]
    assert srv["config_state"] == "draft"
    assert len(srv["services"]) == len(tpl["items"])
    assert srv["credentials"][0]["secret_set"] is True
    sid = srv["id"]
    # duplicate hostname
    assert admin.post("/api/servers", json=body).status_code == 409
    # list / filter / sort / paginate
    r = admin.get("/api/servers", params={"q": "CRUD-WIN", "environment": "production", "sort": "hostname"})
    assert r.json()["meta"]["total"] == 1
    r = admin.get("/api/servers", params={"page_size": 1, "page": 1})
    assert r.json()["meta"]["page_size"] == 1
    # update: keep token when not supplied, change thresholds
    services = srv["services"]
    cpu = next(s for s in services if s["service_code"] == "ncpa_cpu")
    cpu["warning"], cpu["critical"] = "70", "95"
    upd = dict(body, display_name="CRUD Windows Renamed", ncpa={"port": 5693}, action="save",
               services=[{k: v for k, v in s.items() if k in ("id", "service_id", "service_description", "params",
                          "is_enabled", "warning", "critical", "check_interval", "retry_interval", "max_check_attempts",
                          "notification_interval", "notifications_enabled")} for s in services])
    r = admin.put(f"/api/servers/{sid}", json=upd)
    assert r.status_code == 200, r.text
    d = r.json()["data"]["server"]
    assert d["display_name"] == "CRUD Windows Renamed"
    assert d["credentials"][0]["secret_set"] is True
    assert next(s for s in d["services"] if s["service_code"] == "ncpa_cpu")["warning"] == "70"
    # disable / enable
    assert admin.post(f"/api/servers/{sid}/disable").json()["data"]["server"]["is_enabled"] is False
    assert admin.post(f"/api/servers/{sid}/enable").json()["data"]["server"]["is_enabled"] is True
    # history
    h = admin.get(f"/api/servers/{sid}/history").json()["data"]
    actions = {a["action"] for a in h["audit"]}
    assert {"server.create", "server.update", "server.disable", "server.enable"} <= actions
    # pending changes recorded
    pend = admin.get("/api/config/pending").json()["data"]
    assert any(c["entity_name"] == "CRUD-WIN-01" for c in pend["changes"])
    # delete (soft)
    assert admin.delete(f"/api/servers/{sid}").status_code == 200
    assert admin.get(f"/api/servers/{sid}").status_code == 404
    # hostname can be reused after delete
    r = admin.post("/api/servers", json=dict(body, action="draft"))
    assert r.status_code == 201
    admin.delete(f"/api/servers/{r.json()['data']['server']['id']}")


def test_ncpa_token_required_on_create(admin):
    r = admin.post("/api/servers", json={"hostname": "NOTOKEN", "display_name": "x", "address": "10.1.1.2",
                                         "os_type": "windows", "monitoring_method": "ncpa", "action": "save"})
    assert r.status_code == 422


def test_snmp_v3_requires_passwords(admin):
    base = {"hostname": "SW-01", "display_name": "Core switch", "address": "10.1.1.3", "os_type": "network",
            "device_type": "network_device", "monitoring_method": "snmp", "host_check": "ping", "action": "draft"}
    r = admin.post("/api/servers", json=dict(base, snmp={"version": "3", "username": "mon", "security_level": "authPriv",
                                                          "auth_protocol": "SHA", "auth_password": "authpass123"}))
    assert r.status_code == 422
    r = admin.post("/api/servers", json=dict(base, snmp={"version": "2c", "community": "s3cret-comm"}))
    assert r.status_code == 201, r.text
    assert "s3cret-comm" not in r.text
    sid = r.json()["data"]["server"]["id"]
    admin.delete(f"/api/servers/{sid}")


def test_windows_service_monitor(admin):
    ws = _svc(admin, "ncpa_windows_service")
    r = admin.post("/api/servers", json={
        "hostname": "WSVC-01", "display_name": "x", "address": "10.1.1.4", "os_type": "windows",
        "monitoring_method": "ncpa", "ncpa": {"token": "t"}, "action": "draft",
        "services": [{"service_id": ws["id"], "service_description": "Service Spooler",
                      "params": {"service": "Spooler", "display_name": "Print Spooler", "state": "running",
                                 "mismatch": "warning"}}]})
    assert r.status_code == 201, r.text
    admin.delete(f"/api/servers/{r.json()['data']['server']['id']}")


def test_template_crud(admin):
    cpu, ping = _svc(admin, "ncpa_cpu"), _svc(admin, "ping")
    r = admin.post("/api/templates", json={"name": "Custom T", "os_type": "windows", "monitoring_method": "ncpa",
                                           "items": [{"service_id": ping["id"], "service_description": "Ping"},
                                                     {"service_id": cpu["id"], "service_description": "CPU", "warning": "60"}]})
    assert r.status_code == 201, r.text
    tid = r.json()["data"]["id"]
    r = admin.put(f"/api/templates/{tid}", json={"name": "Custom T2", "os_type": "windows", "monitoring_method": "ncpa",
                                                 "items": [{"service_id": cpu["id"], "service_description": "CPU"}]})
    assert r.json()["data"]["name"] == "Custom T2" and len(r.json()["data"]["items"]) == 1
    assert admin.delete(f"/api/templates/{tid}").status_code == 200


def test_groups_contacts(admin):
    r = admin.post("/api/hostgroups", json={"name": "app-servers", "alias": "Application Servers"})
    assert r.status_code == 201, r.text
    gid = r.json()["data"]["id"]
    assert admin.post("/api/hostgroups", json={"name": "app-servers", "alias": "dup"}).status_code == 409
    c = admin.post("/api/contacts", json={"name": "oncall", "alias": "On call", "email": "oncall@example.com"})
    assert c.status_code == 201, c.text
    cg = admin.post("/api/contact-groups", json={"name": "ops-team", "alias": "Ops", "member_ids": [c.json()["data"]["id"]]})
    assert cg.status_code == 201, cg.text
    assert admin.post("/api/contacts", json={"name": "bad", "alias": "x", "email": "not-an-email"}).status_code == 422
    assert admin.delete(f"/api/hostgroups/{gid}").status_code == 200


def test_custom_service_definition(admin):
    cmd = admin.post("/api/commands", json={"name": "check_http_custom",
                                            "command_line": "/usr/lib/nagios/plugins/check_http -H $HOSTADDRESS$ $ARG1$"})
    assert cmd.status_code == 201, cmd.text
    r = admin.post("/api/services", json={
        "code": "http_url", "name": "HTTP URL", "category": "availability", "monitoring_method": "custom",
        "os_types": ["windows", "linux"], "command_id": cmd.json()["data"]["id"],
        "arg_template": "-u {path}[[ -w {warning}]][[ -c {critical}]]",
        "params_schema": [{"name": "path", "type": "mount", "label": "URL path", "required": True, "default": "/"}],
        "default_description": "HTTP {path}", "default_warning": "2", "default_critical": "5"})
    assert r.status_code == 201, r.text
    bad = admin.post("/api/services", json={
        "code": "bad_tpl", "name": "Bad", "category": "custom", "monitoring_method": "custom", "os_types": ["linux"],
        "command_id": cmd.json()["data"]["id"], "arg_template": "-x {nope}", "params_schema": [],
        "default_description": "Bad"})
    assert bad.status_code == 422


def test_settings(admin):
    r = admin.put("/api/settings", json={"perf_retention_days": 60, "display_timezone": "Asia/Kolkata"})
    assert r.status_code == 200 and r.json()["data"]["perf_retention_days"] == 60
    assert admin.put("/api/settings", json={"display_timezone": "Mars/Base"}).status_code == 422
    assert admin.put("/api/settings", json={"unknown": 1}).status_code == 422


def test_user_management(admin, app):
    roles = {r["name"]: r["id"] for r in admin.get("/api/roles").json()["data"]}
    r = admin.post("/api/users", json={"username": "newop", "full_name": "New Op", "email": "n@example.com",
                                       "role_ids": [roles["operator"]], "password": "weak"})
    assert r.status_code == 422
    r = admin.post("/api/users", json={"username": "newop", "full_name": "New Op", "email": "n@example.com",
                                       "role_ids": [roles["operator"]], "password": "N3wOp!Password"})
    assert r.status_code == 201, r.text
    from conftest import make_api
    api = make_api(app)
    assert api.login("newop", "N3wOp!Password").status_code == 200
    # must change password first
    assert api.get("/api/servers").status_code == 403
    r = api.post("/api/auth/change-password", json={"current_password": "N3wOp!Password", "new_password": "An0ther!Password"})
    assert r.status_code == 200, r.text
    assert api.get("/api/servers").status_code == 200


def test_notifications_config(admin):
    prov = admin.get("/api/notification-providers").json()["data"]
    assert {"email", "teams", "webhook", "whatsapp", "sms", "web"} <= {p["key"] for p in prov}
    r = admin.post("/api/notification-channels", json={"name": "Ops Teams", "provider": "teams",
                                                       "settings": {"webhook_url": "https://example.invalid/hook?sig=SECRETSIG"}})
    assert r.status_code == 201, r.text
    assert "SECRETSIG" not in r.text
    ch = r.json()["data"]
    assert ch["secrets_set"]["webhook_url"] is True
    r = admin.post("/api/notification-rules", json={"name": "Prod critical", "event_types": ["host_down", "service_critical"],
                                                    "channel_id": ch["id"], "environments": ["production"]})
    assert r.status_code == 201, r.text
    web = admin.post("/api/notification-channels", json={"name": "In-app", "provider": "web", "settings": {}})
    assert web.status_code == 201
    assert admin.post("/api/notification-rules", json={"name": "bad", "event_types": ["nope"],
                                                       "channel_id": ch["id"]}).status_code == 422


def test_csv_exports(admin):
    r = admin.get("/api/audit", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("time_utc,user")
    r = admin.get("/api/reports/availability", params={"format": "csv"})
    assert r.status_code == 200


def test_dashboard_and_reports_shape(admin):
    d = admin.get("/api/dashboard").json()["data"]
    assert {"hosts", "services", "top_problems", "recent_events", "pending_changes"} <= set(d)
    for url in ["/api/reports/availability", "/api/reports/service-availability", "/api/reports/sla",
                "/api/reports/performance", "/api/reports/health"]:
        assert admin.get(url).status_code == 200, url
