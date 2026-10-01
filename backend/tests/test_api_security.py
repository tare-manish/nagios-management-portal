"""API: authentication, authorization (RBAC), CSRF, input validation, injection, XSS, audit."""
import pytest

from conftest import ADMIN_PW, make_api


def test_unauthenticated_access_denied(anon):
    for url in ["/api/servers", "/api/dashboard", "/api/audit", "/api/users", "/api/config/versions", "/api/health"]:
        r = anon.get(url)
        assert r.status_code == 401, url
        assert r.json()["error"]["code"] == "unauthenticated"


def test_login_logout_and_me(app):
    api = make_api(app)
    assert api.login("admin", "wrong-password").status_code == 401
    r = api.login("admin", ADMIN_PW)
    assert r.status_code == 200
    body = r.json()["data"]
    assert "password_hash" not in str(body)
    assert "servers.create" in body["user"]["permissions"]
    cookie = r.headers.get("set-cookie", "")
    assert "nmp_session=" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict")
    assert api.get("/api/auth/me").status_code == 200
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/auth/me").status_code == 401


def test_username_enumeration_same_error(anon):
    a = anon.login("admin", "nope-nope-nope")
    b = anon.login("no-such-user", "nope-nope-nope")
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_account_lockout(app):
    make_api(app, "locky", "L0cky!Passw0rd", "viewer")
    api = make_api(app)
    for _ in range(5):
        assert api.login("locky", "bad-password-x").status_code == 401
    r = api.login("locky", "L0cky!Passw0rd")
    assert r.status_code == 423


def test_csrf_required_for_mutations(admin):
    r = admin.c.post("/api/hostgroups", json={"name": "csrf-test", "alias": "x"})  # no header
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"
    r = admin.c.post("/api/hostgroups", json={"name": "csrf-test", "alias": "x"}, headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403


def test_cross_origin_post_rejected(admin):
    r = admin.c.post("/api/hostgroups", json={"name": "origin-test", "alias": "x"},
                     headers={"X-CSRF-Token": admin.csrf, "Origin": "https://evil.example"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "bad_origin"


def test_security_headers(admin):
    r = admin.get("/api/dashboard")
    for h in ("x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy", "cache-control"):
        assert h in r.headers
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("url,method", [
    ("/api/users", "get"), ("/api/roles", "get"), ("/api/audit", "get"),
    ("/api/servers", "post"), ("/api/config/apply", "post"), ("/api/config/validate", "post"),
    ("/api/hostgroups", "post"), ("/api/templates", "post"), ("/api/commands", "post"),
    ("/api/notification-channels", "get"), ("/api/backups", "post"), ("/api/import/scan", "get"),
])
def test_viewer_forbidden(viewer, url, method):
    r = getattr(viewer, method)(url) if method == "get" else viewer.post(url, json={})
    assert r.status_code == 403, (url, r.text)


def test_operator_permissions(operator):
    assert operator.get("/api/servers").status_code == 200
    assert operator.get("/api/monitoring/problems").status_code == 200
    assert operator.post("/api/servers", json={}).status_code == 403
    assert operator.post("/api/config/apply").status_code == 403
    assert operator.get("/api/users").status_code == 403


def test_administrator_cannot_manage_users(administrator):
    assert administrator.get("/api/users").status_code == 403
    assert administrator.put("/api/settings", json={"perf_retention_days": 30}).status_code == 403
    assert administrator.get("/api/audit").status_code == 200


def test_denied_access_is_audited(viewer, admin):
    viewer.get("/api/users")
    r = admin.get("/api/audit", params={"action": "access.denied", "user": "view"})
    assert r.json()["meta"]["total"] >= 1


def test_privilege_escalation_blocked(app, admin):
    # a user manager without config.apply cannot hand out a role that has it
    r = admin.post("/api/roles", json={"name": "usermgr", "display_name": "User Manager",
                                       "permissions": ["users.manage", "dashboard.view"]})
    assert r.status_code == 201, r.text
    api = make_api(app, "umgr", "Us3rMgr!Pass#1", "viewer")
    # promote umgr to usermgr role via admin
    users = admin.get("/api/users").json()["data"]
    uid = next(u["id"] for u in users if u["username"] == "umgr")
    role_id = r.json()["data"]["id"]
    assert admin.put(f"/api/users/{uid}", json={"username": "umgr", "full_name": "U", "role_ids": [role_id]}).status_code == 200
    api = make_api(app, "umgr", "Us3rMgr!Pass#1")
    roles = api.get("/api/roles").json()["data"]
    super_id = next(x["id"] for x in roles if x["name"] == "super_admin")
    r = api.put(f"/api/users/{uid}", json={"username": "umgr", "full_name": "U", "role_ids": [super_id]})
    assert r.status_code == 403
    r = api.post("/api/users", json={"username": "sneaky", "password": "Sn3aky!Passw0rd", "role_ids": [super_id]})
    assert r.status_code == 403
    r = api.post("/api/roles", json={"name": "evil", "display_name": "Evil", "permissions": ["config.apply"]})
    assert r.status_code == 403


def test_cannot_remove_last_super_admin(admin):
    users = admin.get("/api/users").json()["data"]
    me = next(u for u in users if u["username"] == "admin")
    roles = admin.get("/api/roles").json()["data"]
    viewer_role = next(r["id"] for r in roles if r["name"] == "viewer")
    r = admin.put(f"/api/users/{me['id']}", json={"username": "admin", "role_ids": [viewer_role]})
    assert r.status_code == 409


@pytest.mark.parametrize("payload", [
    "' OR '1'='1", "x'; DROP TABLE servers; --", "1 UNION SELECT password_hash FROM users",
])
def test_sql_injection_in_filters_is_harmless(admin, payload):
    r = admin.get("/api/servers", params={"q": payload})
    assert r.status_code == 200
    assert r.json()["data"] == []
    r = admin.get("/api/audit", params={"q": payload, "user": payload})
    assert r.status_code == 200
    assert admin.get("/api/servers").status_code == 200  # table still there


BASE_SERVER = {
    "hostname": "SEC-TEST-01", "display_name": "Sec test", "address": "10.9.9.9", "environment": "test",
    "os_type": "windows", "monitoring_method": "ncpa", "ncpa": {"port": 5693, "token": "tok-123"},
    "services": [], "action": "save",
}


@pytest.mark.parametrize("field,value", [
    ("hostname", "evil;reboot"), ("hostname", "$(id)"), ("hostname", "a`id`"),
    ("address", "10.0.0.1; rm -rf /"), ("address", "$(curl evil)"),
    ("display_name", "<script>alert(1)</script>"), ("display_name", "x; y"), ("location", "a|b"),
    ("check_period", "24x7;id"),
])
def test_server_injection_rejected(admin, field, value):
    body = dict(BASE_SERVER, **{field: value})
    r = admin.post("/api/servers", json=body)
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "validation_error"


def test_service_param_injection_rejected(admin):
    svcs = admin.get("/api/services").json()["data"]
    disk = next(s for s in svcs if s["code"] == "ncpa_disk_windows")
    winsvc = next(s for s in svcs if s["code"] == "ncpa_windows_service")
    for item in [
        {"service_id": disk["id"], "service_description": "D", "params": {"drive": "C:|/;id"}},
        {"service_id": winsvc["id"], "service_description": "W", "params": {"service": "W3SVC'; id; '"}},
        {"service_id": disk["id"], "service_description": "D", "params": {"drive": "C"}, "warning": "80;id"},
        {"service_id": disk["id"], "service_description": "bad;desc", "params": {"drive": "C"}},
    ]:
        r = admin.post("/api/servers", json=dict(BASE_SERVER, hostname="SEC-TEST-02", services=[item]))
        assert r.status_code == 422, (item, r.text)


def test_custom_command_injection_rejected(admin):
    for cl in ["/bin/sh -c id", "$USER1$/check_x; id", "$USER1$/check_x `id`", "$USER1$/check_x > /tmp/x"]:
        r = admin.post("/api/commands", json={"name": "evilcmd", "command_line": cl})
        assert r.status_code == 422, (cl, r.text)
    r = admin.post("/api/commands", json={"name": "nmp_hijack", "command_line": "$USER1$/check_x"})
    assert r.status_code == 422


def test_secrets_never_returned(admin):
    r = admin.post("/api/servers", json=dict(BASE_SERVER, hostname="SEC-SECRET-01",
                                             ncpa={"port": 5693, "token": "SuperSecretToken987"}))
    assert r.status_code == 201, r.text
    sid = r.json()["data"]["server"]["id"]
    for url in [f"/api/servers/{sid}", f"/api/servers/{sid}/history", "/api/servers", "/api/config/pending",
                "/api/audit"]:
        assert "SuperSecretToken987" not in admin.get(url).text, url


def test_error_format(admin):
    r = admin.get("/api/servers/999999")
    assert r.status_code == 404
    assert set(r.json()["error"]) == {"code", "message", "details"}
