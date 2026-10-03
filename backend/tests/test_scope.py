"""Company-based access: Super Admin sees everything; other users see only their companies
(one or several), optionally narrowed to particular locations."""
import pytest

from conftest import make_api

PW = {"pharma.admin": "Ph4rma!Admin#26", "multi.admin": "Mult1!Admin#2026", "pack.oper": "P4ck!Oper#2026x",
      "nobody.view": "N0body!View#2026"}


def _loc(admin, name):
    return next(l for l in admin.get("/api/locations").json()["data"] if l["name"] == name)


def _server(api, hostname, **kw):
    body = {"hostname": hostname, "display_name": hostname, "address": "10.20.0.1", "environment": "production",
            "os_type": "linux", "monitoring_method": "ping", "host_check": "ping", "action": "draft"}
    body.update(kw)
    return api.post("/api/servers", json=body)


@pytest.fixture(scope="module")
def world(app):
    sa = make_api(app, "admin", "Adm1n!Passw0rd#")
    daman, vapi = _loc(sa, "Daman"), _loc(sa, "Vapi")
    pharma = sa.post("/api/companies", json={"name": "Test Pharma", "code": "TPH"})
    assert pharma.status_code == 201, pharma.text
    pack = sa.post("/api/companies", json={"name": "Test Packaging", "code": "TPK"})
    pharma, pack = pharma.json()["data"], pack.json()["data"]
    mk = lambda h, co, lo: _server(sa, h, company_id=co, location_id=lo).json()["data"]["server"]  # noqa: E731
    servers = {
        "ph_dmn": mk("CO-PH-DMN", pharma["id"], daman["id"]),     # Pharma at Daman
        "pk_dmn": mk("CO-PK-DMN", pack["id"], daman["id"]),       # Packaging at Daman (same site, other company)
        "ph_vap": mk("CO-PH-VAP", pharma["id"], vapi["id"]),      # Pharma at Vapi
        "none": mk("CO-NONE", None, daman["id"]),                  # no company
    }
    roles = {r["name"]: r["id"] for r in sa.get("/api/roles").json()["data"]}
    users = [("pharma.admin", "administrator", [pharma["id"]], []),                       # one company, all sites
             ("multi.admin", "administrator", [pharma["id"], pack["id"]], [daman["id"]]),  # two companies, Daman only
             ("pack.oper", "operator", [pack["id"]], []),
             ("nobody.view", "viewer", [], [])]
    for name, role, cos, locs in users:
        r = sa.post("/api/users", json={"username": name, "full_name": name, "role_ids": [roles[role]], "company_ids": cos,
                                        "location_ids": locs, "password": PW[name], "must_change_password": False})
        assert r.status_code == 201, r.text
    apis = {n: make_api(app, n, PW[n]) for n in PW}
    return {"sa": sa, **apis, "daman": daman, "vapi": vapi, "pharma": pharma, "pack": pack, "s": servers}


def _names(api, **params):
    return {s["hostname"] for s in api.get("/api/servers", params={"page_size": 500, **params}).json()["data"]}


ALL = {"CO-PH-DMN", "CO-PK-DMN", "CO-PH-VAP", "CO-NONE"}


def test_visibility_by_company(world):
    assert ALL <= _names(world["sa"])
    assert _names(world["pharma.admin"]) & ALL == {"CO-PH-DMN", "CO-PH-VAP"}      # own company, every site
    assert _names(world["multi.admin"]) & ALL == {"CO-PH-DMN", "CO-PK-DMN"}       # two companies, Daman only
    assert _names(world["pack.oper"]) & ALL == {"CO-PK-DMN"}
    assert _names(world["nobody.view"]) & ALL == set()                             # nothing assigned = nothing


def test_same_site_other_company_is_hidden(world):
    adm, s = world["pharma.admin"], world["s"]
    for key in ("pk_dmn", "none"):
        sid = s[key]["id"]
        assert adm.get(f"/api/servers/{sid}").status_code == 404
        assert adm.get(f"/api/servers/{sid}/performance").status_code == 404
        assert adm.delete(f"/api/servers/{sid}").status_code == 404
    one = adm.get(f"/api/servers/{s['ph_dmn']['id']}").json()["data"]
    assert one["company_name"] == "Test Pharma" and one["location_name"] == "Daman"


def test_me_and_lists_show_only_own_companies(world):
    me = world["multi.admin"].get("/api/auth/me").json()["data"]["user"]
    assert me["is_super"] is False
    assert {c["name"] for c in me["companies"]} == {"Test Pharma", "Test Packaging"}
    assert [l["name"] for l in me["locations"]] == ["Daman"]
    assert {c["name"] for c in world["pharma.admin"].get("/api/companies").json()["data"]} == {"Test Pharma"}
    # not limited by site -> every active location is offered on the server form
    assert len(world["pharma.admin"].get("/api/locations").json()["data"]) >= 7
    assert [l["name"] for l in world["multi.admin"].get("/api/locations").json()["data"]] == ["Daman"]
    assert "companies.manage" not in me["permissions"] and "templates.manage" not in me["permissions"]


def test_company_management_super_admin_only(world):
    for n in ("pharma.admin", "multi.admin", "pack.oper"):
        api = world[n]
        assert api.post("/api/companies", json={"name": "X Co", "code": "XCO"}).status_code == 403
        assert api.put(f"/api/companies/{world['pharma']['id']}", json={"name": "Y", "code": "TPH"}).status_code == 403
        assert api.post("/api/locations", json={"name": "Nowhere", "code": "NWH"}).status_code == 403
    sa = world["sa"]
    assert sa.post("/api/companies", json={"name": "Test Pharma", "code": "ZZZ"}).status_code == 409
    full = sa.get("/api/companies").json()["data"]
    assert next(c for c in full if c["name"] == "Test Pharma")["users"] == 2
    assert sa.delete(f"/api/companies/{world['pack']['id']}").status_code in (404, 405)
    assert sa.post("/api/locations", json={"name": "Test City", "code": "TCY"}).status_code == 201


def test_filters_only_within_own_scope(world):
    adm = world["multi.admin"]
    assert _names(adm, company_id=world["pack"]["id"]) & ALL == {"CO-PK-DMN"}
    assert adm.get("/api/servers", params={"company_id": -1}).status_code == 403
    assert world["pharma.admin"].get("/api/servers", params={"company_id": world["pack"]["id"]}).status_code == 403
    assert adm.get("/api/servers", params={"location_id": world["vapi"]["id"]}).status_code == 403
    assert "CO-NONE" in _names(world["sa"], company_id=-1)


def test_create_and_update_rules(world):
    adm, sa = world["pharma.admin"], world["sa"]
    assert _server(adm, "CO-NOCOMP").status_code == 422                                         # company required
    assert _server(adm, "CO-WRONG", company_id=world["pack"]["id"]).status_code == 422           # not theirs
    r = _server(adm, "CO-PH-NEW", company_id=world["pharma"]["id"], location_id=world["vapi"]["id"])
    assert r.status_code == 201, r.text
    # site-limited user must also pick one of their sites
    multi = world["multi.admin"]
    assert _server(multi, "CO-M-VAP", company_id=world["pack"]["id"], location_id=world["vapi"]["id"]).status_code == 422
    assert _server(multi, "CO-M-DMN", company_id=world["pack"]["id"], location_id=world["daman"]["id"]).status_code == 201
    # moving a server to a company the user does not have is refused
    s = r.json()["data"]["server"]
    body = {k: s[k] for k in ("hostname", "display_name", "address", "environment", "os_type", "monitoring_method", "host_check")}
    assert adm.put(f"/api/servers/{s['id']}", json={**body, "company_id": world["pack"]["id"], "action": "draft"}).status_code == 422
    # an edit that does not send company/location keeps them
    r = adm.put(f"/api/servers/{s['id']}", json={**body, "display_name": "renamed", "action": "draft"})
    assert r.status_code == 200, r.text
    after = sa.get(f"/api/servers/{s['id']}").json()["data"]
    assert after["company_id"] == world["pharma"]["id"] and after["display_name"] == "renamed"


def test_retired_location_never_widens_scope(world):
    """A site-limited user whose only site is retired must see nothing, not everything."""
    sa = world["sa"]
    loc = sa.post("/api/locations", json={"name": "Retire Me", "code": "RTM"}).json()["data"]
    roles = {r["name"]: r["id"] for r in sa.get("/api/roles").json()["data"]}
    sa.post("/api/users", json={"username": "retired.site", "role_ids": [roles["viewer"]], "company_ids": [world["pharma"]["id"]],
                                "location_ids": [loc["id"]], "password": "R3tired!Site#26", "must_change_password": False})
    sa.put(f"/api/locations/{loc['id']}", json={"name": "Retire Me", "code": "RTM", "is_active": False})
    api = make_api(world["sa"].c.app, "retired.site", "R3tired!Site#26")
    assert _names(api) & ALL == set()


def test_shared_config_and_estate_operations_are_super_admin_only(world):
    adm = world["pharma.admin"]
    assert adm.post("/api/templates", json={"name": "x", "os_type": "linux", "monitoring_method": "ping", "items": []}).status_code == 403
    assert adm.post("/api/hostgroups", json={"name": "x-group", "alias": "x"}).status_code == 403
    assert adm.get("/api/backups").status_code == 403
    assert adm.get("/api/import/scan").status_code == 403
    assert adm.post("/api/config/versions/1/rollback").status_code == 403
    assert adm.get("/api/notification-channels").status_code == 403
    assert adm.get("/api/templates").status_code == 200
    r = world["sa"].post("/api/roles", json={"name": "co_viewer", "display_name": "Co viewer",
                                              "permissions": ["dashboard.view", "companies.manage"]})
    assert r.status_code == 422


def test_apply_blocked_when_other_companies_pending(world):
    sa = world["sa"]
    assert _server(sa, "CO-PK-PEND", company_id=world["pack"]["id"], location_id=world["daman"]["id"], action="save").status_code == 201
    p = world["pharma.admin"].get("/api/config/pending").json()["data"]
    assert p["other_changes"] >= 1 and p["can_apply"] is False
    assert all(c["entity_name"] != "CO-PK-PEND" for c in p["changes"])
    r = world["pharma.admin"].post("/api/config/apply")
    assert r.status_code == 409 and r.json()["error"]["code"] == "other_changes_pending"


def test_split_pending_allows_own_changes(world):
    from sqlalchemy import select

    from nmp.api import scope
    from nmp.api.deps import Principal, user_permissions
    from nmp.db import SessionLocal
    from nmp.models import ConfigurationChange, User

    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == "pharma.admin"))
        p = Principal(user=u, session=None, permissions=user_permissions(u))
        own = ConfigurationChange(entity_type="server", entity_id=world["s"]["ph_vap"]["id"], entity_name="x", action="update")
        other = ConfigurationChange(entity_type="server", entity_id=world["s"]["pk_dmn"]["id"], entity_name="y", action="update")
        shared = ConfigurationChange(entity_type="hostgroup", entity_id=1, entity_name="z", action="update")
        mine, others = scope.split_pending(db, p, [own, other, shared])
        assert mine == [own] and others == [other, shared]


def test_dashboard_reports_audit_scoped(world):
    d = world["multi.admin"].get("/api/dashboard").json()["data"]
    assert {x["name"] for x in d["inventory"]["by_company"]} <= {"Test Pharma", "Test Packaging"}
    assert {x["name"] for x in d["inventory"]["by_location"]} <= {"Daman"}
    d1 = world["multi.admin"].get("/api/dashboard", params={"company_id": world["pack"]["id"]}).json()["data"]
    assert {x["name"] for x in d1["inventory"]["by_company"]} == {"Test Packaging"}
    assert world["pharma.admin"].get("/api/dashboard", params={"company_id": world["pack"]["id"]}).status_code == 403
    rows = world["pharma.admin"].get("/api/reports/availability").json()["data"]
    assert rows and all(r["company"] == "Test Pharma" for r in rows)
    csv = world["pharma.admin"].get("/api/reports/availability", params={"format": "csv"}).text
    assert "Test Packaging" not in csv and "CO-PK-DMN" not in csv
    audit = world["pharma.admin"].get("/api/audit", params={"page_size": 500}).json()["data"]
    assert audit and not any(a["entity_name"] in ("CO-PK-DMN", "CO-NONE") for a in audit)


def test_monitoring_actions_refused_outside_scope(world):
    op = world["pack.oper"]
    assert op.post("/api/monitoring/recheck", json={"host_name": "CO-PH-DMN"}).status_code == 404
    assert op.post("/api/monitoring/acknowledge", json={"host_name": "localhost", "comment": "x"}).status_code == 404
    hosts = {h["host_name"] for h in op.get("/api/monitoring/hosts", params={"page_size": 500}).json()["data"]}
    assert "localhost" not in hosts and "CO-PH-DMN" not in hosts
