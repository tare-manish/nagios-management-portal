"""Test configuration.

Unit tests run anywhere with a MariaDB test database. Integration tests
(marked `nagios`) additionally need a real Nagios Core install laid out
like production (/usr/local/nagios) and the privileged helpers configured
in /etc/nagios-management/privileged.json; they are skipped otherwise.

Environment:
  NMP_TEST_DATABASE_URL  (default mysql+pymysql://nagios_mgmt:TestPass!2345@localhost/nagios_mgmt_test)
"""
from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_tmp = Path(tempfile.mkdtemp(prefix="nmp-test-"))
(_tmp / "master.key").write_bytes(base64.b64encode(secrets.token_bytes(32)))
os.environ.setdefault("NMP_DATABASE_URL", os.environ.get(
    "NMP_TEST_DATABASE_URL", "mysql+pymysql://nagios_mgmt:TestPass%212345@localhost/nagios_mgmt_test?charset=utf8mb4"))
os.environ["NMP_MASTER_KEY_FILE"] = str(_tmp / "master.key")
os.environ["NMP_PRIV_MODE"] = "direct"
os.environ.setdefault("NMP_PRIV_SBIN", "/opt/nagios-management/privileged/sbin")
os.environ["NMP_COOKIE_SECURE"] = "0"
os.environ["NMP_LOG_DIR"] = str(_tmp)
os.environ["NMP_FRONTEND_DIST"] = str(_tmp / "no-dist")
os.environ["NMP_API_RATE_LIMIT"] = "100000"
os.environ["NMP_TESTING"] = "1"

from sqlalchemy import create_engine, text  # noqa: E402

NAGIOS_AVAILABLE = Path("/usr/local/nagios/bin/nagios").exists() and Path("/etc/nagios-management/privileged.json").exists()
ADMIN_PW = "Adm1n!Passw0rd#"


def pytest_configure(config):
    config.addinivalue_line("markers", "nagios: integration test requiring a real Nagios installation")


def pytest_collection_modifyitems(config, items):
    if NAGIOS_AVAILABLE:
        return
    skip = pytest.mark.skip(reason="Nagios integration environment not available")
    for it in items:
        if "nagios" in it.keywords:
            it.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def database():
    url = os.environ["NMP_DATABASE_URL"]
    base, dbname = url.rsplit("/", 1)
    dbname = dbname.split("?")[0]
    eng = create_engine(base + "/?charset=utf8mb4")
    with eng.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS `{dbname}`"))
        c.execute(text(f"CREATE DATABASE `{dbname}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
    eng.dispose()
    from nmp.cli import main as cli
    assert cli(["migrate"]) == 0          # migrations are part of what we test
    from nmp.db import SessionLocal
    from nmp.seed import seed_all
    with SessionLocal() as db:
        seed_all(db, sync_legacy=NAGIOS_AVAILABLE)
    _create_user("admin", ADMIN_PW, "super_admin")
    yield


def _create_user(username, password, role):
    from sqlalchemy import select
    from nmp.db import SessionLocal
    from nmp.models import Role, User
    from nmp.security.passwords import hash_password
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == username))
        if u is None:
            u = User(username=username, full_name=username.title(), password_hash=hash_password(password))
            u.roles = [db.scalar(select(Role).where(Role.name == role))]
            db.add(u)
            db.commit()


@pytest.fixture(scope="session")
def app():
    from nmp.main import create_app
    return create_app()


class Api:
    def __init__(self, client):
        self.c = client
        self.csrf = None

    def login(self, username, password):
        r = self.c.post("/api/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            self.csrf = r.json()["data"]["csrf_token"]
        return r

    def _h(self):
        return {"X-CSRF-Token": self.csrf} if self.csrf else {}

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, json=None, **kw):
        return self.c.post(url, json=json, headers=self._h(), **kw)

    def put(self, url, json=None, **kw):
        return self.c.put(url, json=json, headers=self._h(), **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self._h(), **kw)


def make_api(app, username=None, password=None, role=None):
    from fastapi.testclient import TestClient
    client = TestClient(app, base_url="http://testserver")
    api = Api(client)
    if username:
        if role:
            _create_user(username, password, role)
        r = api.login(username, password)
        assert r.status_code == 200, r.text
    return api


@pytest.fixture()
def admin(app):
    return make_api(app, "admin", ADMIN_PW)


@pytest.fixture()
def administrator(app):
    return make_api(app, "adm2", "Admin!strat0r#1", "administrator")


@pytest.fixture()
def operator(app):
    return make_api(app, "oper", "0perator!Pass#", "operator")


@pytest.fixture()
def viewer(app):
    return make_api(app, "view", "V1ewer!Pass#12", "viewer")


@pytest.fixture()
def anon(app):
    return make_api(app)
