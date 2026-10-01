"""NCPA connection test against a fake HTTPS NCPA agent; worker perf sampling and notification engine."""
import datetime as dt
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nmp import agents


class FakeNcpa(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        token = q.get("token", [""])[0]
        if token == "SlowToken":
            time.sleep(4)
        if token not in ("GoodToken123", "SlowToken"):
            body, code = {"error": "Incorrect credentials given."}, 403
        else:
            body, code = {"system": {"system": "Windows", "node": "WINFAKE", "release": "2019Server",
                                     "agent_version": "3.1.1"}}, 200
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def ncpa_server(tmp_path_factory):
    d = tmp_path_factory.mktemp("ncpa")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeNcpa)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_ncpa_success(ncpa_server):
    r = agents.test_ncpa("127.0.0.1", ncpa_server, "GoodToken123", verify_ssl=False, timeout=5)
    assert r["result"] == "success" and r["label"] == "Connection Successful"
    assert r["agent_version"] == "3.1.1" and r["node"] == "WINFAKE"


def test_ncpa_auth_failed(ncpa_server):
    r = agents.test_ncpa("127.0.0.1", ncpa_server, "WrongToken", timeout=5)
    assert r["result"] == "auth_failed" and r["label"] == "Authentication Failed"


def test_ncpa_timeout(ncpa_server):
    r = agents.test_ncpa("127.0.0.1", ncpa_server, "SlowToken", timeout=1)
    assert r["result"] == "timeout"


def test_ncpa_agent_not_installed():
    r = agents.test_ncpa("127.0.0.1", _free_port(), "x", timeout=3)
    assert r["result"] == "agent_not_installed" and r["label"] == "Agent Not Installed"


def test_ncpa_tls_verification_failure(ncpa_server):
    r = agents.test_ncpa("127.0.0.1", ncpa_server, "GoodToken123", verify_ssl=True, timeout=5)
    assert r["result"] == "connection_failed"


def test_connection_test_api_before_saving(admin, ncpa_server):
    r = admin.post("/api/servers/test-connection", json={
        "address": "127.0.0.1", "monitoring_method": "ncpa",
        "ncpa": {"port": ncpa_server, "token": "GoodToken123", "verify_ssl": False, "timeout": 5}})
    assert r.status_code == 200 and r.json()["data"]["result"] == "success"
    r = admin.post("/api/servers/test-connection", json={
        "address": "127.0.0.1", "monitoring_method": "ncpa", "ncpa": {"port": ncpa_server, "token": "bad", "timeout": 5}})
    assert r.json()["data"]["result"] == "auth_failed"


def test_connection_test_uses_stored_token(admin, ncpa_server):
    r = admin.post("/api/servers", json={"hostname": "CT-STORED", "display_name": "x", "address": "127.0.0.1",
                                         "os_type": "windows", "monitoring_method": "ncpa", "action": "draft",
                                         "ncpa": {"port": ncpa_server, "token": "GoodToken123", "timeout": 5}})
    sid = r.json()["data"]["server"]["id"]
    r = admin.post(f"/api/servers/{sid}/test")
    assert r.json()["data"]["result"] == "success"
    assert admin.get(f"/api/servers/{sid}").json()["data"]["credentials"][0]["last_test_result"] == "success"
    admin.delete(f"/api/servers/{sid}")


def test_worker_perf_and_notifications(admin, monkeypatch):
    from nmp import worker as W
    from nmp.db import SessionLocal
    from nmp.models import Notification, PerfSample
    from nmp.nagios import status as st
    from nmp.notifications.providers import registry

    cpu = next(s for s in admin.get("/api/services").json()["data"] if s["code"] == "ncpa_cpu")
    r = admin.post("/api/servers", json={"hostname": "WK-01", "display_name": "Worker test", "address": "10.2.2.2",
                                         "os_type": "windows", "monitoring_method": "ncpa", "ncpa": {"token": "t"},
                                         "environment": "production", "action": "save",
                                         "services": [{"service_id": cpu["id"], "service_description": "CPU Usage"}]})
    sid = r.json()["data"]["server"]["id"]
    ch = admin.post("/api/notification-channels", json={"name": "Capture", "provider": "webhook",
                                                        "settings": {"url": "https://capture.invalid/x"}}).json()["data"]
    admin.post("/api/notification-rules", json={"name": "cap", "event_types": ["service_critical", "high_cpu", "recovery"],
                                                "channel_id": ch["id"], "throttle_minutes": 0})
    sent = []
    prov = registry.get("webhook")
    monkeypatch.setattr(prov, "send", lambda settings, secrets, msg: sent.append((secrets["url"], msg.event_type, msg.title)))

    now = int(time.time())

    def snapshot(state, t):
        snap = st.StatusSnapshot(mtime=time.time())
        snap.hosts["WK-01"] = {"host_name": "WK-01", "current_state": 0, "has_been_checked": 1, "state_type": 1}
        snap.services[("WK-01", "CPU Usage")] = {"host_name": "WK-01", "service_description": "CPU Usage",
                                                 "current_state": state, "has_been_checked": 1, "state_type": 1,
                                                 "last_check": t, "plugin_output": "cpu",
                                                 "performance_data": f"'value'={95 if state else 10}%;80;90"}
        return snap

    w = W.Worker()
    for i, state in enumerate([0, 2, 0]):
        monkeypatch.setattr(W, "get_status", lambda state=state, i=i: snapshot(state, now + i * 60))
        w.cycle()
    kinds = [k for _, k, _ in sent]
    assert kinds.count("service_critical") == 1 and kinds.count("high_cpu") == 1 and kinds.count("recovery") == 1
    assert sent[0][0] == "https://capture.invalid/x"
    with SessionLocal() as db:
        n = db.query(PerfSample).filter_by(server_id=sid).count()
        assert n == 3
        assert db.query(Notification).filter_by(status="sent").count() >= 3
    perf = admin.get(f"/api/servers/{sid}/performance", params={"hours": 24}).json()["data"]
    assert perf and perf[0]["label"] == "value" and len(perf[0]["points"]) == 3
