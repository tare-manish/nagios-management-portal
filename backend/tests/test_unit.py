"""Unit tests: validators, argument rendering, parsers, crypto, log redaction."""
import pytest

from nmp import validators as V
from nmp.logging_setup import redact
from nmp.nagios.generator import GenerationError, build_check_values, nagios_escape, render_args
from nmp.nagios.logparser import parse_line
from nmp.nagios.status import parse_perfdata, parse_status, primary_percent
from nmp.security import crypto
from nmp.security.passwords import hash_password, password_policy_errors, verify_password


@pytest.mark.parametrize("v", ["WIN-APP01", "srv.example", "host_1", "WIN-SERVER-10.0.0.12"])
def test_hostname_ok(v):
    assert V.check_hostname(v) == v


@pytest.mark.parametrize("v", ["", "-bad", "a b", "x;rm -rf /", "$(id)", "h`id`", "a" * 70, "host!", "h'o", "h\"o",
                               "<script>", "h|x", "h&x"])
def test_hostname_rejects_injection(v):
    with pytest.raises(V.ValidationError):
        V.check_hostname(v)


@pytest.mark.parametrize("v", ["10.0.0.1", "::1", "fe80::1", "server.corp.local", "a.b"])
def test_address_ok(v):
    V.check_address(v)


@pytest.mark.parametrize("v", ["10.0.0.1;id", "1.2.3", "$(id)", "a b", "http://x", "-H"])
def test_address_bad(v):
    with pytest.raises(V.ValidationError):
        V.check_address(v)


@pytest.mark.parametrize("v,ok", [("80", True), ("10:", True), ("~:90", True), ("@5:10", True), ("200.0,20%", True),
                                  ("80;id", False), ("$(x)", False), ("80 -c 1", False), ("`x`", False)])
def test_thresholds(v, ok):
    if ok:
        assert V.check_threshold(v, "w") == v
    else:
        with pytest.raises(V.ValidationError):
            V.check_threshold(v, "w")


@pytest.mark.parametrize("v", ["a;b", "x$y", "a`b`", "a\\b", "x!y", "<b>", "a|b", "a&b"])
def test_free_text_rejects(v):
    with pytest.raises(V.ValidationError):
        V.check_free_text(v, "f")


def test_free_text_collapses_newlines():
    assert V.check_free_text("line1\nline2\r\n  x", "f") == "line1 line2 x"


def test_params_schema_validation():
    schema = [{"name": "drive", "type": "drive", "required": True, "default": "C"}]
    assert V.validate_params(schema, {"drive": "D"}) == {"drive": "D"}
    assert V.validate_params(schema, {}) == {"drive": "C"}
    for bad in ["CD", "C;", "1", "$"]:
        with pytest.raises(V.ValidationError):
            V.validate_params(schema, {"drive": bad})
    with pytest.raises(V.ValidationError):
        V.validate_params(schema, {"drive": "C", "extra": "x"})


@pytest.mark.parametrize("line", ["/usr/lib/nagios/plugins/check_x; rm -rf /", "/tmp/evil", "$USER1$/check_x `id`",
                                  "$USER1$/check_x $(id)", "$USER1$/check_x > /etc/passwd", "$USER1$/../../bin/sh -c id",
                                  "$USER1$/check_x && id", "$USER1$/check_x | sh", "$USER1$/check_x $PATH"])
def test_command_line_injection_rejected(line):
    with pytest.raises(V.ValidationError):
        V.check_command_line(line, ["$USER1$/", "/usr/lib/nagios/plugins/"])


def test_command_line_ok():
    assert V.check_command_line("$USER1$/check_http -H $HOSTADDRESS$ -u '/a|b' $ARG1$", ["$USER1$/"])


def test_render_args_optional_segments():
    t = "-M 'disk/logical/{drive}:|/used_percent'[[ -w {warning}]][[ -c {critical}]]"
    v = build_check_values("80", None, [{"name": "drive", "type": "drive", "required": True}], {"drive": "e"})
    assert render_args(t, v) == "-M 'disk/logical/E:|/used_percent' -w 80"


def test_render_args_mount_and_escape():
    v = build_check_values(None, None, [{"name": "mount", "type": "mount", "required": True}], {"mount": "/var/log"})
    assert render_args("-M 'disk/logical/{mount_ncpa}/used_percent'", v) == "-M 'disk/logical/|var|log/used_percent'"
    v = build_check_values(None, None, [{"name": "service", "type": "winservice", "required": True}], {"service": "MSSQL$PROD"})
    assert "MSSQL$$PROD" in render_args("-q 'service={service}'", v)
    assert nagios_escape("a$b") == "a$$b"


def test_render_args_required_missing():
    with pytest.raises(GenerationError):
        render_args("{warning}!{critical}", {"warning": "1", "critical": ""})


def test_render_args_rejects_unsafe_values():
    with pytest.raises(GenerationError):
        render_args("{x}", {"x": "a;b"})
    with pytest.raises(GenerationError):
        render_args("{x}", {"x": "a!b"})


def test_crypto_roundtrip_and_purpose_binding():
    ct = crypto.encrypt_json({"token": "s3cr3t"}, "cred:ncpa")
    assert "s3cr3t" not in ct
    assert crypto.decrypt_json(ct, "cred:ncpa") == {"token": "s3cr3t"}
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_json(ct, "cred:snmp")


def test_password_hash_and_policy():
    h = hash_password("Corr3ct!Horse")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "Corr3ct!Horse")
    assert not verify_password(h, "wrong")
    assert not verify_password(None, "anything")
    assert password_policy_errors("short")
    assert password_policy_errors("alllowercaseletters")
    assert password_policy_errors("Admin!Passw0rd123", username="admin")
    assert not password_policy_errors("Str0ng!Passphrase")


def test_log_redaction():
    s = redact("check_ncpa.py -H x -t 'abc123' token=zzz password: hunter2 community=public")
    assert "abc123" not in s and "zzz" not in s and "hunter2" not in s and "public" not in s


def test_perfdata_parsing():
    items = parse_perfdata("'used'=42.5%;80;90;0;100 load1=0.5;5;10 'C:\\ Used'=12GB;;")
    assert items[0]["label"] == "used" and items[0]["value"] == 42.5 and items[0]["uom"] == "%"
    assert items[0]["warn"] == 80 and items[0]["crit"] == 90
    assert items[1]["label"] == "load1"
    assert primary_percent("'used'=42.5%;80;90") == 42.5


def test_status_parse():
    text = """info {
    version=4.5.14
    }
programstatus {
    nagios_pid=123
    program_start=1700000000
    }
hoststatus {
    host_name=h1
    current_state=1
    has_been_checked=1
    state_type=1
    plugin_output=CRITICAL - down
    last_check=1700000100
    }
servicestatus {
    host_name=h1
    service_description=CPU Usage
    current_state=2
    has_been_checked=1
    performance_data='value'=95%;80;90
    }
hostdowntime {
    host_name=h1
    downtime_id=7
    start_time=1700000000
    end_time=1700003600
    }
"""
    s = parse_status(text)
    assert s.program["nagios_pid"] == 123
    assert s.hosts["h1"]["current_state"] == 1
    assert s.services[("h1", "CPU Usage")]["current_state"] == 2
    assert s.downtimes[0]["downtime_id"] == 7 and s.downtimes[0]["kind"] == "host"


def test_log_line_parsing():
    e = parse_line("[1700000000] SERVICE ALERT: h1;CPU Usage;CRITICAL;HARD;3;CRITICAL: cpu 95%\n")
    assert (e.kind, e.host, e.service, e.state, e.state_type) == ("SERVICE ALERT", "h1", "CPU Usage", "CRITICAL", "HARD")
    e = parse_line("[1700000000] HOST ALERT: h1;DOWN;SOFT;1;timeout")
    assert e.state == "DOWN" and e.state_type == "SOFT"
    e = parse_line("[1700000000] Caught SIGHUP, restarting...")
    assert e.kind == "PROGRAM"
