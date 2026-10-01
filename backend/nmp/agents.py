"""Agent connection tests: NCPA (HTTPS API) and SNMP (net-snmp snmpget).

Results use a fixed vocabulary shown in the UI:
  success | auth_failed | timeout | agent_not_installed | connection_failed
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

import httpx

LABELS = {
    "success": "Connection Successful",
    "auth_failed": "Authentication Failed",
    "timeout": "Timeout",
    "agent_not_installed": "Agent Not Installed",
    "connection_failed": "Connection Failed",
}


def _result(code: str, detail: str = "", **info) -> dict:
    return {"result": code, "label": LABELS[code], "detail": detail, **info}


def _find(d, key):
    if isinstance(d, dict):
        if key in d and not isinstance(d[key], (dict, list)):
            return d[key]
        for v in d.values():
            r = _find(v, key)
            if r is not None:
                return r
    elif isinstance(d, list):
        for v in d:
            r = _find(v, key)
            if r is not None:
                return r
    return None


def test_ncpa(address: str, port: int, token: str, verify_ssl: bool = False, timeout: int = 10,
              ssl_enabled: bool = True) -> dict:
    scheme = "https" if ssl_enabled else "http"
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    base = f"{scheme}://{host}:{int(port)}/api"
    t0 = time.monotonic()
    try:
        with httpx.Client(verify=verify_ssl, timeout=timeout, follow_redirects=False) as client:
            r = client.get(f"{base}/system", params={"token": token})
            elapsed = round((time.monotonic() - t0) * 1000)
            if r.status_code in (401, 403):
                return _result("auth_failed", "The agent rejected the token", response_ms=elapsed)
            try:
                data = r.json()
            except ValueError:
                return _result("connection_failed", f"Unexpected response (HTTP {r.status_code}) - is this an NCPA agent?",
                               response_ms=elapsed)
            err = data.get("error") if isinstance(data, dict) else None
            if err:
                low = str(err).lower()
                if "token" in low or "credential" in low or "auth" in low:
                    return _result("auth_failed", "The agent rejected the token", response_ms=elapsed)
                return _result("connection_failed", str(err)[:200], response_ms=elapsed)
            if r.status_code != 200:
                return _result("connection_failed", f"HTTP {r.status_code}", response_ms=elapsed)
            info = {
                "agent_version": _find(data, "agent_version"),
                "os": _find(data, "system"),
                "os_release": _find(data, "release"),
                "node": _find(data, "node"),
                "response_ms": elapsed,
            }
            return _result("success", f"NCPA {info['agent_version'] or ''} on {info['node'] or address}".strip(), **info)
    except httpx.TimeoutException:
        return _result("timeout", f"No response within {timeout}s")
    except httpx.ConnectError as exc:
        msg = str(exc).lower()
        if "refused" in msg:
            return _result("agent_not_installed", f"Port {port} refused the connection - NCPA is not installed or not running")
        if "certificate" in msg or "ssl" in msg:
            return _result("connection_failed", "TLS certificate verification failed (disable 'Verify SSL' for self-signed agents)")
        if "name or service not known" in msg or "nodename" in msg or "resolve" in msg:
            return _result("connection_failed", "DNS name could not be resolved")
        return _result("connection_failed", "Host unreachable or connection blocked by a firewall")
    except httpx.HTTPError as exc:
        return _result("connection_failed", type(exc).__name__)


def test_snmp(address: str, cred: dict, timeout: int = 5) -> dict:
    snmpget = shutil.which("snmpget")
    if not snmpget:
        return _result("connection_failed", "net-snmp 'snmpget' is not installed on the Nagios server (apt install snmp)")
    d = tempfile.mkdtemp(prefix="nmp-snmptest-")
    os.chmod(d, 0o700)
    try:
        lines = []
        if cred.get("version") == "3":
            lines += ["defVersion 3", f"defSecurityName {cred.get('username', '')}",
                      f"defSecurityLevel {cred.get('security_level') or 'authPriv'}"]
            for key, conf in (("auth_protocol", "defAuthType"), ("auth_password", "defAuthPassphrase"),
                              ("priv_protocol", "defPrivType"), ("priv_password", "defPrivPassphrase")):
                if cred.get(key):
                    lines.append(f"{conf} {cred[key]}")
        else:
            lines += ["defVersion 2c", f"defCommunity {cred.get('community', '')}"]
        fd = os.open(os.path.join(d, "snmp.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        t0 = time.monotonic()
        p = subprocess.run([snmpget, "-On", "-OQ", "-t", str(timeout), "-r", "0", address,
                            "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"],
                           capture_output=True, text=True, timeout=timeout + 5,
                           env={"SNMPCONFPATH": d, "PATH": "/usr/bin:/bin", "MIBS": ""}, shell=False)
        elapsed = round((time.monotonic() - t0) * 1000)
        if p.returncode == 0:
            vals = [ln.split(" = ", 1)[1].strip('"') for ln in p.stdout.splitlines() if " = " in ln]
            return _result("success", vals[1] if len(vals) > 1 else "SNMP agent responded",
                           sys_descr=vals[0][:200] if vals else None, response_ms=elapsed)
        err = (p.stderr or p.stdout).lower()
        if "timeout" in err:
            return _result("timeout", "No SNMP response (wrong community/credentials, ACL, or agent not running)")
        if "authentication" in err or "unknown user" in err or "wrong digest" in err:
            return _result("auth_failed", "SNMPv3 authentication failed")
        return _result("connection_failed", (p.stderr or "").strip().splitlines()[0][:200] if p.stderr else "SNMP error")
    except subprocess.TimeoutExpired:
        return _result("timeout", "SNMP request timed out")
    finally:
        shutil.rmtree(d, ignore_errors=True)
