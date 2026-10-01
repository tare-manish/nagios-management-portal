#!/usr/bin/python3
"""SNMP check wrapper for Nagios Management Portal (v2c / v3).

Credentials are read from the secrets file and handed to net-snmp through a
private temporary snmp.conf (SNMPCONFPATH), never on the command line.

Usage: check_snmp_nmp.py --nmp-key KEY -H HOST --mode MODE [options]
  --mode uptime                       sysUpTime (seconds)      [-w/-c ranges]
  --mode ifstatus  --if-index N       admin/oper status
  --mode ifutil    --if-index N [--if-speed MBPS]  utilisation %  [-w/-c]
  --mode bandwidth --if-index N       max(in,out) Mbps              [-w/-c]
  --mode oid       --oid OID          numeric OID value             [-w/-c]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import nmp_secrets  # noqa: E402

SNMPGET = shutil.which("snmpget") or "/usr/bin/snmpget"
STATE_DIR = "/usr/local/nagios/var/nmp-snmp-state"
STATES = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}


def finish(code, msg, perf=""):
    print(f"{STATES[code]}: {msg}" + (f" | {perf}" if perf else ""))
    sys.exit(code)


def snmp_conf(cred):
    d = tempfile.mkdtemp(prefix="nmp-snmp-")
    os.chmod(d, 0o700)
    lines = []
    if cred.get("version") == "3":
        lines += ["defVersion 3", f"defSecurityName {cred.get('username', '')}",
                  f"defSecurityLevel {cred.get('security_level', 'authPriv')}"]
        if cred.get("auth_protocol"):
            lines.append(f"defAuthType {cred['auth_protocol']}")
        if cred.get("auth_password"):
            lines.append(f"defAuthPassphrase {cred['auth_password']}")
        if cred.get("priv_protocol"):
            lines.append(f"defPrivType {cred['priv_protocol']}")
        if cred.get("priv_password"):
            lines.append(f"defPrivPassphrase {cred['priv_password']}")
    else:
        lines += ["defVersion 2c", f"defCommunity {cred.get('community', '')}"]
    path = os.path.join(d, "snmp.conf")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return d


def get(host, oids, confdir, timeout):
    env = {"SNMPCONFPATH": confdir, "PATH": "/usr/bin:/bin", "MIBS": ""}
    cmd = [SNMPGET, "-On", "-OQ", "-Oe", "-t", str(timeout), "-r", "1", host] + list(oids)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3 + 5, env=env)
    except subprocess.TimeoutExpired:
        finish(3, "SNMP request timed out")
    if p.returncode != 0:
        err = (p.stderr or p.stdout).strip().splitlines()
        finish(3 if "Timeout" not in (p.stderr or "") else 2, "SNMP error: " + (err[0] if err else "unknown"))
    out = {}
    for line in p.stdout.splitlines():
        if " = " in line:
            k, v = line.split(" = ", 1)
            out[k.strip().lstrip(".")] = v.strip().strip('"')
    return out


def evaluate(value, warn, crit):
    if crit and nmp_secrets.in_range(value, crit):
        return 2
    if warn and nmp_secrets.in_range(value, warn):
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nmp-key", required=True)
    ap.add_argument("-H", dest="host", required=True)
    ap.add_argument("--mode", required=True, choices=["uptime", "ifstatus", "ifutil", "bandwidth", "oid"])
    ap.add_argument("--if-index", type=int)
    ap.add_argument("--if-speed", type=float, default=0.0)
    ap.add_argument("--oid")
    ap.add_argument("-w", dest="warn")
    ap.add_argument("-c", dest="crit")
    ap.add_argument("--timeout", type=int, default=5)
    a = ap.parse_args()
    cred = nmp_secrets.lookup(a.nmp_key, "snmp")
    if not cred:
        finish(3, f"no SNMP credential found for {a.nmp_key}")
    confdir = snmp_conf(cred)
    try:
        run(a, confdir)
    finally:
        shutil.rmtree(confdir, ignore_errors=True)


def run(a, confdir):
    if a.mode == "uptime":
        oid = "1.3.6.1.2.1.1.3.0"
        v = get(a.host, [oid], confdir, a.timeout).get(oid, "")
        try:
            secs = int(v.split()[0]) / 100.0 if v and v.split()[0].isdigit() else float(v)
        except ValueError:
            finish(3, f"unexpected sysUpTime value '{v}'")
        d, rem = divmod(int(secs), 86400)
        h, rem = divmod(rem, 3600)
        code = evaluate(secs, a.warn, a.crit)
        finish(code, f"Uptime {d}d {h}h {rem // 60}m", f"uptime={int(secs)}s;{a.warn or ''};{a.crit or ''}")
    if a.mode == "oid":
        if not a.oid:
            finish(3, "--oid required")
        oid = a.oid.lstrip(".")
        v = get(a.host, [oid], confdir, a.timeout).get(oid)
        try:
            num = float(str(v).split()[0])
        except (TypeError, ValueError, IndexError):
            finish(0 if not (a.warn or a.crit) else 3, f"OID {oid} = {v}")
        finish(evaluate(num, a.warn, a.crit), f"OID {oid} = {num}", f"value={num};{a.warn or ''};{a.crit or ''}")
    if a.if_index is None:
        finish(3, "--if-index required")
    idx = a.if_index
    if a.mode == "ifstatus":
        oids = {"admin": f"1.3.6.1.2.1.2.2.1.7.{idx}", "oper": f"1.3.6.1.2.1.2.2.1.8.{idx}",
                "descr": f"1.3.6.1.2.1.2.2.1.2.{idx}"}
        r = get(a.host, list(oids.values()), confdir, a.timeout)
        admin, oper, descr = (r.get(oids["admin"], ""), r.get(oids["oper"], ""), r.get(oids["descr"], f"if{idx}"))
        if admin.startswith("2") or "down" in admin:
            finish(0, f"{descr} is administratively down")
        if oper.startswith("1") or oper.startswith("up"):
            finish(0, f"{descr} is up")
        finish(2, f"{descr} is DOWN (oper={oper})")
    # ifutil / bandwidth
    oids = {"in": f"1.3.6.1.2.1.31.1.1.1.6.{idx}", "out": f"1.3.6.1.2.1.31.1.1.1.10.{idx}",
            "speed": f"1.3.6.1.2.1.31.1.1.1.15.{idx}", "name": f"1.3.6.1.2.1.31.1.1.1.1.{idx}"}
    r = get(a.host, list(oids.values()), confdir, a.timeout)
    try:
        cin, cout = int(r[oids["in"]]), int(r[oids["out"]])
    except (KeyError, ValueError):
        finish(3, "interface counters not available (ifHCInOctets/ifHCOutOctets)")
    name = r.get(oids["name"], f"if{idx}")
    speed = a.if_speed or float(r.get(oids["speed"], "0") or 0)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    sfile = os.path.join(STATE_DIR, f"{a.nmp_key}-{a.host}-{idx}.json".replace("/", "_"))
    now = time.time()
    prev = None
    try:
        with open(sfile) as fh:
            prev = json.load(fh)
    except (OSError, ValueError):
        pass
    with open(sfile, "w") as fh:
        json.dump({"t": now, "in": cin, "out": cout}, fh)
    if not prev or now - prev["t"] <= 0 or cin < prev["in"] or cout < prev["out"]:
        finish(0, f"{name}: collecting baseline")
    dt = now - prev["t"]
    in_mbps = (cin - prev["in"]) * 8 / dt / 1e6
    out_mbps = (cout - prev["out"]) * 8 / dt / 1e6
    perf = f"in={in_mbps:.3f}Mbps out={out_mbps:.3f}Mbps"
    if a.mode == "bandwidth":
        peak = max(in_mbps, out_mbps)
        finish(evaluate(peak, a.warn, a.crit), f"{name}: in {in_mbps:.2f} Mbps, out {out_mbps:.2f} Mbps",
               perf + f" peak={peak:.3f};{a.warn or ''};{a.crit or ''}")
    if speed <= 0:
        finish(3, f"{name}: interface speed unknown, set --if-speed")
    util = max(in_mbps, out_mbps) / speed * 100.0
    finish(evaluate(util, a.warn, a.crit), f"{name}: utilisation {util:.1f}% of {speed:g} Mbps",
           perf + f" util={util:.2f}%;{a.warn or ''};{a.crit or ''};0;100")


if __name__ == "__main__":
    main()
