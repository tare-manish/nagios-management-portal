"""The ONLY place the web application executes external programs with privileges.

Commands are a fixed whitelist of root-owned scripts; arguments are
validated against strict patterns; subprocess is always called with an
argument list (never a shell).
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path

from ..config import get_settings

log = logging.getLogger("nmp.config")

_SCRIPTS = {
    "validate": ("nagios-config-validate", re.compile(r"^[0-9]{1,10}$")),
    "apply": ("nagios-config-apply", re.compile(r"^[0-9]{1,10}$")),
    "backup": ("nagios-config-backup", re.compile(r"^[a-z0-9-]{1,40}$")),
    "rollback": ("nagios-config-rollback", re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,60}$")),
    "status": ("nagios-status-check", None),
    "backup_delete": ("nagios-config-backup-delete", re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,60}$")),
}


class PrivilegedError(Exception):
    pass


def run(action: str, arg: str | None = None) -> dict:
    if action not in _SCRIPTS:
        raise PrivilegedError(f"action not allowed: {action}")
    script, pattern = _SCRIPTS[action]
    if pattern is None:
        if arg is not None:
            raise PrivilegedError("this action takes no argument")
        args: list[str] = []
    else:
        if arg is None or not pattern.match(str(arg)):
            raise PrivilegedError("invalid argument")
        args = [str(arg)]
    s = get_settings()
    path = str(Path(s.priv_sbin) / script)
    if s.priv_mode == "sudo":
        cmd = ["/usr/bin/sudo", "-n", path] + args
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    elif s.priv_mode == "direct":  # development / automated tests only
        cmd = [path] + args
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
        if os.environ.get("NMP_PRIV_CONF"):
            env["NMP_PRIV_CONF"] = os.environ["NMP_PRIV_CONF"]
    else:
        raise PrivilegedError("invalid priv_mode")
    log.info("privileged action=%s arg=%s", action, args[0] if args else "")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=s.priv_timeout, env=env,
                              shell=False, cwd="/")
    except subprocess.TimeoutExpired:
        raise PrivilegedError(f"{script} timed out after {s.priv_timeout}s")
    except OSError as exc:
        raise PrivilegedError(f"cannot execute {script}: {exc}")
    out = (proc.stdout or "").strip().splitlines()
    try:
        result = json.loads(out[-1]) if out else {}
    except json.JSONDecodeError:
        result = {}
    if not result:
        err = (proc.stderr or "").strip()[:500]
        if "password is required" in err or "a password is required" in err or "not allowed" in err:
            raise PrivilegedError("sudo rule for the portal is missing or incorrect (see docs/TROUBLESHOOTING.md)")
        raise PrivilegedError(f"{script} returned no result (rc={proc.returncode}) {err}")
    log.info("privileged action=%s ok=%s", action, result.get("ok"))
    return result
