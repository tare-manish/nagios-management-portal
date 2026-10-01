"""Input validation shared by API schemas and the config generator.

Everything that ends up inside a Nagios object file or a check command line
passes through one of these validators. Nagios runs check commands through
/bin/sh when they contain shell metacharacters, so values are restricted to
conservative character sets (defence in depth: the generator re-validates).
"""
from __future__ import annotations

import ipaddress
import re

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
OBJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SERVICE_DESC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,99}$")
FQDN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
# Nagios range syntax plus "rta,pl%" form used by check_ping.
THRESHOLD_RE = re.compile(r"^[0-9.,:@~%-]{0,40}$")
TIMEPERIOD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
NOTIF_OPTS_HOST_RE = re.compile(r"^([durfsn](,[durfsn])*)$")
NOTIF_OPTS_SVC_RE = re.compile(r"^([wucrfsn](,[wucrfsn])*)$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")

# Parameter types used by service catalog params_schema
PARAM_PATTERNS: dict[str, re.Pattern] = {
    "drive": re.compile(r"^[A-Za-z]$"),
    "mount": re.compile(r"^/[A-Za-z0-9_./-]{0,120}$"),
    "winservice": re.compile(r"^[A-Za-z0-9_.$-][A-Za-z0-9_.$ -]{0,79}$"),
    "process": re.compile(r"^[A-Za-z0-9_.-]{1,80}$"),
    "interface": re.compile(r"^[A-Za-z0-9_. -]{1,64}$"),
    "metric": re.compile(r"^[A-Za-z0-9_/|:.-]{1,200}$"),
    "query": re.compile(r"^[A-Za-z0-9_=,.:/-]{0,200}$"),
    "logname": re.compile(r"^[A-Za-z0-9 _.-]{1,64}$"),
    "severity": re.compile(r"^(ERROR|WARNING|INFORMATION|CRITICAL|AUDIT_FAILURE)$"),
    "window": re.compile(r"^[0-9]{1,4}[smhd]$"),
    "state": re.compile(r"^(running|stopped)$"),
    "mismatch": re.compile(r"^(warning|critical)$"),
    "direction": re.compile(r"^(recv|sent)$"),
    "int": re.compile(r"^[0-9]{1,9}$"),
    "oid": re.compile(r"^\.?[0-9]+(\.[0-9]+){1,40}$"),
    "units": re.compile(r"^(|k|Ki|M|Mi|G|Gi|T|Ti)$"),
    "args": re.compile(r"^[A-Za-z0-9 _=,.:/%@~+-]{0,300}$"),
    "plugin": re.compile(r"^[A-Za-z0-9_.-]{1,80}$"),
    "text": re.compile(r"^[A-Za-z0-9 _.,:/()+-]{0,120}$"),
}

# Characters that would break a Nagios object file line or a command line.
_UNSAFE_FREE_TEXT = re.compile(r"[;$`\\!\x00-\x1f\x7f<>|&]")


class ValidationError(ValueError):
    def __init__(self, field: str, message: str):
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


def check_hostname(v: str, field: str = "hostname") -> str:
    v = (v or "").strip()
    if not HOSTNAME_RE.match(v):
        raise ValidationError(field, "1-63 chars: letters, digits, '.', '_' or '-' (must start alphanumeric)")
    return v


def check_object_name(v: str, field: str = "name") -> str:
    v = (v or "").strip()
    if not OBJECT_NAME_RE.match(v):
        raise ValidationError(field, "1-64 chars: letters, digits, '.', '_' or '-'")
    return v


def check_service_description(v: str, field: str = "service_description") -> str:
    v = (v or "").strip()
    if not SERVICE_DESC_RE.match(v) or "  " in v:
        raise ValidationError(field, "1-100 chars: letters, digits, space and . _ : / + -")
    return v


def check_address(v: str, field: str = "address") -> str:
    v = (v or "").strip()
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if FQDN_RE.match(v) and not v.replace(".", "").isdigit():
        return v.rstrip(".")
    raise ValidationError(field, "must be a valid IPv4/IPv6 address or DNS name")


def check_threshold(v: str | None, field: str) -> str | None:
    if v is None or str(v).strip() == "":
        return None
    v = str(v).strip()
    if not THRESHOLD_RE.match(v):
        raise ValidationError(field, "invalid threshold (use Nagios range syntax, e.g. 80, 10:, ~:90, @5:10, 200.0,20%)")
    return v


def check_free_text(v: str | None, field: str, max_len: int = 120, required: bool = False) -> str | None:
    if v is None or str(v).strip() == "":
        if required:
            raise ValidationError(field, "is required")
        return None
    v = " ".join(str(v).split())
    if len(v) > max_len:
        raise ValidationError(field, f"must be at most {max_len} characters")
    if _UNSAFE_FREE_TEXT.search(v):
        raise ValidationError(field, "contains characters that are not allowed ( ; $ ` \\ ! < > | & )")
    return v


def check_timeperiod(v: str, field: str) -> str:
    if not TIMEPERIOD_RE.match(v or ""):
        raise ValidationError(field, "invalid time period name")
    return v


def check_interval(v: int, field: str, lo: int = 1, hi: int = 1440) -> int:
    try:
        iv = int(v)
    except (TypeError, ValueError):
        raise ValidationError(field, "must be an integer")
    if iv < lo or iv > hi:
        raise ValidationError(field, f"must be between {lo} and {hi}")
    return iv


def check_email(v: str | None, field: str = "email") -> str | None:
    if not v:
        return None
    v = v.strip()
    if not EMAIL_RE.match(v):
        raise ValidationError(field, "invalid e-mail address")
    return v


def check_param(ptype: str, value, field: str) -> str:
    rx = PARAM_PATTERNS.get(ptype)
    if rx is None:
        raise ValidationError(field, f"unknown parameter type {ptype}")
    sval = "" if value is None else str(value).strip()
    if not rx.match(sval):
        raise ValidationError(field, f"invalid value for {ptype}")
    return sval


def validate_params(schema: list[dict], params: dict | None) -> dict:
    """Validate a params dict against a catalog params_schema list."""
    params = params or {}
    out: dict[str, str] = {}
    known = {p["name"] for p in schema}
    for k in params:
        if k not in known:
            raise ValidationError(f"params.{k}", "unknown parameter")
    for p in schema:
        name = p["name"]
        val = params.get(name, p.get("default"))
        if (val is None or str(val).strip() == "") and not p.get("required", False):
            out[name] = "" if p.get("default") is None else str(p["default"])
            continue
        if val is None or str(val).strip() == "":
            raise ValidationError(f"params.{name}", "is required")
        out[name] = check_param(p["type"], val, f"params.{name}")
    return out


# --- custom command lines (admin-defined) --------------------------------
_CMD_FORBIDDEN = re.compile(r"(;|&&|\|\||`|\$\(|>|<|\n|\r|\\)")
_MACRO_RE = re.compile(r"\$[A-Za-z0-9_]+\$")


def check_command_line(v: str, allowed_prefixes: list[str]) -> str:
    v = (v or "").strip()
    if not v or len(v) > 1024:
        raise ValidationError("command_line", "must be 1-1024 characters")
    if _CMD_FORBIDDEN.search(v):
        raise ValidationError("command_line", "shell operators ; && || ` $( > < \\ are not allowed")
    exe = v.split()[0]
    if not any(exe.startswith(p) for p in allowed_prefixes):
        raise ValidationError("command_line", "must start with an approved plugin directory: " + ", ".join(allowed_prefixes))
    if ".." in exe:
        raise ValidationError("command_line", "path traversal is not allowed")
    # only whitelisted-safe characters outside macros
    stripped = _MACRO_RE.sub("", v)
    if "$" in stripped:
        raise ValidationError("command_line", "stray '$' (only $MACRO$ tokens allowed)")
    if "|" in stripped.replace("'", "").replace('"', "") and not re.search(r"'[^']*\|[^']*'", v):
        raise ValidationError("command_line", "pipes are only allowed inside single quotes")
    return v
