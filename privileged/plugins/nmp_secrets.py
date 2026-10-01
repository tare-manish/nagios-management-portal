"""Credential lookup for NMP check wrappers (imported by the plugins)."""
import base64
import json

SECRETS_FILE = "/usr/local/nagios/etc/managed-secrets/nmp-secrets.tsv"


def lookup(key, kind):
    try:
        with open(SECRETS_FILE, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3 and parts[0] == key and parts[1] == kind:
                    return json.loads(base64.b64decode(parts[2]).decode("utf-8"))
    except (OSError, ValueError):
        return None
    return None


def in_range(value, spec):
    """Nagios threshold semantics: return True when value triggers an alert."""
    if spec is None or spec == "":
        return False
    inside = spec.startswith("@")
    if inside:
        spec = spec[1:]
    if ":" in spec:
        lo_s, hi_s = spec.split(":", 1)
    else:
        lo_s, hi_s = "0", spec
    lo = float("-inf") if lo_s in ("~",) else float(lo_s or 0)
    hi = float("inf") if hi_s == "" else float(hi_s)
    outside = value < lo or value > hi
    return (not outside) if inside else outside
