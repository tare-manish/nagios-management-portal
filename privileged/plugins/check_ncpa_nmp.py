#!/usr/bin/python3
"""NCPA check wrapper for Nagios Management Portal.

Looks up the agent token for --nmp-key in the root/nagios-only secrets file
and runs the stock check_ncpa.py *in-process*, so the token never appears
on a command line, in `ps` output, in Nagios object files or in logs.

Extra options (consumed here, not passed to check_ncpa.py):
  --nmp-key KEY                  host key (srv-<id>) for token lookup
  --nmp-ssl=verify|noverify      require certificate verification (-s)
  --nmp-mismatch=warning|critical  state to report when a Windows service
                                 check does not match (default critical)
"""
import io
import os
import runpy
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import nmp_secrets  # noqa: E402

CHECK_NCPA = "/usr/local/nagios/libexec/check_ncpa.py"


def unknown(msg):
    print("UNKNOWN: " + msg)
    sys.exit(3)


def main():
    args = sys.argv[1:]
    key, ssl, mismatch, rest = None, "noverify", "critical", []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--nmp-key" and i + 1 < len(args):
            key = args[i + 1]
            i += 2
            continue
        if a.startswith("--nmp-ssl="):
            ssl = a.split("=", 1)[1]
        elif a.startswith("--nmp-mismatch="):
            mismatch = a.split("=", 1)[1]
        elif a in ("-t", "--token") or a.startswith("--token="):
            unknown("token must not be passed on the command line")
        else:
            rest.append(a)
        i += 1
    if not key:
        unknown("missing --nmp-key")
    cred = nmp_secrets.lookup(key, "ncpa")
    if not cred or not cred.get("token"):
        unknown("no NCPA credential found for " + key + " (apply configuration from the portal)")
    argv = [CHECK_NCPA] + rest + ["-t", cred["token"]]
    if ssl == "verify":
        argv.append("-s")
    sys.argv = argv
    buf = io.StringIO()
    code = 3
    try:
        with redirect_stdout(buf):
            runpy.run_path(CHECK_NCPA, run_name="__main__")
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 3)
    except Exception as exc:  # plugin crashed
        out = buf.getvalue().replace(cred["token"], "***")
        print("UNKNOWN: check_ncpa failed: " + type(exc).__name__ + " " + out[:200])
        sys.exit(3)
    out = buf.getvalue().replace(cred["token"], "***")
    if mismatch == "warning" and code == 2:
        code = 1
        if out.startswith("CRITICAL"):
            out = "WARNING" + out[len("CRITICAL"):]
    sys.stdout.write(out)
    sys.exit(code)


if __name__ == "__main__":
    main()
