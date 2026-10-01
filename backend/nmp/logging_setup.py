"""Logging to /var/log/nagios-management/{application,configuration,security,audit,error}.log

A redaction filter scrubs anything that looks like a token, password,
community string or API key before a record reaches any handler.
"""
from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path

from .config import get_settings

_REDACTIONS = [
    re.compile(r"(?i)((?:token|password|passwd|pwd|secret|community|api[_-]?key|authpass|privpass|auth_pass|priv_pass)[\"']?\s*[:=]\s*[\"']?)([^\s\"'&,}]+)"),
    re.compile(r"(?i)((?:^|\s)(?:-t|--token|-C|--community|-A|-X)\s+)(\S+)"),
    re.compile(r"(?i)(authorization:\s*\w+\s+)(\S+)"),
]


def redact(text: str) -> str:
    for rx in _REDACTIONS:
        text = rx.sub(lambda m: m.group(1) + "***", text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        record.msg = redact(msg)
        record.args = None
        return True


_configured = False


def setup_logging() -> None:
    global _configured
    if _configured:
        return
    _configured = True
    s = get_settings()
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s", "%Y-%m-%dT%H:%M:%S%z")
    redactor = RedactingFilter()
    log_dir = Path(s.log_dir)
    can_write = log_dir.is_dir() and _writable(log_dir)

    def handler(filename: str, level: int = logging.INFO) -> logging.Handler:
        h: logging.Handler
        try:
            if not can_write:
                raise PermissionError
            h = logging.handlers.WatchedFileHandler(str(log_dir / filename), encoding="utf-8")
        except OSError:
            h = logging.StreamHandler()  # never let a log-file permission problem stop the service
        h.setLevel(level)
        h.setFormatter(fmt)
        h.addFilter(redactor)
        return h

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler("application.log"))
    root.addHandler(handler("error.log", logging.ERROR))

    for name, fname in (("nmp.config", "configuration.log"), ("nmp.security", "security.log"), ("nmp.audit", "audit.log")):
        lg = logging.getLogger(name)
        lg.addHandler(handler(fname))
    # never log full request URLs from HTTP client libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _writable(p: Path) -> bool:
    import os

    return os.access(p, os.W_OK)
