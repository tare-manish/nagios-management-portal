"""Whitelisted Nagios external commands (acknowledge, downtime, re-check).

Written to the Nagios command pipe (nagios.cmd). Only the commands below
can be produced; every argument is validated and must not contain ';' or
newlines. Host/service names must exist in the live status snapshot.
"""
from __future__ import annotations

import errno
import os
import re
import time

from ..config import get_settings
from .status import get_status

_SAFE = re.compile(r"^[^;\n\r\x00]{0,255}$")


class ExternalCommandError(Exception):
    pass


def _check(v: str, field: str) -> str:
    v = str(v)
    if not _SAFE.match(v):
        raise ExternalCommandError(f"invalid {field}")
    return v


def _require_object(host: str, service: str | None = None) -> None:
    st = get_status()
    if st.error:
        raise ExternalCommandError("Nagios status is not available")
    if host not in st.hosts:
        raise ExternalCommandError(f"unknown host '{host}'")
    if service is not None and (host, service) not in st.services:
        raise ExternalCommandError(f"unknown service '{service}' on host '{host}'")


def _write(line: str) -> None:
    path = get_settings().nagios_command_file
    payload = f"[{int(time.time())}] {line}\n".encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ENXIO:
            raise ExternalCommandError("Nagios is not reading its command pipe (is Nagios running?)")
        raise ExternalCommandError(f"cannot open Nagios command pipe: {exc.strerror}")
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def acknowledge(host: str, service: str | None, author: str, comment: str, sticky: bool = True,
                notify: bool = True, persistent: bool = False) -> str:
    _require_object(host, service)
    a = [_check(host, "host")]
    if service is not None:
        a.append(_check(service, "service"))
    a += ["2" if sticky else "1", "1" if notify else "0", "1" if persistent else "0",
          _check(author, "author"), _check(comment, "comment")]
    cmd = ("ACKNOWLEDGE_SVC_PROBLEM;" if service else "ACKNOWLEDGE_HOST_PROBLEM;") + ";".join(a)
    _write(cmd)
    return cmd


def remove_acknowledgement(host: str, service: str | None) -> str:
    _require_object(host, service)
    cmd = (f"REMOVE_SVC_ACKNOWLEDGEMENT;{_check(host, 'host')};{_check(service, 'service')}" if service
           else f"REMOVE_HOST_ACKNOWLEDGEMENT;{_check(host, 'host')}")
    _write(cmd)
    return cmd


def schedule_downtime(host: str, service: str | None, start: int, end: int, author: str, comment: str,
                      include_services: bool = False, fixed: bool = True, duration: int = 0) -> str:
    _require_object(host, service)
    if end <= start or end - start > 86400 * 90:
        raise ExternalCommandError("invalid downtime window (max 90 days)")
    common = f"{int(start)};{int(end)};{1 if fixed else 0};0;{int(duration or end - start)};" \
             f"{_check(author, 'author')};{_check(comment, 'comment')}"
    if service:
        cmd = f"SCHEDULE_SVC_DOWNTIME;{_check(host, 'host')};{_check(service, 'service')};{common}"
        _write(cmd)
    else:
        cmd = f"SCHEDULE_HOST_DOWNTIME;{_check(host, 'host')};{common}"
        _write(cmd)
        if include_services:
            _write(f"SCHEDULE_HOST_SVC_DOWNTIME;{_check(host, 'host')};{common}")
    return cmd


def delete_downtime(downtime_id: int, kind: str) -> str:
    if kind not in ("host", "service"):
        raise ExternalCommandError("invalid downtime kind")
    cmd = f"{'DEL_HOST_DOWNTIME' if kind == 'host' else 'DEL_SVC_DOWNTIME'};{int(downtime_id)}"
    _write(cmd)
    return cmd


def recheck(host: str, service: str | None = None, all_services: bool = False) -> str:
    _require_object(host, service)
    now = int(time.time())
    if service:
        cmd = f"SCHEDULE_FORCED_SVC_CHECK;{_check(host, 'host')};{_check(service, 'service')};{now}"
    elif all_services:
        cmd = f"SCHEDULE_FORCED_HOST_SVC_CHECKS;{_check(host, 'host')};{now}"
        _write(f"SCHEDULE_FORCED_HOST_CHECK;{_check(host, 'host')};{now}")
    else:
        cmd = f"SCHEDULE_FORCED_HOST_CHECK;{_check(host, 'host')};{now}"
    _write(cmd)
    return cmd
