"""Application settings.

Values come from environment variables (loaded by systemd from
/etc/nagios-management/app.env). Nothing secret is hard-coded here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8").strip()


@dataclass(frozen=True)
class Settings:
    # --- database -------------------------------------------------------
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "nagios_mgmt"
    db_user: str = "nagios_mgmt"
    db_password: str = ""
    db_socket: str | None = "/run/mysqld/mysqld.sock"
    database_url_override: str | None = None

    # --- security -------------------------------------------------------
    master_key_file: str = "/etc/nagios-management/master.key"
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    cookie_secure: bool = True
    allowed_origins: tuple[str, ...] = ()
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    api_rate_limit_per_minute: int = 600
    password_min_length: int = 12

    # --- nagios ---------------------------------------------------------
    nagios_base: str = "/usr/local/nagios"
    nagios_cfg: str = "/usr/local/nagios/etc/nagios.cfg"
    nagios_status_file: str = "/usr/local/nagios/var/status.dat"
    nagios_log_file: str = "/usr/local/nagios/var/nagios.log"
    nagios_log_archive: str = "/usr/local/nagios/var/archives"
    nagios_command_file: str = "/usr/local/nagios/var/rw/nagios.cmd"
    nagios_objects_cache: str = "/usr/local/nagios/var/objects.cache"
    managed_dir: str = "/usr/local/nagios/etc/managed"
    staging_dir: str = "/var/lib/nagios-management/staging"
    backup_dir: str = "/var/lib/nagios-management/backups"
    plugin_dir_ncpa: str = "/usr/local/nagios/libexec"
    plugin_dir_nmp: str = "/usr/local/nagios/libexec/nmp"
    plugin_dir_std: str = "/usr/lib/nagios/plugins"
    nagios_service: str = "nagios"

    # --- privileged helper invocation ------------------------------------
    priv_mode: str = "sudo"  # sudo | direct (tests/dev only)
    priv_sbin: str = "/opt/nagios-management/privileged/sbin"
    priv_timeout: int = 180

    # --- app ------------------------------------------------------------
    log_dir: str = "/var/log/nagios-management"
    frontend_dist: str = "/opt/nagios-management/frontend/dist"
    display_timezone: str = "Asia/Kolkata"
    perf_retention_days: int = 90
    enable_api_docs: bool = True
    testing: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        from urllib.parse import quote_plus

        base = (
            f"mysql+pymysql://{quote_plus(self.db_user)}:{quote_plus(self.db_password)}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"
        )
        if self.db_socket and self.db_host in ("localhost", "") and Path(self.db_socket).exists():
            base += f"&unix_socket={quote_plus(self.db_socket)}"
        return base


def load_settings() -> Settings:
    pw = _env("NMP_DB_PASSWORD") or _read_secret_file(_env("NMP_DB_PASSWORD_FILE")) or ""
    origins = tuple(o.strip() for o in (_env("NMP_ALLOWED_ORIGINS", "") or "").split(",") if o.strip())
    return Settings(
        db_host=_env("NMP_DB_HOST", "localhost"),
        db_port=_env_int("NMP_DB_PORT", 3306),
        db_name=_env("NMP_DB_NAME", "nagios_mgmt"),
        db_user=_env("NMP_DB_USER", "nagios_mgmt"),
        db_password=pw,
        db_socket=_env("NMP_DB_SOCKET", "/run/mysqld/mysqld.sock"),
        database_url_override=_env("NMP_DATABASE_URL"),
        master_key_file=_env("NMP_MASTER_KEY_FILE", "/etc/nagios-management/master.key"),
        session_idle_minutes=_env_int("NMP_SESSION_IDLE_MINUTES", 30),
        session_absolute_hours=_env_int("NMP_SESSION_ABSOLUTE_HOURS", 12),
        cookie_secure=_env_bool("NMP_COOKIE_SECURE", True),
        allowed_origins=origins,
        login_max_failures=_env_int("NMP_LOGIN_MAX_FAILURES", 5),
        login_lockout_minutes=_env_int("NMP_LOGIN_LOCKOUT_MINUTES", 15),
        api_rate_limit_per_minute=_env_int("NMP_API_RATE_LIMIT", 600),
        nagios_base=_env("NMP_NAGIOS_BASE", "/usr/local/nagios"),
        nagios_cfg=_env("NMP_NAGIOS_CFG", "/usr/local/nagios/etc/nagios.cfg"),
        nagios_status_file=_env("NMP_NAGIOS_STATUS_FILE", "/usr/local/nagios/var/status.dat"),
        nagios_log_file=_env("NMP_NAGIOS_LOG_FILE", "/usr/local/nagios/var/nagios.log"),
        nagios_log_archive=_env("NMP_NAGIOS_LOG_ARCHIVE", "/usr/local/nagios/var/archives"),
        nagios_command_file=_env("NMP_NAGIOS_COMMAND_FILE", "/usr/local/nagios/var/rw/nagios.cmd"),
        nagios_objects_cache=_env("NMP_NAGIOS_OBJECTS_CACHE", "/usr/local/nagios/var/objects.cache"),
        managed_dir=_env("NMP_MANAGED_DIR", "/usr/local/nagios/etc/managed"),
        staging_dir=_env("NMP_STAGING_DIR", "/var/lib/nagios-management/staging"),
        backup_dir=_env("NMP_BACKUP_DIR", "/var/lib/nagios-management/backups"),
        plugin_dir_ncpa=_env("NMP_PLUGIN_DIR_NCPA", "/usr/local/nagios/libexec"),
        plugin_dir_nmp=_env("NMP_PLUGIN_DIR_NMP", "/usr/local/nagios/libexec/nmp"),
        plugin_dir_std=_env("NMP_PLUGIN_DIR_STD", "/usr/lib/nagios/plugins"),
        nagios_service=_env("NMP_NAGIOS_SERVICE", "nagios"),
        priv_mode=_env("NMP_PRIV_MODE", "sudo"),
        priv_sbin=_env("NMP_PRIV_SBIN", "/opt/nagios-management/privileged/sbin"),
        priv_timeout=_env_int("NMP_PRIV_TIMEOUT", 180),
        log_dir=_env("NMP_LOG_DIR", "/var/log/nagios-management"),
        frontend_dist=_env("NMP_FRONTEND_DIST", "/opt/nagios-management/frontend/dist"),
        display_timezone=_env("NMP_DISPLAY_TZ", "Asia/Kolkata"),
        perf_retention_days=_env_int("NMP_PERF_RETENTION_DAYS", 90),
        enable_api_docs=_env_bool("NMP_ENABLE_API_DOCS", True),
        testing=_env_bool("NMP_TESTING", False),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
