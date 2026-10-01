"""Shared implementation of the privileged configuration pipeline.

Pipeline (apply):  lock -> verify staging integrity -> VALIDATE (staged copy)
                   -> BACKUP -> install (atomic dir swap) -> validate live
                   -> RELOAD -> VERIFY -> (on any failure) restore previous
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import grp
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

CONF_PATH = "/etc/nagios-management/privileged.json"

DEFAULTS = {
    "nagios_bin": "/usr/local/nagios/bin/nagios",
    "nagios_cfg": "/usr/local/nagios/etc/nagios.cfg",
    "nagios_user": "nagios",
    "nagios_group": "nagios",
    "managed_dir": "/usr/local/nagios/etc/managed",
    "secrets_dir": "/usr/local/nagios/etc/managed-secrets",
    "staging_dir": "/var/lib/nagios-management/staging",
    "work_dir": "/var/lib/nagios-management/work",
    "backup_dir": "/var/lib/nagios-management/backups",
    "backup_keep": 200,
    "reload_method": "systemctl",       # systemctl | signal | none
    "nagios_service": "nagios",
    "app_user": "nagmgmt",
    "app_group": "nagmgmt",
    "verify_timeout": 45,
    "validate_timeout": 120,
    "log_file": "/var/log/nagios-management/configuration.log",
}

VERSION_RE = re.compile(r"^[0-9]{1,10}$")
BACKUP_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,60}$")
REASON_RE = re.compile(r"^[a-z0-9-]{1,40}$")
REL_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")


# ------------------------------------------------------------------ output --
class PipelineError(Exception):
    def __init__(self, message: str, **extra):
        super().__init__(message)
        self.extra = extra


def emit(obj: dict, code: int = 0) -> None:
    sys.stdout.write(json.dumps(obj, default=str))
    sys.stdout.write("\n")
    sys.stdout.flush()
    sys.exit(code)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# -------------------------------------------------------------------- conf --
def load_conf() -> dict:
    path = CONF_PATH
    override = os.environ.get("NMP_PRIV_CONF")
    # An override is honoured only when not invoked through sudo (tests/dev).
    if override and not os.environ.get("SUDO_USER"):
        path = override
    conf = dict(DEFAULTS)
    p = Path(path)
    if p.exists():
        st = p.stat()
        if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
            if st.st_uid != 0 or (st.st_mode & 0o022):
                raise PipelineError(f"{path} must be owned by root and not group/world writable")
        conf.update(json.loads(p.read_text()))
    return conf


class Logger:
    def __init__(self, conf: dict):
        self.path = conf.get("log_file")
        self.steps: list[dict] = []

    def step(self, name: str, status: str, detail: str = "") -> None:
        entry = {"time": now_utc().isoformat(timespec="seconds"), "step": name, "status": status, "detail": detail}
        self.steps.append(entry)
        try:
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(f"{entry['time']} [{name}] {status} {detail}\n")
        except OSError:
            pass


# ----------------------------------------------------------------- helpers --
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def ids(conf: dict) -> tuple[int, int, int]:
    """(nagios uid, nagios gid, nagios group gid)"""
    try:
        pw = pwd.getpwnam(conf["nagios_user"])
        gid = grp.getgrnam(conf["nagios_group"]).gr_gid
        return pw.pw_uid, pw.pw_gid, gid
    except KeyError as exc:
        raise PipelineError(f"nagios user/group not found: {exc}")


def is_root() -> bool:
    return os.geteuid() == 0


def chown_safe(path: Path, uid: int, gid: int) -> None:
    if is_root():
        os.chown(path, uid, gid, follow_symlinks=False)


class Lock:
    def __init__(self, conf: dict, timeout: int = 90):
        Path(conf["work_dir"]).mkdir(parents=True, exist_ok=True, mode=0o750)
        self.path = Path(conf["work_dir"]) / ".pipeline.lock"
        self.timeout = timeout
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "w")
        deadline = time.time() + self.timeout
        while True:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.time() > deadline:
                    raise PipelineError("another configuration operation is in progress (lock timeout)")
                time.sleep(0.5)

    def __exit__(self, *exc):
        if self.fh:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()


def read_nagios_cfg(conf: dict) -> list[str]:
    return Path(conf["nagios_cfg"]).read_text(encoding="utf-8", errors="replace").splitlines()


def cfg_directive(lines: list[str], key: str) -> list[str]:
    vals = []
    for ln in lines:
        s = ln.strip()
        if not s or s[0] in "#;":
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            if k.strip() == key:
                vals.append(v.strip())
    return vals


# ------------------------------------------------------------ staging area --
def stage_path(conf: dict, version: str) -> Path:
    if not VERSION_RE.match(version):
        raise PipelineError("invalid version id")
    base = Path(conf["staging_dir"]).resolve()
    p = (base / f"v{version}")
    if p.is_symlink() or not p.is_dir():
        raise PipelineError(f"staging directory for version {version} not found")
    if p.resolve().parent != base:
        raise PipelineError("staging path escapes staging directory")
    return p


def load_manifest(stage: Path) -> dict:
    mf = stage / "manifest.json"
    if mf.is_symlink() or not mf.is_file():
        raise PipelineError("manifest.json missing")
    manifest = json.loads(mf.read_text(encoding="utf-8"))
    stage_real = stage.resolve()
    for section in ("files", "secrets"):
        for rel, digest in (manifest.get(section) or {}).items():
            _check_rel(rel)
            base = "managed" if section == "files" else "secrets"
            f = stage / base / rel
            if f.is_symlink() or not f.is_file():
                raise PipelineError(f"staged file missing or not a regular file: {base}/{rel}")
            if stage_real not in f.resolve().parents:
                raise PipelineError("staged file escapes staging directory")
            if sha256_file(f) != digest:
                raise PipelineError(f"integrity check failed for {base}/{rel}")
    # no unexpected files inside managed/ (everything must be in the manifest)
    listed = set(manifest.get("files") or {})
    managed_root = stage / "managed"
    if managed_root.is_dir():
        for f in managed_root.rglob("*"):
            if f.is_symlink():
                raise PipelineError("symlinks are not allowed in staging")
            if f.is_file() and str(f.relative_to(managed_root)) not in listed:
                raise PipelineError(f"unlisted file in staging: {f.relative_to(managed_root)}")
    for ov in manifest.get("overrides") or []:
        _check_rel(ov["file"])
        f = stage / "overrides" / ov["file"]
        if f.is_symlink() or not f.is_file() or sha256_file(f) != ov["sha256"]:
            raise PipelineError(f"integrity check failed for override {ov['file']}")
        if not os.path.isabs(ov["target"]) or ".." in ov["target"]:
            raise PipelineError("invalid override target")
    return manifest


def _check_rel(rel: str) -> None:
    if not REL_PATH_RE.match(rel) or ".." in rel.split("/"):
        raise PipelineError(f"invalid relative path in manifest: {rel}")


def check_override_targets(conf: dict, manifest: dict) -> None:
    """Overrides may only replace existing object files already loaded by nagios.cfg."""
    lines = read_nagios_cfg(conf)
    cfg_files = set(cfg_directive(lines, "cfg_file"))
    cfg_dirs = [d.rstrip("/") for d in cfg_directive(lines, "cfg_dir")]
    managed = conf["managed_dir"].rstrip("/")
    for ov in manifest.get("overrides") or []:
        t = ov["target"]
        if not t.endswith(".cfg"):
            raise PipelineError(f"override target must be a .cfg file: {t}")
        if t.startswith(managed + "/"):
            raise PipelineError("override target may not be inside the managed directory")
        in_dir = any(t.startswith(d + "/") for d in cfg_dirs)
        if t not in cfg_files and not in_dir:
            raise PipelineError(f"override target is not part of the Nagios configuration: {t}")
        if not Path(t).is_file():
            raise PipelineError(f"override target does not exist: {t}")
        current = sha256_file(Path(t))
        if current != ov["sha256_before"]:
            raise PipelineError(
                f"{t} was modified after the change was prepared - regenerate the configuration",
                file=t)


# ---------------------------------------------------------------- validate --
def _copytree_for_nagios(src: Path, dst: Path, conf: dict) -> None:
    uid, _, gid = ids(conf)
    shutil.copytree(src, dst, symlinks=False)
    for root, dirs, files in os.walk(dst):
        os.chmod(root, 0o750)
        chown_safe(Path(root), 0, gid)
        for f in files:
            fp = Path(root) / f
            os.chmod(fp, 0o640)
            chown_safe(fp, 0, gid)


def build_validation_tree(conf: dict, stage: Path, manifest: dict, label: str) -> tuple[Path, Path, dict]:
    """Create a temp copy of nagios.cfg pointing at the staged managed dir.

    Returns (work_dir, temp_nagios_cfg, path_map) where path_map maps temp
    paths back to meaningful names for error reporting.
    """
    work_base = Path(conf["work_dir"])
    work_base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"validate-{label}-", dir=work_base))
    _, _, gid = ids(conf)
    os.chmod(work, 0o750)
    chown_safe(work, 0, gid)
    path_map: dict[str, str] = {}

    managed_copy = work / "managed"
    _copytree_for_nagios(stage / "managed", managed_copy, conf)
    path_map[str(managed_copy)] = "managed"

    lines = read_nagios_cfg(conf)
    managed = conf["managed_dir"].rstrip("/")
    out_lines: list[str] = []
    found_managed = False
    overrides = {ov["target"]: stage / "overrides" / ov["file"] for ov in (manifest.get("overrides") or [])}
    dir_overrides: dict[str, list[tuple[str, Path]]] = {}
    cfg_files = set(cfg_directive(lines, "cfg_file"))
    for t, src in overrides.items():
        if t not in cfg_files:
            for d in cfg_directive(lines, "cfg_dir"):
                if t.startswith(d.rstrip("/") + "/"):
                    dir_overrides.setdefault(d.rstrip("/"), []).append((t, src))
                    break
    ov_dir = work / "overrides"
    ov_dir.mkdir()
    os.chmod(ov_dir, 0o750)
    chown_safe(ov_dir, 0, gid)
    for idx, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("cfg_dir=") and s.split("=", 1)[1].strip().rstrip("/") == managed:
            out_lines.append(f"cfg_dir={managed_copy}")
            found_managed = True
            continue
        if s.startswith("cfg_file="):
            target = s.split("=", 1)[1].strip()
            if target in overrides:
                dst = ov_dir / f"file-{idx}.cfg"
                shutil.copyfile(overrides[target], dst)
                os.chmod(dst, 0o640)
                chown_safe(dst, 0, gid)
                path_map[str(dst)] = target
                out_lines.append(f"cfg_file={dst}")
                continue
        if s.startswith("cfg_dir="):
            d = s.split("=", 1)[1].strip().rstrip("/")
            if d in dir_overrides:
                dst_dir = ov_dir / f"dir-{idx}"
                _copytree_for_nagios(Path(d), dst_dir, conf)
                for t, src in dir_overrides[d]:
                    rel = os.path.relpath(t, d)
                    shutil.copyfile(src, dst_dir / rel)
                    os.chmod(dst_dir / rel, 0o640)
                path_map[str(dst_dir)] = d
                out_lines.append(f"cfg_dir={dst_dir}")
                continue
        out_lines.append(ln)
    if not found_managed:
        raise PipelineError(
            f"nagios.cfg does not contain cfg_dir={managed}; run the installer to register the managed directory")
    tmp_cfg = work / "nagios.cfg"
    tmp_cfg.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    os.chmod(tmp_cfg, 0o640)
    chown_safe(tmp_cfg, 0, gid)
    path_map[str(tmp_cfg)] = "nagios.cfg (validation copy)"
    return work, tmp_cfg, path_map


def run_nagios_verify(conf: dict, cfg_path: str) -> tuple[int, str]:
    cmd = [conf["nagios_bin"], "-v", cfg_path]
    if is_root() and pwd.getpwuid(os.geteuid()).pw_name != conf["nagios_user"]:
        cmd = ["/usr/sbin/runuser", "-u", conf["nagios_user"], "--"] + cmd
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=conf["validate_timeout"],
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}, cwd="/")
    except subprocess.TimeoutExpired:
        return 124, "nagios -v timed out"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


_FILE_RX = [
    re.compile(r"config file '([^']+)', starting on line (\d+)"),
    re.compile(r"in file '([^']+)' on line (\d+)"),
    re.compile(r"config file '([^']+)'"),
    re.compile(r"file '([^']+)'"),
]
_OBJ_RX = re.compile(
    r"\b(host|service|hostgroup|servicegroup|contact|contactgroup|command|timeperiod|template|host escalation|service dependency)\s+'([^']+)'",
    re.I)

SUGGESTIONS = [
    (re.compile(r"Could not find any (host|contact)group matching '([^']+)'", re.I),
     "The {0}group '{1}' is referenced but not defined. Create it under Host Groups / Contact Groups, or remove the reference."),
    (re.compile(r"Could not find any host matching '([^']+)'", re.I),
     "Host '{0}' is referenced but not defined. Ensure the server exists and is not in Draft state."),
    (re.compile(r"(?:check|notification|event handler) command '([^'!]+)[^']*' specified in .* not defined", re.I),
     "Command '{0}' is not defined. Add it under Configuration > Commands or pick another service definition."),
    (re.compile(r"Duplicate definition found for (\w+) '([^']+)'", re.I),
     "A {0} named '{1}' is already defined elsewhere (possibly in a manually maintained file). Rename it or import/take over the existing definition."),
    (re.compile(r"timeperiod '([^']+)' specified .* not defined|Could not find.*timeperiod '([^']+)'", re.I),
     "The time period is not defined. Use an existing time period such as 24x7."),
    (re.compile(r"has no default contacts or contactgroups", re.I),
     "Assign at least one contact group to the server (Server > Notifications)."),
    (re.compile(r"Invalid (\w+) value", re.I),
     "The value for '{0}' is invalid. Check the numeric settings for this object."),
    (re.compile(r"Unexpected token or statement", re.I),
     "The generated file contains an invalid line. Check free-text fields for unsupported characters."),
    (re.compile(r"Service '([^']+)' on host '([^']+)' has no default contacts", re.I),
     "Assign a contact group to host '{1}'."),
    (re.compile(r"Unable to write to check_result_path", re.I),
     "Validation must run as the nagios user; check ownership of the check_result_path directory."),
]


def _map_path(p: str, path_map: dict) -> str:
    best = None
    for tmp, real in path_map.items():
        if p == tmp or p.startswith(tmp.rstrip("/") + "/"):
            if best is None or len(tmp) > len(best[0]):
                best = (tmp, real)
    if best is None:
        return p
    tmp, real = best
    return real + p[len(tmp):] if p != tmp else real


def parse_verify_output(output: str, path_map: dict | None = None) -> dict:
    path_map = path_map or {}
    errors, warnings = [], []
    counts: dict[str, int] = {}
    for raw in output.splitlines():
        line = raw.strip()
        m = re.match(r"Checked (\d+) (.+?)\.?$", line)
        if m:
            counts.setdefault(m.group(2), int(m.group(1)))
            continue
        kind = None
        if line.startswith("Error:") or line.startswith("***> ") and "Error" in line:
            kind = "error"
        elif line.startswith("Warning:"):
            kind = "warning"
        if not kind:
            continue
        msg = line.split(":", 1)[1].strip() if ":" in line else line
        entry = {"message": msg, "file": None, "line": None, "object": None, "suggestion": None}
        for rx in _FILE_RX:
            fm = rx.search(msg)
            if fm:
                entry["file"] = _map_path(fm.group(1), path_map)
                if fm.lastindex and fm.lastindex >= 2:
                    entry["line"] = int(fm.group(2))
                break
        om = _OBJ_RX.search(msg)
        if om:
            entry["object"] = f"{om.group(1).lower()} '{om.group(2)}'"
        for rx, tmpl in SUGGESTIONS:
            sm = rx.search(msg)
            if sm:
                groups = [g for g in sm.groups() if g is not None]
                try:
                    entry["suggestion"] = tmpl.format(*groups)
                except (IndexError, KeyError):
                    entry["suggestion"] = tmpl
                break
        for tmp, real in path_map.items():
            entry["message"] = entry["message"].replace(tmp, real)
        (errors if kind == "error" else warnings).append(entry)
    return {"errors": errors, "warnings": warnings, "counts": counts}


def validate_stage(conf: dict, stage: Path, manifest: dict, log: Logger, label: str) -> dict:
    check_override_targets(conf, manifest)
    work, tmp_cfg, path_map = build_validation_tree(conf, stage, manifest, label)
    try:
        rc, output = run_nagios_verify(conf, str(tmp_cfg))
        parsed = parse_verify_output(output, path_map)
        for tmp, real in path_map.items():
            output = output.replace(tmp, real)
        ok = rc == 0 and not parsed["errors"]
        log.step("validate", "ok" if ok else "failed",
                 f"errors={len(parsed['errors'])} warnings={len(parsed['warnings'])}")
        return {"ok": ok, "rc": rc, "output": output, **parsed}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ------------------------------------------------------------------ backup --
def create_backup(conf: dict, reason: str, version: str | None, extra_targets: list[str], log: Logger) -> dict:
    if not REASON_RE.match(reason):
        raise PipelineError("invalid backup reason")
    bdir = Path(conf["backup_dir"])
    bdir.mkdir(parents=True, exist_ok=True, mode=0o750)
    ts = now_utc().strftime("%Y%m%d-%H%M%S")
    name = f"{ts}-{reason}" + (f"-v{version}" if version else "")
    n = 1
    while (bdir / f"{name}.tar.gz").exists():
        n += 1
        name = f"{ts}-{reason}" + (f"-v{version}" if version else "") + f"-{n}"
    tar_path = bdir / f"{name}.tar.gz"
    meta = {"name": name, "created_at": now_utc().isoformat(timespec="seconds"), "reason": reason,
            "version": version, "legacy": []}
    lines = read_nagios_cfg(conf)
    legacy_targets = set(extra_targets)
    tmp = tar_path.with_suffix(".tmp")
    with tarfile.open(tmp, "w:gz") as tar:
        tar.add(conf["nagios_cfg"], arcname="nagios.cfg")
        if Path(conf["managed_dir"]).is_dir():
            tar.add(conf["managed_dir"], arcname="managed")
        # NOTE: managed-secrets (plaintext agent tokens) are deliberately NOT backed up.
        # They are regenerated from the encrypted copies in MariaDB on every apply.
        # every other object file loaded by nagios.cfg (manual config) for full recovery
        others = [f for f in cfg_directive(lines, "cfg_file") if Path(f).is_file()]
        for d in cfg_directive(lines, "cfg_dir"):
            if d.rstrip("/") == conf["managed_dir"].rstrip("/"):
                continue
            if Path(d).is_dir():
                others += [str(p) for p in sorted(Path(d).rglob("*.cfg")) if p.is_file() and not p.is_symlink()]
        for i, f in enumerate(sorted(set(others) | legacy_targets)):
            if Path(f).is_file():
                arc = f"legacy/{i:04d}.cfg"
                tar.add(f, arcname=arc)
                meta["legacy"].append({"arcname": arc, "target": f, "sha256": sha256_file(Path(f)),
                                       "changed_by_this_operation": f in legacy_targets})
        mjson = json.dumps(meta, indent=2).encode()
        info = tarfile.TarInfo("backup-meta.json")
        info.size = len(mjson)
        info.mtime = int(time.time())
        import io
        tar.addfile(info, io.BytesIO(mjson))
    os.replace(tmp, tar_path)
    os.chmod(tar_path, 0o640)
    try:
        chown_safe(tar_path, 0, grp.getgrnam(conf["app_group"]).gr_gid)
    except KeyError:
        pass
    meta["size_bytes"] = tar_path.stat().st_size
    meta["sha256"] = sha256_file(tar_path)
    (bdir / f"{name}.json").write_text(json.dumps(meta, indent=2))
    os.chmod(bdir / f"{name}.json", 0o640)
    try:
        chown_safe(bdir / f"{name}.json", 0, grp.getgrnam(conf["app_group"]).gr_gid)
    except KeyError:
        pass
    prune_backups(conf)
    log.step("backup", "ok", name)
    return meta


def prune_backups(conf: dict) -> None:
    keep = int(conf.get("backup_keep", 200))
    bdir = Path(conf["backup_dir"])
    archives = sorted(bdir.glob("*.tar.gz"))
    for old in archives[:-keep] if len(archives) > keep else []:
        old.unlink(missing_ok=True)
        old.with_suffix("").with_suffix(".json").unlink(missing_ok=True)


BACKUP_DELETE_KEEP_NEWEST = 5       # the newest portal backups can never be deleted
BACKUP_DELETE_MIN_AGE = 86400       # nor any backup younger than 24 hours


def delete_backup(conf: dict, name: str, log: Logger) -> dict:
    """Delete ONE portal backup archive (+ its .json). Used by the Super Admin data cleanup.

    Independent of the portal database, this refuses: names that are not portal
    backups (installer/upgrade backups never match), symlinks or paths outside the
    backup directory, the newest BACKUP_DELETE_KEEP_NEWEST backups, and anything
    younger than 24 hours.
    """
    if not BACKUP_RE.match(name):
        raise PipelineError("invalid backup name")
    if name[16:].startswith("install"):
        raise PipelineError("refused: the installation backup is always kept")
    bdir = Path(conf["backup_dir"]).resolve()
    tar_path = bdir / f"{name}.tar.gz"
    if tar_path.is_symlink() or not tar_path.is_file():
        raise PipelineError("backup archive not found")
    if tar_path.resolve().parent != bdir:
        raise PipelineError("backup path escapes backup directory")
    portal = sorted(p.name[:-7] for p in bdir.glob("*.tar.gz")
                    if p.is_file() and not p.is_symlink() and BACKUP_RE.match(p.name[:-7]))
    if name in portal[-BACKUP_DELETE_KEEP_NEWEST:]:
        raise PipelineError(f"refused: one of the newest {BACKUP_DELETE_KEEP_NEWEST} backups")
    if time.time() - tar_path.stat().st_mtime < BACKUP_DELETE_MIN_AGE:
        raise PipelineError("refused: backup is younger than 24 hours")
    size = tar_path.stat().st_size
    tar_path.unlink()
    meta = bdir / f"{name}.json"
    if meta.is_file() and not meta.is_symlink():
        meta.unlink()
    log.step("backup-delete", "ok", name)
    return {"name": name, "size_bytes": size}


# ----------------------------------------------------------------- install --
def _install_dir(src: Path | None, dst: Path, owner_uid: int, gid: int, dmode: int, fmode: int) -> Path | None:
    """Atomically replace dst with a copy of src. Returns path of previous copy (dst.prev)."""
    new = dst.with_name(dst.name + ".new")
    prev = dst.with_name(dst.name + ".prev")
    shutil.rmtree(new, ignore_errors=True)
    if src is not None and src.is_dir():
        shutil.copytree(src, new, symlinks=False)
    else:
        new.mkdir(parents=True)
    for root, dirs, files in os.walk(new):
        os.chmod(root, dmode)
        chown_safe(Path(root), owner_uid, gid)
        for f in files:
            os.chmod(Path(root) / f, fmode)
            chown_safe(Path(root) / f, owner_uid, gid)
    shutil.rmtree(prev, ignore_errors=True)
    had_prev = dst.exists()
    if had_prev:
        os.rename(dst, prev)
    os.rename(new, dst)
    return prev if had_prev else None


def _restore_dir(dst: Path, prev: Path | None) -> None:
    if prev is None:
        shutil.rmtree(dst, ignore_errors=True)
        return
    if prev.exists():
        failed = dst.with_name(dst.name + ".failed")
        shutil.rmtree(failed, ignore_errors=True)
        if dst.exists():
            os.rename(dst, failed)
        os.rename(prev, dst)


def _write_file_atomic(target: Path, src: Path) -> None:
    st = target.stat()
    tmp = target.with_name(f".{target.name}.nmp-tmp")
    shutil.copyfile(src, tmp)
    os.chmod(tmp, st.st_mode & 0o7777)
    chown_safe(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, target)


class Installed:
    def __init__(self):
        self.managed_prev: Path | None = None
        self.secrets_prev: Path | None = None
        self.legacy_prev: list[tuple[Path, Path]] = []
        self.secrets_installed = False
        self.done = False


def install_stage(conf: dict, stage: Path, manifest: dict, log: Logger) -> Installed:
    nag_uid, _, gid = ids(conf)
    inst = Installed()
    managed = Path(conf["managed_dir"])
    secrets = Path(conf["secrets_dir"])
    inst.managed_prev = _install_dir(stage / "managed", managed, 0, gid, 0o750, 0o640)
    if not manifest.get("keep_secrets"):
        inst.secrets_prev = _install_dir(stage / "secrets", secrets, nag_uid, 0, 0o500, 0o400)
        inst.secrets_installed = True
    for ov in manifest.get("overrides") or []:
        target = Path(ov["target"])
        keep = target.with_name(f".{target.name}.nmp-prev")
        shutil.copy2(target, keep)
        inst.legacy_prev.append((target, keep))
        _write_file_atomic(target, stage / "overrides" / ov["file"])
    inst.done = True
    log.step("install", "ok", f"files={len(manifest.get('files') or {})} overrides={len(manifest.get('overrides') or [])}")
    return inst


def restore_installed(conf: dict, inst: Installed, log: Logger) -> None:
    _restore_dir(Path(conf["managed_dir"]), inst.managed_prev)
    if inst.secrets_installed:
        _restore_dir(Path(conf["secrets_dir"]), inst.secrets_prev)
    for target, keep in inst.legacy_prev:
        if keep.exists():
            os.replace(keep, target)
    log.step("restore-previous", "ok", "previous configuration restored")


def cleanup_installed(inst: Installed, conf: dict) -> None:
    for p in (inst.managed_prev, inst.secrets_prev):
        if p:
            shutil.rmtree(p, ignore_errors=True)
    for _, keep in inst.legacy_prev:
        keep.unlink(missing_ok=True)


# ------------------------------------------------------------ reload/verify --
def _lock_file_pid(conf: dict) -> int | None:
    lines = read_nagios_cfg(conf)
    lf = (cfg_directive(lines, "lock_file") or [None])[0]
    if lf and Path(lf).is_file():
        try:
            pid = int(Path(lf).read_text().strip())
            os.kill(pid, 0)
            return pid
        except (ValueError, ProcessLookupError, PermissionError):
            return None
    return None


def _status_program_start(conf: dict) -> int | None:
    lines = read_nagios_cfg(conf)
    sf = (cfg_directive(lines, "status_file") or [None])[0]
    if not sf or not Path(sf).is_file():
        return None
    in_prog = False
    try:
        with open(sf, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                s = ln.strip()
                if s.startswith("programstatus {"):
                    in_prog = True
                elif in_prog and s.startswith("program_start="):
                    return int(s.split("=", 1)[1])
                elif in_prog and s == "}":
                    return None
    except (OSError, ValueError):
        return None
    return None


def reload_nagios(conf: dict, log: Logger) -> None:
    method = conf.get("reload_method", "systemctl")
    if method == "systemctl":
        proc = subprocess.run(["/usr/bin/systemctl", "reload", conf["nagios_service"]], capture_output=True,
                              text=True, timeout=120, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        if proc.returncode != 0:
            raise PipelineError("systemctl reload failed: " + (proc.stderr or proc.stdout).strip()[:500])
    elif method == "signal":
        pid = _lock_file_pid(conf)
        if not pid:
            raise PipelineError("Nagios is not running (no valid PID in lock file)")
        os.kill(pid, signal.SIGHUP)
    elif method == "none":
        log.step("reload", "skipped", "reload_method=none")
        return
    else:
        raise PipelineError(f"unknown reload_method {method}")
    log.step("reload", "ok", method)


def verify_nagios(conf: dict, since: float, expected_hosts: list[str], log: Logger,
                  old_program_start: int | None = None) -> None:
    if conf.get("reload_method") == "none":
        log.step("verify", "skipped", "reload_method=none")
        return
    deadline = time.time() + int(conf.get("verify_timeout", 45))
    last_err = "Nagios did not come back after reload"
    while time.time() < deadline:
        time.sleep(1.5)
        pid = _lock_file_pid(conf)
        if not pid:
            last_err = "Nagios process not running after reload"
            continue
        if conf.get("reload_method") == "systemctl":
            st = subprocess.run(["/usr/bin/systemctl", "is-active", conf["nagios_service"]], capture_output=True,
                                text=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
            if st.stdout.strip() != "active":
                last_err = f"nagios service state: {st.stdout.strip()}"
                continue
        ps = _status_program_start(conf)
        if ps is None or ps < int(since) - 1 or (old_program_start is not None and ps <= old_program_start):
            last_err = "waiting for Nagios to report the new program start in status.dat"
            continue
        missing = _missing_hosts(conf, expected_hosts)
        if missing:
            last_err = "hosts not present in objects.cache: " + ", ".join(missing[:10])
            continue
        log.step("verify", "ok", f"pid={pid} program_start={ps} hosts_checked={len(expected_hosts)}")
        return
    raise PipelineError(last_err)


def _missing_hosts(conf: dict, expected: list[str]) -> list[str]:
    if not expected:
        return []
    lines = read_nagios_cfg(conf)
    oc = (cfg_directive(lines, "object_cache_file") or [None])[0]
    if not oc or not Path(oc).is_file():
        return []
    found: set[str] = set()
    in_host = False
    with open(oc, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            s = ln.strip()
            if s.startswith("define host {") or s == "define host{":
                in_host = True
            elif in_host and s.startswith("host_name"):
                found.add(s.split(None, 1)[1].strip())
                in_host = False
            elif s == "}":
                in_host = False
    return [h for h in expected if h not in found]


def reload_and_verify(conf: dict, expected_hosts: list[str], log: Logger) -> None:
    """Reload Nagios and wait until a *new* process generation reports in status.dat."""
    old_ps = _status_program_start(conf)
    if old_ps is not None and time.time() - old_ps < 1.2:
        time.sleep(1.2)  # program_start has 1 s resolution; make the new start distinguishable
    t0 = time.time()
    reload_nagios(conf, log)
    verify_nagios(conf, t0, expected_hosts, log, old_program_start=old_ps)


# ------------------------------------------------------------ full pipeline --
def apply_stage(conf: dict, stage: Path, manifest: dict, log: Logger, label: str, backup_reason: str,
                version: str | None) -> dict:
    """Backup -> validate -> install -> validate live -> reload -> verify. Restores on failure."""
    result: dict = {"ok": False, "backup": None, "validation": None}
    validation = validate_stage(conf, stage, manifest, log, label)
    result["validation"] = validation
    if not validation["ok"]:
        raise PipelineError("validation failed - configuration NOT applied", result=result)

    targets = [ov["target"] for ov in (manifest.get("overrides") or [])]
    backup = create_backup(conf, backup_reason, version, targets, log)
    result["backup"] = backup

    inst = install_stage(conf, stage, manifest, log)
    try:
        rc, out = run_nagios_verify(conf, conf["nagios_cfg"])
        live = parse_verify_output(out)
        if rc != 0 or live["errors"]:
            log.step("validate-live", "failed", f"rc={rc}")
            raise PipelineError("live configuration failed validation after install", live=live, output=out)
        log.step("validate-live", "ok")
        reload_and_verify(conf, manifest.get("expected_hosts") or [], log)
    except Exception as exc:
        log.step("apply", "failed", str(exc)[:500])
        restore_installed(conf, inst, log)
        try:
            rc, _ = run_nagios_verify(conf, conf["nagios_cfg"])
            if rc == 0 and conf.get("reload_method") != "none":
                reload_and_verify(conf, [], log)
        except Exception as exc2:  # pragma: no cover - extreme failure path
            log.step("recover", "failed", str(exc2)[:500])
        if isinstance(exc, PipelineError):
            exc.extra.setdefault("result", result)
            raise
        raise PipelineError(str(exc), result=result)
    cleanup_installed(inst, conf)
    result["ok"] = True
    return result
