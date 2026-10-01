"""Read-only parser for existing (manually maintained) Nagios object files.

Used to (a) detect name collisions before generating config, (b) list
existing host groups / contact groups / time periods that portal objects
may reference, and (c) import existing hosts and services.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..config import get_settings

_DEFINE_RE = re.compile(r"^define\s+(\w+)\s*\{?\s*$")


@dataclass
class NagiosObject:
    type: str
    attrs: dict[str, str]
    file: str
    start_line: int
    end_line: int

    @property
    def register(self) -> bool:
        return self.attrs.get("register", "1").strip() != "0"

    @property
    def key(self) -> str | None:
        a = self.attrs
        for k in ("host_name", "hostgroup_name", "command_name", "contact_name", "contactgroup_name",
                  "timeperiod_name", "servicegroup_name"):
            if k in a and self.type != "service":
                return a[k]
        if self.type == "service":
            return f"{a.get('host_name', '')}/{a.get('service_description', '')}"
        return a.get("name")


@dataclass
class LegacyConfig:
    objects: list[NagiosObject] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)  # path -> sha256
    errors: list[str] = field(default_factory=list)

    def names(self, otype: str, attr: str) -> set[str]:
        out = set()
        for o in self.objects:
            if o.type == otype and o.register and attr in o.attrs:
                for n in o.attrs[attr].split(","):
                    if n.strip():
                        out.add(n.strip())
        return out

    def template_names(self, otype: str) -> set[str]:
        return {o.attrs["name"] for o in self.objects if o.type == otype and "name" in o.attrs}

    def hosts(self) -> list[NagiosObject]:
        return [o for o in self.objects if o.type == "host" and o.register and "host_name" in o.attrs]

    def services_for(self, host: str) -> list[NagiosObject]:
        out = []
        for o in self.objects:
            if o.type == "service" and o.register:
                hosts = [h.strip() for h in o.attrs.get("host_name", "").split(",")]
                if host in hosts:
                    out.append(o)
        return out


def strip_comment(line: str) -> str:
    s = line.strip()
    if not s or s[0] in "#;":
        return ""
    # inline ';' comments (unless escaped)
    return re.sub(r"(?<!\\);.*$", "", s).rstrip()


def parse_file(path: str) -> list[NagiosObject]:
    objs: list[NagiosObject] = []
    cur_type = None
    attrs: dict[str, str] = {}
    start = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, start=1):
            s = strip_comment(raw)
            if not s:
                continue
            m = _DEFINE_RE.match(s)
            if m:
                cur_type, attrs, start = m.group(1), {}, n
                continue
            if cur_type and s.startswith("}"):
                objs.append(NagiosObject(cur_type, attrs, path, start, n))
                cur_type = None
                continue
            if cur_type:
                parts = s.split(None, 1)
                if parts:
                    attrs[parts[0]] = parts[1].strip() if len(parts) > 1 else ""
    return objs


def config_files(nagios_cfg: str | None = None, exclude_dirs: list[str] | None = None) -> list[str]:
    s = get_settings()
    cfg = nagios_cfg or s.nagios_cfg
    exclude = [d.rstrip("/") for d in (exclude_dirs or [s.managed_dir])]
    files: list[str] = []
    seen_dirs: set[str] = set()
    for raw in Path(cfg).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if k == "cfg_file" and v not in files:
            files.append(v)
        elif k == "cfg_dir":
            d = v.rstrip("/")
            if d in exclude or d in seen_dirs:
                continue
            seen_dirs.add(d)
            p = Path(d)
            if p.is_dir():
                files.extend(str(f) for f in sorted(p.rglob("*.cfg")) if f.is_file() and str(f) not in files)
    return files


def load_legacy(nagios_cfg: str | None = None) -> LegacyConfig:
    lc = LegacyConfig()
    try:
        files = config_files(nagios_cfg)
    except OSError as exc:
        lc.errors.append(f"cannot read nagios.cfg: {exc}")
        return lc
    for f in files:
        try:
            data = Path(f).read_bytes()
            lc.files[f] = hashlib.sha256(data).hexdigest()
            lc.objects.extend(parse_file(f))
        except OSError as exc:
            lc.errors.append(f"cannot read {f}: {exc}")
    return lc


def comment_out_blocks(path: str, ranges: list[tuple[int, int]], tag: str) -> str:
    """Return file content with the given 1-based inclusive line ranges commented out."""
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    marked = set()
    for a, b in ranges:
        marked.update(range(a, b + 1))
    out = []
    for i, ln in enumerate(lines, start=1):
        if i in marked:
            out.append(f"#{tag}# {ln}" if ln.endswith("\n") else f"#{tag}# {ln}\n")
        else:
            out.append(ln)
    return "".join(out)
