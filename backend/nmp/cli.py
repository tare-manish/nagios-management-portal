"""nmp-admin: command-line administration.

  nmp-admin migrate                 run database migrations (alembic upgrade head)
  nmp-admin bootstrap               seed roles, permissions, catalog, templates, settings; register manual groups
  nmp-admin create-admin USER       create a Super Admin (password read from stdin or prompted)
  nmp-admin reset-password USER     set a new password (stdin/prompt), unlock, force change at next login
  nmp-admin generate [--out DIR]    dry-run: generate configuration into DIR (no secrets) and print summary
  nmp-admin validate                generate + validate (no apply)
  nmp-admin apply                   generate + validate + apply + reload + verify
  nmp-admin import-scan             list importable hosts from manual configuration
  nmp-admin health                  print health checks
  nmp-admin gen-key PATH            create a new master key file
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path


def _read_password(prompt: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    p1 = getpass.getpass(prompt)
    p2 = getpass.getpass("Repeat: ")
    if p1 != p2:
        sys.exit("Passwords do not match")
    return p1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nmp-admin", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    b = sub.add_parser("bootstrap")
    b.add_argument("--no-legacy", action="store_true")
    ca = sub.add_parser("create-admin")
    ca.add_argument("username")
    ca.add_argument("--full-name", default="Administrator")
    ca.add_argument("--email")
    ca.add_argument("--force-change", action="store_true", help="require password change at first login")
    rp = sub.add_parser("reset-password")
    rp.add_argument("username")
    g = sub.add_parser("generate")
    g.add_argument("--out")
    sub.add_parser("validate")
    sub.add_parser("apply")
    sub.add_parser("import-scan")
    sub.add_parser("health")
    gk = sub.add_parser("gen-key")
    gk.add_argument("path")
    a = ap.parse_args(argv)

    if a.cmd == "gen-key":
        from .security.crypto import generate_key_file
        generate_key_file(a.path)
        print(f"created {a.path}")
        return 0
    if a.cmd == "migrate":
        from alembic import command
        from alembic.config import Config
        base = Path(__file__).resolve().parent.parent
        cfg = Config(str(base / "alembic.ini"))
        cfg.set_main_option("script_location", str(base / "migrations"))
        command.upgrade(cfg, "head")
        print("database migrated")
        return 0

    from .audit import AuditContext
    from .db import SessionLocal

    ctx = AuditContext(None, "cli", "127.0.0.1", "nmp-admin")
    with SessionLocal() as db:
        if a.cmd == "bootstrap":
            from .seed import seed_all
            print(json.dumps(seed_all(db, sync_legacy=not a.no_legacy), indent=2))
            return 0
        if a.cmd in ("create-admin", "reset-password"):
            from sqlalchemy import select
            from .audit import audit
            from .db import utcnow
            from .models import Role, User
            from .security import passwords
            uname = a.username.strip().lower()
            pw = _read_password(f"Password for {uname}: ")
            errs = passwords.password_policy_errors(pw, uname)
            if errs:
                print("\n".join(errs), file=sys.stderr)
                return 2
            user = db.scalar(select(User).where(User.username == uname))
            if a.cmd == "create-admin":
                if user:
                    print("user already exists", file=sys.stderr)
                    return 1
                role = db.scalar(select(Role).where(Role.name == "super_admin"))
                if role is None:
                    print("run 'nmp-admin bootstrap' first", file=sys.stderr)
                    return 1
                user = User(username=uname, full_name=a.full_name, email=a.email, password_hash=passwords.hash_password(pw),
                            must_change_password=a.force_change, password_changed_at=utcnow())
                user.roles = [role]
                db.add(user)
                db.flush()
                audit(db, ctx, "user.create", entity_type="user", entity_id=user.id, entity_name=uname, detail="created via CLI")
            else:
                if not user:
                    print("user not found", file=sys.stderr)
                    return 1
                user.password_hash = passwords.hash_password(pw)
                user.locked_until, user.failed_logins, user.must_change_password = None, 0, True
                audit(db, ctx, "user.reset_password", entity_type="user", entity_id=user.id, entity_name=uname,
                      detail="reset via CLI")
            db.commit()
            print("ok")
            return 0
        if a.cmd == "generate":
            from .nagios.generator import generate
            from .nagios.legacy import load_legacy
            gen = generate(db, load_legacy())
            if a.out:
                out = Path(a.out)
                for rel, content in gen.files.items():
                    p = out / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(content)
            print(json.dumps({"stats": gen.stats, "errors": gen.errors, "warnings": gen.warnings,
                              "files": sorted(gen.files), "hash": gen.config_hash}, indent=2))
            return 1 if gen.errors else 0
        if a.cmd in ("validate", "apply"):
            from .nagios import pipeline
            v = pipeline.run_pipeline(db, ctx, f"CLI {a.cmd}", apply=(a.cmd == "apply"))
            print(json.dumps({"version": v.id, "status": v.status, "errors": v.validation_errors,
                              "steps": v.apply_log}, indent=2, default=str))
            return 0 if v.status in ("validated", "applied") else 1
        if a.cmd == "import-scan":
            from .nagios.importer import plan_imports
            print(json.dumps([p.as_dict() for p in plan_imports(db)], indent=2))
            return 0
        if a.cmd == "health":
            from .nagios.status import get_status
            snap = get_status()
            print(json.dumps({"status_error": snap.error, "hosts": len(snap.hosts), "services": len(snap.services),
                              "program": snap.program}, indent=2, default=str))
            return 0 if not snap.error else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
