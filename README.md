# Nagios Management Portal

A web portal for managing the servers that your existing **Nagios Core 4.5** monitors. You add, edit, disable and delete servers, services, thresholds, templates, contacts and host groups in the portal, and never edit Nagios configuration files by hand.

MariaDB holds the inventory and your intended configuration. The portal **generates** the Nagios object files from it. Every change goes through the same safe pipeline:

```
BACKUP → GENERATE → VALIDATE (nagios -v, as the nagios user) → INSTALL → VALIDATE LIVE → RELOAD → VERIFY
                         └── any failure: nothing is applied / previous configuration restored
```

Nagios remains the monitoring engine. Live status is read directly from `status.dat` and the Nagios event log, and is not copied into MariaDB.

---

## Contents of this package

| Path | What it is |
|---|---|
| `install-nagios-management.sh` | Installer: pre-flight checks, backups, database, services, Apache, sudoers, initial admin |
| `upgrade-nagios-management.sh` | In-place upgrade with database and code backup and automatic restore |
| `uninstall-nagios-management.sh` | Removal. By default keeps monitoring running on the generated files |
| `backend/` | Python 3 / FastAPI API, config generator, worker, Alembic migrations, tests |
| `frontend/` | React + TypeScript UI (`frontend/dist` is prebuilt, so the server needs no Node.js) |
| `privileged/sbin/` | Root-owned helper scripts, the only programs run through `sudo` |
| `privileged/plugins/` | NCPA and SNMP check wrappers, which keep agent secrets off the command line |
| `deploy/` | Apache vhost, systemd units, sudoers rule, logrotate |
| `docs/` | Architecture, security, API, user manual, troubleshooting, OpenAPI spec |
| `tools/nagios-discovery.sh` | The read-only discovery script used to plan this installation |

## Technology

| Layer | Choice | Why |
|---|---|---|
| Backend | Python 3.14 + FastAPI, SQLAlchemy 2, Alembic, PyMySQL | Fast, typed, OpenAPI docs built in. Pure-Python MariaDB driver, so no compiler is needed. |
| Frontend | React 18 + TypeScript + Vite, Chart.js, TanStack Query | Prebuilt static files served by Apache |
| Database | Your existing MariaDB (11.8) | Configuration, inventory, audit, versions, performance samples |
| Web server | Your existing Apache 2.4 | HTTPS on 443 (static UI, proxy for `/api`). `/nagios` is unchanged. |
| Auth | Server-side sessions (HttpOnly/Secure/SameSite=Strict cookie) + CSRF token | Sessions can be revoked instantly. JWT was not used; see `docs/SECURITY.md`. |
| Privilege | Dedicated `nagmgmt` account + one sudoers rule for 6 root-owned scripts | The web application never runs as root |

## Requirements (all detected by the installer)

- Ubuntu Server 26.04 (tested on 24.04 and 26.04 layouts). Nagios Core 4.5 in `/usr/local/nagios`, running under systemd.
- MariaDB and Apache running. `python3` available (the installer adds `python3-venv` and `python3-dev`).
- `check_ncpa.py` in `/usr/local/nagios/libexec` for NCPA checks.
- Internet access to Ubuntu mirrors and PyPI during install.

## Install: exact commands

```bash
# 1. copy the package to the Nagios server and unpack
scp nagios-management-portal-<version>.tar.gz admin@nagios-server:/tmp/
ssh admin@nagios-server
cd /tmp && tar -xzf nagios-management-portal-<version>.tar.gz && cd nagios-management-portal-<version>

# 2. (recommended) take a VM snapshot first, then run the installer
sudo ./install-nagios-management.sh --server-name nagios.yourdomain.local
#    optional: --cert /path/fullchain.pem --key /path/privkey.pem   (use your own certificate)
#              --admin-user admin                                    (initial Super Admin name)
#              --no-dedupe                                           (keep duplicate cfg_dir lines)

# 3. open the portal
#    https://nagios.yourdomain.local/        (portal)
#    https://nagios.yourdomain.local/nagios  (classic Nagios UI, unchanged)
```

The installer stops **before changing anything** if the current Nagios configuration does not validate, if Nagios or MariaDB is not running, or if the port or directories are already in use. It writes a full log to `/var/log/nagios-management/install-<timestamp>.log`.

### What the installer changes on your server

1. Takes a backup: `/var/lib/nagios-management/backups/pre-install-<ts>.tar.gz` (all of `/usr/local/nagios/etc`, `/etc/apache2`, `/etc/sudoers.d`).
2. Creates the system user `nagmgmt` and adds it to the `nagios` group, the same access `www-data` already has.
3. Creates the MariaDB database `nagios_mgmt` and user `nagios_mgmt@localhost` (random password in `/etc/nagios-management/db.password`).
4. Adds **one line** to `nagios.cfg`: `cfg_dir=/usr/local/nagios/etc/managed`. It also removes the duplicated `cfg_dir=/etc/nagiosql/...` lines, unless you pass `--no-dedupe`. This change is validated, backed up and reloaded.
5. Installs the check wrappers in `/usr/local/nagios/libexec/nmp/`. Existing plugins are untouched.
6. Installs `/etc/sudoers.d/nagios-management`, checks it with `visudo`, and confirms that arbitrary commands are refused.
7. Installs the systemd services `nagios-management` (API on 127.0.0.1:8095) and `nagios-management-worker`.
8. Adds the Apache site `nagios-management` on port 443 with a self-signed certificate unless you provide one. It enables modules `ssl proxy proxy_http headers` and runs `configtest` before reloading.
9. Creates the first Super Admin and the `nmp-admin` CLI wrapper.

It never reinstalls or restarts Nagios, and never edits your existing object files. Taking over existing hosts is a separate, explicit, validated step in the UI.

## After installation

1. Log in as the admin you created. With `--yes`, the password is in `/root/nagios-management-initial-admin.txt`; change it at first login.
2. **Administration → Import Configuration.** Take over the hosts you defined by hand (for example Windows servers monitored with NCPA). Inline NCPA tokens are encrypted and the old blocks are commented out of `windows.cfg` in the same validated change.
3. **Infrastructure → Servers → Add server** to add more servers.
4. **Administration → Users** to create Administrators, Operators and Viewers.
5. **Back up `/etc/nagios-management/master.key`.** Stored agent credentials cannot be decrypted without it.

## Service management

```bash
sudo systemctl status nagios-management nagios-management-worker
sudo journalctl -u nagios-management -f
sudo nmp-admin health               # live status summary
sudo nmp-admin validate             # generate + validate (no apply)
sudo nmp-admin apply                # generate + validate + apply + reload + verify
sudo nmp-admin reset-password admin # recover a locked-out admin
```

## Upgrade / uninstall

```bash
sudo ./upgrade-nagios-management.sh      # backs up DB + code, migrates, restarts, restores on failure
sudo ./uninstall-nagios-management.sh    # keeps monitoring running on the generated files
sudo ./uninstall-nagios-management.sh --remove-managed --drop-database --purge   # full removal
```

## Running the tests

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
export NMP_TEST_DATABASE_URL='mysql+pymysql://USER:PASS@localhost/nagios_mgmt_test?charset=utf8mb4'
.venv/bin/pytest            # 160 tests. Nagios integration tests run when a real Nagios is present.
```

The integration suite (`tests/test_pipeline_nagios.py`) exercises the full workflow against a real Nagios daemon: add Windows server → NCPA → template → generate → validate → apply → reload → host appears → services checked through the NCPA wrapper. It also covers modify, disable, delete, validation failure, rollback, invalid credentials, importing existing hosts, backups and emergency restore. Run it on a **test copy** of the server, not production. The fixture restores `/usr/local/nagios/etc` afterwards.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, data flow, file layout, pipeline, database schema
- [docs/SECURITY.md](docs/SECURITY.md): threat model and controls
- [docs/API.md](docs/API.md): REST API reference (full OpenAPI in `docs/openapi.json`, live at `/api/docs`)
- [docs/USER_MANUAL.md](docs/USER_MANUAL.md): how to use every screen
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): common problems and fixes
