# Architecture

## Components

```
 Browser ──HTTPS──► Apache 2.4 (:443)
                     ├── /            static React UI  (/opt/nagios-management/frontend/dist)
                     ├── /api/*  ───► nagios-management.service  (uvicorn, 127.0.0.1:8095, user nagmgmt)
                     └── /nagios      classic Nagios CGIs (unchanged)

 nagios-management (FastAPI)                         nagios-management-worker
   ├── auth / RBAC / CSRF / audit                      ├── perf sampler (status.dat → perf_samples)
   ├── inventory + catalog + templates (MariaDB)       ├── notification rule engine → providers
   ├── config generator  ──► staging dir + manifest    └── housekeeping (retention)
   ├── live status  ◄── status.dat, nagios.log, archives
   ├── operator actions ──► nagios.cmd (whitelisted external commands)
   └── privileged invoker ──sudo──► /opt/nagios-management/privileged/sbin/*  (root, stdlib-only)
                                         ├── nagios-config-validate   (nagios -v as nagios)
                                         ├── nagios-config-apply      (backup/install/reload/verify)
                                         ├── nagios-config-backup
                                         ├── nagios-config-rollback   (emergency file restore)
                                         └── nagios-status-check

 Nagios Core 4.5 (unchanged binary/service)
   nagios.cfg ── cfg_file / cfg_dir (your existing files, untouched)
              └─ cfg_dir=/usr/local/nagios/etc/managed   ← the only portal-owned object directory
```

**Configuration data** (servers, credentials, services, thresholds, templates, groups, contacts, versions, audit) lives in MariaDB.
**Live monitoring data** (host and service states, outputs, downtime, acknowledgements, events) is read from Nagios on each request (`status.dat` is cached until its mtime changes) and is not copied into MariaDB. The only monitoring-derived data the portal stores is performance history (`perf_samples`, which Nagios does not keep) and the notification engine's last-state bookkeeping.

## Controlled configuration layout

```
/usr/local/nagios/etc/
├── nagios.cfg                 + one line: cfg_dir=/usr/local/nagios/etc/managed
├── objects/…                  your existing files (only changed by an explicit "take over" import)
├── managed/                   root:nagios 0750 / files 0640 - GENERATED, replaced atomically
│   ├── commands/nmp-commands.cfg
│   ├── templates/nmp-templates.cfg   (nmp-generic-host, nmp-windows-host, … nmp-generic-service)
│   ├── hostgroups/nmp-hostgroups.cfg
│   ├── contacts/nmp-contacts.cfg
│   ├── hosts/<hostname>.cfg
│   └── services/<hostname>.cfg
└── managed-secrets/           nagios:root 0500 / file 0400 - agent credentials for the wrappers only
    └── nmp-secrets.tsv

/usr/local/nagios/libexec/nmp/     root:nagios 0750 - check_ncpa_nmp.py, check_snmp_nmp.py, nmp_secrets.py
/var/lib/nagios-management/
├── staging/v<N>/               nagmgmt - generated files + manifest.json (SHA-256 of every file)
├── work/                       root - temporary validation copies
└── backups/*.tar.gz + *.json   root:nagmgmt 0640
/etc/nagios-management/         app.env, privileged.json, master.key, db.password, tls/
/var/log/nagios-management/     application, configuration, security, audit, error logs
```

All portal object names are namespaced: commands `nmp_*` and templates `nmp-*`. Before generating, the generator parses your manual configuration and refuses any host, command, host group, contact or contact group that would collide with it. Host groups and contact groups that already exist in your files are registered as **external**, so portal servers can reference them without redefining them.

## The configuration pipeline

1. **Generate** (application, unprivileged). Reads MariaDB and renders every file from validated values only. Performs portal-side pre-validation: collisions, missing credentials, unknown groups or time periods, parameter and threshold syntax. Writes `staging/v<N>/` with `manifest.json` (file hashes, expected hosts, legacy-file overrides), stores all files in `configuration_version_files` (without secrets), and snapshots the configuration tables into `configuration_versions.snapshot`.
2. **Validate** (`sudo nagios-config-validate N`). Verifies manifest integrity (hashes, no symlinks, no unlisted files). Copies staging into a root-owned work dir and builds a temporary `nagios.cfg` identical to the live one except that `cfg_dir=…/managed` points to the staged copy. It runs `nagios -v` as the `nagios` user and parses errors and warnings into file, line, object and suggested fix. Live files are never touched.
3. **Apply** (`sudo nagios-config-apply N`). Takes a lock, re-runs step 2 (never trusts an earlier result), then **backs up** nagios.cfg, the managed dir and every manual object file. It **installs** by atomic directory swap (`managed.new` → `managed`, previous kept as `managed.prev`), validates the **live** config, runs `systemctl reload nagios` (your unit's ExecReload itself runs `nagios -v` and then HUP), and **verifies**: the process is alive, status.dat reports a *new* `program_start`, and every expected host is present in `objects.cache`. Any failure restores the previous files and reloads again.
4. **Record**. The version becomes `applied`, pending changes are linked to it, server states become `applied`, and the backup is registered. Everything is audited.

**Rollback to version N** restores the configuration tables from version N's snapshot, then runs generate → validate → apply as a new version ("Rollback to version N"). The database and Nagios therefore stay consistent. **Emergency restore** of a backup archive (`nagios-config-rollback`) restores files only, through the same validate/backup/install/reload/verify path.

**Import (take over)** creates portal objects from your manual definitions and, in the same version, overrides the original file with those blocks commented out (`#NMP-MIGRATED#`). Both are validated together. The override is refused if the file changed since the scan (SHA-256 check).

## Secrets

- NCPA tokens, SNMP communities/passwords and notification-channel secrets are encrypted in MariaDB with AES-256-GCM (key in `/etc/nagios-management/master.key`). Associated data binds each ciphertext to its purpose.
- At apply time they are written only to `managed-secrets/nmp-secrets.tsv` (owner `nagios`, mode 0400).
- `check_ncpa_nmp.py` looks up the token by host key and runs the stock `check_ncpa.py` **in-process** (runpy). The token never appears in object files, `objects.cache`, `ps`, the Nagios CGIs or logs. `check_snmp_nmp.py` gives credentials to net-snmp through a private temporary `snmp.conf`.
- Backups and version downloads never contain secrets.

## Database schema (MariaDB, Alembic migration `0001`)

| Area | Tables |
|---|---|
| Identity & RBAC | `users`, `roles`, `permissions`, `role_permissions`, `user_roles`, `user_sessions`, `rate_limit_buckets` |
| Inventory | `servers`, `server_credentials`, `server_groups`, `server_group_members`, `server_contact_groups` |
| Monitoring definitions | `commands`, `services` (catalog), `server_services`, `service_thresholds`, `monitoring_templates`, `template_services` |
| Contacts | `contacts`, `contact_groups`, `contact_group_members` |
| Config management | `configuration_versions`, `configuration_version_files`, `configuration_changes`, `config_backups` |
| Audit | `audit_logs` |
| Notifications | `notification_channels`, `notification_rules`, `notifications` |
| Other | `perf_samples`, `monitor_state_cache`, `system_settings`, `worker_heartbeat` |

Every table has a primary key. Relationships use foreign keys (`CASCADE` for owned children, `SET NULL` for authorship, `RESTRICT` where deletion must be blocked). Unique constraints cover names (for example `servers(hostname, deleted_token)`, which allows re-use of a deleted hostname while keeping history). Indexes cover the list and filter columns. Mutable tables carry `created_at`, `updated_at`, `created_by` and `updated_by`.

## Nagios retention note

The portal templates set `retain_nonstatus_information 0`, so the configuration (enabled/disabled, notifications) is the source of truth after every reload. Status, acknowledgements, comments and downtime are still retained.

## Extensibility

- **Monitoring engines**: live data access lives in `nmp/nagios/status.py`, `logparser.py` and `external.py`, and generation in `generator.py`. Another engine can be added as a sibling package behind the same service functions.
- **Notification providers**: implement `Provider.send()` and `register()` it (`nmp/notifications/providers`). The generic webhook provider already covers most HTTP APIs (WhatsApp BSPs, SMS gateways, ITSM).
- **Service types**: add catalog entries in the UI (Configuration → Services) using the safe argument-template language, with no code changes.
