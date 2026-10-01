# Security

The portal manages infrastructure monitoring, so it is built on the assumption that the web tier can be attacked. The main design goal is that **a compromise of the web application must not give root on the Nagios server, and must not leak agent credentials in plain text through config files, logs or backups.**

## Controls

| Requirement | Implementation |
|---|---|
| HTTPS | Apache vhost on 443, TLS 1.2/1.3 only, HSTS. The API listens on 127.0.0.1 only. |
| Secure login | Argon2id password hashes (time 3, 64 MiB). Identical error for unknown user and wrong password, with constant work for both. Password policy: 12+ characters and 3 of 4 character classes. Forced change on first login when an admin sets the password. |
| Session management | 256-bit random token in an `HttpOnly; Secure; SameSite=Strict` cookie. Only its SHA-256 is stored. 30-minute idle timeout (server-side plus UI auto-logout) and 12-hour absolute limit. All sessions are revoked on password or role change and on deactivation. |
| CSRF | Per-session CSRF token, required in `X-CSRF-Token` for every non-GET request. `Origin` must match the portal host. SameSite=Strict cookies. |
| SQL injection | SQLAlchemy ORM/Core with bound parameters only. No string-built SQL containing user input. Tested with injection payloads. |
| XSS | React escapes all output (no `dangerouslySetInnerHTML`). Strict CSP (`script-src 'self'`, no inline scripts). The API sends JSON with `nosniff`. Free-text fields also reject `< > ; $ \` \ ! | &`. |
| Input validation | Pydantic models plus `nmp/validators.py`: host names, addresses, Nagios range thresholds, typed service parameters (drive letter, mount, Windows service, OID…), time periods, e-mail. The generator **re-validates** every value before writing a file. |
| Command injection | No shell anywhere in the web tier (`subprocess` with argument lists, `shell=False`). Nagios command arguments come only from typed, whitelisted parameter patterns. Admin-defined commands must start with an approved plugin directory and cannot contain `; && || \` $( > < \` or stray `$`. Literal `$` in values is escaped as `$$`. |
| Privilege separation | The API and worker run as `nagmgmt`, never root. One sudoers line allows exactly six root-owned scripts. Each takes a single argument matched against a strict regex (a numeric version id, backup name or reason keyword), resolves paths only inside fixed directories, and checks a manifest with SHA-256 hashes before using any staged file. The scripts run `python3 -I` (isolated mode), import only root-owned code, and read their configuration from a root-owned file. sudo/sudo-rs `env_reset` blocks environment injection. The installer verifies that `sudo -n /usr/bin/id` is refused. |
| Encrypted credentials | AES-256-GCM with a 32-byte master key (`/etc/nagios-management/master.key`, root:nagmgmt 0440). Ciphertexts are purpose-bound (AAD). Secrets are never returned by the API (only `secret_set: true`) and are write-only in the UI. |
| No credentials in URLs | The portal API never takes secrets in query strings; login and credentials go in POST/PUT bodies. The NCPA connection test calls the agent's own API, which requires the token as a parameter, over TLS; that request is not logged by the portal. |
| No credentials in logs | A logging filter redacts `token/password/secret/community/api_key/-t/-C/...` patterns in every log file. Audit and change records pass through `scrub()`, which masks secret keys. |
| RBAC | Permission-based checks on every endpoint (28 permissions, 4 built-in roles, custom roles). Denied attempts are audited. **No escalation**: users can only grant roles or permissions they hold. The last Super Admin cannot be removed or demoted. |
| Rate limiting | Login: per-IP counter in MariaDB (shared across workers) plus per-account lockout (5 failures → 15 min). API: 600 requests/min per client IP. |
| Secure headers | CSP, HSTS, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy no-referrer, Permissions-Policy, COOP, `Cache-Control: no-store` on the API. Request bodies limited to 2 MB. |
| Audit logging | Every login/logout/failure, change, apply, rollback, backup, test, acknowledgement, downtime and denied access, with user, time, IP, user agent, old/new values and result. |
| Backups | Created before every apply, rollback and install. No plaintext secrets inside. Mode 0640 root:nagmgmt. |

## Residual risks and recommendations

- **Group membership**: `nagmgmt` is in the `nagios` group (as `www-data` already is on this server). This is needed to read `status.dat` and the logs and to write the command pipe. Members of that group can also write files that are group-writable by `nagios` (often `libexec`). Restrict `libexec` to `root:nagios 0755` if you want to close this.
- **Master key**: anyone with root, or who can read the key file, can decrypt stored credentials. Back the key up offline. Without it, re-enter all tokens.
- **Self-signed certificate**: replace it with a certificate from your internal CA (`--cert/--key` or edit the Apache site).
- **NCPA TLS**: NCPA agents ship self-signed certificates, so "Verify SSL" is off by default. Turn it on per server once agents have proper certificates.
- **Existing Nagios CGI authentication** (`/nagios`, htpasswd) is unchanged and separate from portal users.
- **SNMP v2c** communities travel in clear text on the network (a protocol limitation). Prefer v3 authPriv.
- **Emergency restore** from backup files restores only files, not the database. The portal then reports drift until the next apply.

## Security tests (backend/tests)

`test_api_security.py` covers: unauthenticated access, login/logout/cookie flags, username enumeration, account lockout, missing and forged CSRF, cross-origin POST, security headers, the permission matrix for viewer/operator/administrator, audit of denied access, privilege escalation through users and roles, last-super-admin protection, SQL injection payloads in filters, injection in host name/address/display name/check period, service parameter and threshold injection, custom command injection, secrets never returned in any response, and the error format. `test_unit.py` covers validators, argument rendering, crypto purpose binding, password hashing and policy, and log redaction.

## Data cleanup (Super Admin only)

| Control | How |
|---|---|
| Who | Permission `maintenance.cleanup`. It is granted only to the built-in Super Admin role, cannot be added to custom roles, and the API additionally requires the `super_admin` role itself. Every denied attempt is audited. |
| Two-step | `POST /api/maintenance/cleanup/preview` only counts. `POST /api/maintenance/cleanup` requires `"confirm": "DELETE"` and runs under the configuration pipeline lock, so it never overlaps validate/apply/rollback. |
| Never deleted | The live Nagios configuration (nothing outside the portal database, the staging folder and portal backups is touched); the applied version; the newest 10 versions; unapplied versions newer than the live one; the backup taken before the live version; the newest 10 backups; the installation backup; installer/upgrade archives; soft-deleted servers whose deletion is not yet live in Nagios. Minimum ages: audit log 30 days, notifications 7, backups 7, config history 7. |
| Root-owned backups | Removed only through `nagios-config-backup-delete <name>`, which independently refuses non-portal names, symlinks/path escapes, the newest 5 backups, the installation backup and anything younger than 24 hours. |
| Audit | Each run writes a `maintenance.cleanup` audit entry (per-category counts, ages, errors). Deleting old audit entries never deletes this new entry. |
