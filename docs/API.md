# REST API

- Base URL: `https://<portal>/api`. Interactive documentation for logged-in users is at `/api/docs`. The full schema is in `docs/openapi.json`.
- **Authentication**: `POST /api/auth/login` with `{"username","password"}` sets the `nmp_session` cookie (HttpOnly) and returns `csrf_token` (also set in the `nmp_csrf` cookie). Send `X-CSRF-Token: <token>` on every POST/PUT/DELETE. The `Origin` header, if present, must be the portal's own origin.
- **Success**: `{"data": ..., "meta": {...}}`. List endpoints return `meta.total/page/page_size/pages`.
- **Errors**: `{"error": {"code": "...", "message": "...", "details": [...]}}`.

| Status | Meaning (error code) |
|---|---|
| 200 / 201 | OK / created |
| 401 | `unauthenticated`, `invalid_credentials` |
| 403 | `forbidden` (missing permission), `csrf_failed`, `bad_origin`, `password_change_required` |
| 404 | `not_found` |
| 409 | `conflict` (duplicate name), `in_use`, `read_only`, `busy` (another config operation running), `invalid_state`, `nagios_command_failed` |
| 413 | `payload_too_large` |
| 422 | `validation_error` (`details: [{field, message}]`), `weak_password`, `import_error` |
| 423 | `account_locked` |
| 429 | `rate_limited` |
| 500 / 502 | `internal_error` / `privileged_error` |

## Examples

```bash
B=https://nagios.local
curl -sk -c jar -H 'Content-Type: application/json' -d '{"username":"admin","password":"..."}' $B/api/auth/login
T=$(awk '/nmp_csrf/{print $7}' jar)

# list servers with filters/sort/paging
curl -sk -b jar "$B/api/servers?q=APP&environment=production&status=DOWN&sort=cpu&order=desc&page=1&page_size=25"

# add a Windows server from a template and apply immediately
curl -sk -b jar -H "X-CSRF-Token: $T" -H 'Content-Type: application/json' -X POST $B/api/servers -d '{
  "hostname":"APP-SERVER-02","display_name":"Application Server 2","address":"10.0.0.50","environment":"production",
  "os_type":"windows","monitoring_method":"ncpa","template_id":1,"location":"Main DC",
  "ncpa":{"port":5693,"token":"<ncpa token>","ssl_enabled":true,"verify_ssl":false,"timeout":30},
  "action":"apply"}'
# -> data.server (no secrets) + data.version {status: applied|validation_failed, errors:[{message,file,line,object,suggestion}], steps:[...]}

# test NCPA before saving
curl -sk -b jar -H "X-CSRF-Token: $T" -H 'Content-Type: application/json' -X POST $B/api/servers/test-connection \
  -d '{"address":"10.0.0.50","monitoring_method":"ncpa","ncpa":{"port":5693,"token":"<token>"}}'
# -> {"data":{"result":"success|auth_failed|timeout|agent_not_installed|connection_failed","label":"Connection Successful",...}}

# validate / apply all pending changes
curl -sk -b jar -H "X-CSRF-Token: $T" -X POST $B/api/config/validate
curl -sk -b jar -H "X-CSRF-Token: $T" -X POST $B/api/config/apply
```

`action` on server create/update: `draft` (not generated), `save` (pending), `validate` (generate + nagios -v), `apply` (full pipeline).

## Endpoints

### Administration

| Method | Path | Operation |
|---|---|---|
| GET | `/api/audit` | Audit Log |
| GET | `/api/health` | Health |
| GET | `/api/permissions` | List Permissions |
| GET | `/api/roles` | List Roles |
| POST | `/api/roles` | Create Role |
| PUT | `/api/roles/{rid}` | Update Role |
| DELETE | `/api/roles/{rid}` | Delete Role |
| GET | `/api/settings` | Get Settings Api |
| PUT | `/api/settings` | Put Settings |
| GET | `/api/users` | List Users |
| POST | `/api/users` | Create User |
| PUT | `/api/users/{uid}` | Update User |
| DELETE | `/api/users/{uid}` | Delete User |
| POST | `/api/users/{uid}/unlock` | Unlock User |

### Companies and locations

| Method | Path | Operation |
|---|---|---|
| GET | `/api/companies` | Super Admin: all companies with server and user counts. Others: their own companies |
| POST | `/api/companies` | Create `{"name","code","description","is_active"}` (Super Admin) |
| PUT | `/api/companies/{id}` | Rename / retire (Super Admin) |
| GET | `/api/locations` | Super Admin: all locations with counts. Others: their assigned sites, or all active sites if not site-limited |
| POST | `/api/locations` | Create (Super Admin) |
| PUT | `/api/locations/{id}` | Rename / retire (Super Admin) |

Servers take `company_id` (required for non-Super-Admin users, must be one of theirs) and `location_id`. Lists, dashboard and reports accept `company_id` and `location_id` within the caller's scope (`-1` = not assigned, Super Admin only). Users take `company_ids` and optional `location_ids`.

### Maintenance (Super Admin only)

| Method | Path | Operation |
|---|---|---|
| GET | `/api/maintenance/cleanup/categories` | Cleanup categories, default and minimum ages |
| POST | `/api/maintenance/cleanup/preview` | Count what would be removed. Body: `{"items":[{"category":"perf_samples","older_than_days":90}]}` |
| POST | `/api/maintenance/cleanup` | Execute. Same body plus `"confirm":"DELETE"`. Audited as `maintenance.cleanup` |

### Auth

| Method | Path | Operation |
|---|---|---|
| POST | `/api/auth/change-password` | Change Password |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Me |

### Backups

| Method | Path | Operation |
|---|---|---|
| GET | `/api/backups` | List Backups |
| POST | `/api/backups` | Create Backup |
| GET | `/api/backups/{bid}/download` | Download Backup |
| POST | `/api/backups/{bid}/restore` | Restore Backup |

### Catalog

| Method | Path | Operation |
|---|---|---|
| GET | `/api/commands` | List Commands |
| POST | `/api/commands` | Create Command |
| PUT | `/api/commands/{cid}` | Update Command |
| DELETE | `/api/commands/{cid}` | Delete Command |
| GET | `/api/contact-groups` | List Cgroups |
| POST | `/api/contact-groups` | Create Cgroup |
| PUT | `/api/contact-groups/{gid}` | Update Cgroup |
| DELETE | `/api/contact-groups/{gid}` | Delete Cgroup |
| GET | `/api/contacts` | List Contacts |
| POST | `/api/contacts` | Create Contact |
| PUT | `/api/contacts/{cid}` | Update Contact |
| DELETE | `/api/contacts/{cid}` | Delete Contact |
| GET | `/api/hostgroups` | List Groups |
| POST | `/api/hostgroups` | Create Group |
| PUT | `/api/hostgroups/{gid}` | Update Group |
| DELETE | `/api/hostgroups/{gid}` | Delete Group |
| GET | `/api/services` | List Service Defs |
| POST | `/api/services` | Create Service Def |
| PUT | `/api/services/{sid}` | Update Service Def |
| DELETE | `/api/services/{sid}` | Delete Service Def |
| GET | `/api/templates` | List Templates |
| POST | `/api/templates` | Create Template |
| GET | `/api/templates/{tid}` | Get Template |
| PUT | `/api/templates/{tid}` | Update Template |
| DELETE | `/api/templates/{tid}` | Delete Template |
| GET | `/api/timeperiods` | Timeperiods |

### Configuration

| Method | Path | Operation |
|---|---|---|
| POST | `/api/config/apply` | Apply |
| GET | `/api/config/pending` | Pending |
| POST | `/api/config/validate` | Validate |
| GET | `/api/config/versions` | Versions |
| GET | `/api/config/versions/{a}/diff/{b}` | Version Diff |
| GET | `/api/config/versions/{vid}` | Version Detail |
| POST | `/api/config/versions/{vid}/apply` | Apply Existing |
| GET | `/api/config/versions/{vid}/download` | Version Download |
| GET | `/api/config/versions/{vid}/file` | Version File |
| POST | `/api/config/versions/{vid}/rollback` | Rollback |

### Monitoring

| Method | Path | Operation |
|---|---|---|
| GET | `/api/dashboard` | Dashboard |
| GET | `/api/events` | Events |
| POST | `/api/monitoring/acknowledge` | Acknowledge |
| DELETE | `/api/monitoring/acknowledge` | Remove Ack |
| POST | `/api/monitoring/downtime` | Schedule Downtime |
| DELETE | `/api/monitoring/downtime/{kind}/{downtime_id}` | Cancel Downtime |
| GET | `/api/monitoring/downtimes` | Mon Downtimes |
| GET | `/api/monitoring/hosts` | Mon Hosts |
| GET | `/api/monitoring/problems` | Mon Problems |
| POST | `/api/monitoring/recheck` | Recheck |
| GET | `/api/monitoring/services` | Mon Services |

### Import

| Method | Path | Operation |
|---|---|---|
| POST | `/api/import` | Run Import |
| GET | `/api/import/scan` | Scan |

### Notifications

| Method | Path | Operation |
|---|---|---|
| GET | `/api/notification-channels` | List Channels |
| POST | `/api/notification-channels` | Create Channel |
| PUT | `/api/notification-channels/{cid}` | Update Channel |
| DELETE | `/api/notification-channels/{cid}` | Delete Channel |
| POST | `/api/notification-channels/{cid}/test` | Test Channel |
| GET | `/api/notification-providers` | Providers |
| GET | `/api/notification-rules` | List Rules |
| POST | `/api/notification-rules` | Create Rule |
| PUT | `/api/notification-rules/{rid}` | Update Rule |
| DELETE | `/api/notification-rules/{rid}` | Delete Rule |
| GET | `/api/notifications` | Feed |
| POST | `/api/notifications/read-all` | Mark All Read |

### Reports

| Method | Path | Operation |
|---|---|---|
| GET | `/api/reports/availability` | Availability Report |
| GET | `/api/reports/health` | Health Report |
| GET | `/api/reports/performance` | Performance Report |
| GET | `/api/reports/service-availability` | Service Availability |
| GET | `/api/reports/sla` | Sla Report |

### Servers

| Method | Path | Operation |
|---|---|---|
| GET | `/api/servers` | List Servers |
| POST | `/api/servers` | Create Server |
| POST | `/api/servers/test-connection` | Test Connection |
| GET | `/api/servers/{server_id}` | Get Server |
| PUT | `/api/servers/{server_id}` | Update Server |
| DELETE | `/api/servers/{server_id}` | Delete Server |
| POST | `/api/servers/{server_id}/apply` | Apply Server |
| POST | `/api/servers/{server_id}/apply-template/{template_id}` | Apply Template |
| POST | `/api/servers/{server_id}/disable` | Disable Server |
| POST | `/api/servers/{server_id}/enable` | Enable Server |
| GET | `/api/servers/{server_id}/events` | Server Events |
| GET | `/api/servers/{server_id}/history` | Server History |
| GET | `/api/servers/{server_id}/performance` | Performance |
| PUT | `/api/servers/{server_id}/services` | Replace Services |
| POST | `/api/servers/{server_id}/test` | Test Server |
| POST | `/api/servers/{server_id}/validate` | Validate Server |