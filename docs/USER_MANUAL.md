# User Manual

## Concepts

- **Portal changes are saved first and applied later.** Saving a server, service, group or contact records a *pending change*. Nothing reaches Nagios until someone with the *Apply* permission applies the configuration. The yellow **"N pending changes"** pill in the top bar lists what is waiting.
- **Apply** always regenerates the complete portal-managed configuration from the database, then runs: validate → backup → install → validate live → reload → verify. If anything fails, nothing is applied and the running Nagios keeps its previous configuration. The result dialog shows each step and, for errors, the file, line, object and a suggested fix.
- **Configuration versions**: every generate/validate/apply creates a numbered version with its files, result, backup and a snapshot you can roll back to.
- **Portal vs manual objects**: hosts, groups and contacts defined in your existing Nagios files are labelled *Manual*. They show live status and can be referenced (for example, the `admins` contact group), but only the portal's own objects are edited here. Use **Import** to take existing hosts over.

## Roles

| Role | Can |
|---|---|
| Super Admin | Everything, including users, roles, system settings and data cleanup |
| Administrator | Servers, services, templates, groups, contacts, validate/apply/rollback, import, backups, notifications, reports, audit |
| Operator | View everything, acknowledge problems, schedule downtime, re-check, test connections |
| Viewer | Read-only dashboards, monitoring, inventory, reports |

Custom roles can be created under **Administration → Roles** from any combination of the permissions (data cleanup is reserved for Super Admin).

## Dashboard
**Host health** and **Service health** lead the page: the share of hosts up / services OK as a large figure, and a status bar showing problems first (down, unreachable, critical, warning, unknown, pending) then healthy. Every state has an icon, label, count and percentage; click one to open the filtered list. Below that: infrastructure summary (total, up, down, warning, unknown, unreachable), service summary (OK, warning, critical, unknown), 30-day availability, top problems, recent events (host and service failures, recoveries and configuration changes) and inventory by environment. Click a tile to open the filtered list. The page refreshes every 30 seconds.

## Monitoring
- **Hosts / Services**: live Nagios status for *all* hosts and services, including manually configured ones. Use the icons to acknowledge, schedule downtime or re-check now.
- **Problems**: non-OK hosts and services. Acknowledged and in-downtime items are hidden unless you tick the box.
- **Events**: the Nagios event log (alerts, notifications, program restarts) merged with portal configuration changes. Filter by type, period and host.
- **Downtime**: current and future scheduled downtime. You can schedule and cancel downtime here.

## Servers

**Infrastructure → Servers** (and **Network Devices**) shows the inventory joined with live status: status, host name, IP, OS, agent, environment, location, host group, CPU, memory, disk, uptime, last check, last state change, 30-day availability and actions. You can search, filter by status, OS, environment, agent, group and config state, sort any column, change page size and export to CSV.

Row actions (**⋯**): View, Edit, Enable/Disable, Test connection, Validate configuration, Apply configuration, View monitoring, View history, Delete.

Status badges: **UP/OK** (green), **WARNING** (amber), **CRITICAL/DOWN** (red), **UNREACHABLE** (orange), **UNKNOWN** (purple), **PENDING** (not checked yet), **NOT IN NAGIOS** (not applied yet). Config badges: *Draft*, *Pending apply*, *Applied*.

### Add server wizard
1. **Basic information**: host name (the Nagios `host_name`; letters, digits, `.`, `_`, `-`), display name, IP/FQDN, description, location, environment (Production, UAT, Development, DR, Test), host groups and contact groups.
2. **Operating system**: Windows, Linux, Unix, Network Device, Other. Optionally enter the OS version (filled automatically by a successful NCPA test).
3. **Monitoring method**: NCPA, SNMP (v2c/v3), NRPE, Ping only, or Custom plugin.
   - For NCPA, enter the port (5693), token, SSL, certificate verification and timeout. Click **Test connection** to see *Connection Successful*, *Authentication Failed*, *Timeout*, *Agent Not Installed* or *Connection Failed*. The token is encrypted and never shown again; when editing, leave it blank to keep the stored one.
   - Host check: *agent responds* (NCPA answers) or *ICMP ping*. Use the agent check if ICMP is blocked by the Windows firewall.
4. **Monitoring services**: choose a template (Windows Standard, Windows Application Server, Linux Standard, Network Device Standard, Ping Only, or your own) and/or **Add service**. Each service has its own parameters, such as drive letter, mount point, Windows service name and expected state, process name or interface. Untick to keep a service defined but not monitored.
5. **Thresholds**: warning, critical, check interval, retry interval, max attempts, notification interval and notifications on/off for each service, plus the host's intervals and time periods. Threshold syntax: `80` alerts above 80; `10:` alerts below 10; `~:90`; `@5:10` alerts inside 5–10; Ping uses `rta,loss%`, e.g. `200.0,20%`.
6. **Review**: check the complete configuration, then choose **Save as draft** (not included in Nagios), **Save & validate** (runs `nagios -v`, applies nothing), **Save & apply** (full pipeline) or **Cancel**.

### Windows service monitoring
Add the service **Windows Service** and set *Service name* (the service key, e.g. `MSSQLSERVER`, `SQLSERVERAGENT`, `W3SVC`, `Spooler`, `wuauserv`), *Display name*, *Expected state* (running/stopped) and *State when not as expected* (warning or critical).

### Linux and custom checks
Linux via NCPA supports CPU, memory, filesystem per mount, swap, processes, named process, users, network, uptime and load (load needs `check_load` in the NCPA plugins folder). Use **Custom NCPA Query** for any NCPA metric path, or **NCPA Agent Plugin** to run a plugin on the agent. For your own Nagios plugins, create a **Command** and a **Service definition** under Configuration.

### Network devices
Add a device with OS *Network Device* and method *SNMP* (v2c community, or v3 user with auth/priv). The *Network Device Standard* template gives Ping (latency and packet loss), Device Uptime, Interface Status and Interface Utilization. You can also add Interface Bandwidth or any numeric **SNMP OID**. Set the `ifIndex` per interface. Utilization needs two samples, so the first check reports "collecting baseline".

### Server details
Tabs: **Overview** (all properties plus live status, availability, CPU, memory, disk, uptime), **Performance** (one chart per metric for 6h/24h/7d/30d: current value with OK/Warning/Critical state, average, peak and low, a shaded trend line, dashed warning/critical lines, and gaps where no samples were collected. Hover with the mouse, drag a finger on a phone, or focus a chart and use ←/→ to read exact values; **Table** shows the raw samples), **Services** (status, current value, thresholds, last/next check, output and performance data, with acknowledge and re-check), **Events** (historical alerts for the host) and **History** (every change with user, time, IP and old → new values).

## Templates
**Infrastructure → Templates**: create or edit service sets. Changing a template does not modify servers already created from it. Use *Apply template* on the server to add missing services.

## Configuration
- **Pending Changes**: what will be applied, with Validate / Apply.
- **Services**: the service catalogue (check definitions). Built-in definitions can have their argument template and defaults tuned. New definitions use a safe template language (`{param}`, `{warning}`, `{critical}`, optional `[[ … ]]`).
- **Commands**: portal-managed Nagios commands (`nmp_*` built-ins are read-only).
- **Contacts / Contact Groups**: portal contacts for Nagios' own e-mail notifications. Manual ones are listed read-only.
- **Configuration Versions**: list with version, date, user, change and status. Open a version to view the files, pipeline steps, errors, included changes and raw `nagios -v` output. You can **Compare** any two versions (unified diff), **Download** a version (zip, no secrets) or **Roll back to this version**.

## Import existing configuration
**Administration → Import Configuration** scans your manual Nagios files. For each host it shows the detected agent, whether a token was found, and how each service maps to a portal service definition.
- **Take over**: select hosts, set environment and OS, then *Validate only* or *Import & apply*. The portal creates the servers, encrypts tokens, generates new definitions and comments out the old blocks, all in one validated and backed-up version. If validation fails, nothing is imported.
- **Read-only**: record hosts in the inventory for live status without managing them.

## Reports
Availability (per server or per service, any period; charts of the 10 lowest-availability and most-downtime servers), SLA (against targets per environment, with a met/breached bar), Performance (average and peak CPU, memory, disk; top-8 charts for peak CPU, peak memory and fullest disk, red ≥ 90 %, amber ≥ 80 %), Infrastructure Health (high disk, memory, CPU and repeated failures) and Audit. Every report has **CSV** export and **Print / PDF** (use the browser's *Save as PDF*; navigation is hidden in print).

## Administration
- **Users**: create, edit, disable, unlock and reset passwords (with forced change at next login).
- **Roles**: permission matrix and custom roles.
- **Notifications**: *channels* (E-mail SMTP, Microsoft Teams, WhatsApp or SMS via HTTP gateway, generic webhook, in-app) and *rules* (events: host down, service critical/warning, recovery, high CPU/memory/disk, network down; filters by environment and host group; throttling). Use **Send test** on a channel. Portal notifications are independent of Nagios' own contact notifications.
- **System Settings**: display time zone (default Asia/Kolkata), default contact group, notification commands, NCPA defaults, SLA targets, health thresholds, performance retention and session timeout.
- **Backups**: automatic and manual backups, download, and emergency restore.
- **System Health**: Nagios, Apache, MariaDB, disk, memory, CPU, configuration status (including drift), last backup, worker, and NCPA agent connectivity. *Deep check* validates the live configuration and probes agent ports.
- **Data Cleanup** (Super Admin only): remove junk and stale data. Select categories (expired sessions, old graph samples, orphaned data of deleted servers, old notifications, old audit entries, failed/abandoned configuration versions, old configuration history, leftover staging folders, old backups, deleted servers), set the age where relevant, click **Preview** to see counts (nothing is deleted), then **Clean up** and type `DELETE`. Protected items (live version, newest versions/backups, the backup before the live version, the installation backup, servers whose deletion is not yet applied) are shown in the *Kept* column. Each run is recorded in the audit log.
