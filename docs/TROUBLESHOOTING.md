# Troubleshooting

Logs: `/var/log/nagios-management/` (`application.log`, `configuration.log` = every pipeline step, `security.log`, `audit.log`, `error.log`, `install-*.log`), `journalctl -u nagios-management`, `journalctl -u nagios-management-worker`, Apache `nagios-management-error.log`, Nagios `/usr/local/nagios/var/nagios.log`.

| Symptom | Cause / fix |
|---|---|
| Portal shows **502 / Service Unavailable** | API not running: `systemctl status nagios-management`, `journalctl -u nagios-management -n 50`. Check that the DB password file and master key are readable by `nagmgmt` (`ls -l /etc/nagios-management`). |
| Installer: *"current Nagios configuration does not validate"* | Fix the reported errors first. Run it yourself **as nagios**: `sudo -u nagios /usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg`. Running as a normal user gives a false *"Unable to write to check_result_path"* error. |
| Validate/Apply: *"sudo rule for the portal is missing or incorrect"* | `sudo -l -U nagmgmt` must list the five scripts. Reinstall `/etc/sudoers.d/nagios-management` (0440 root:root) and check it with `visudo -cf`. On sudo-rs, make sure the paths match exactly `/opt/nagios-management/privileged/sbin/...`. |
| Apply: *"another configuration operation is in progress"* | Only one pipeline runs at a time. Wait and retry. A stale lock clears automatically when the process ends. |
| Apply: validation errors about a name *already defined in manual configuration* | A host, command or group with that name exists in your own files. Rename it in the portal, or **Import → Take over** the existing host. |
| Apply: *"<file> was modified after the change was prepared"* | A manual file changed between scan and apply. Rescan the import and try again. |
| Apply fails at **verify** (*"waiting for Nagios to report the new program start"*) | Nagios did not come back after the reload. The portal restored the previous files and reloaded again. Check `systemctl status nagios` and `nagios.log`. Make sure the unit's ExecReload works (`systemctl reload nagios`). If `systemctl` says the unit changed on disk, run `systemctl daemon-reload`. |
| Server shows **NOT IN NAGIOS** | It is Draft or not applied yet. Open Pending Changes → Apply. |
| NCPA test: **Agent Not Installed** | Nothing listens on port 5693. Check that the NCPA service is running on the Windows server and the firewall allows 5693/TCP from the Nagios server. |
| NCPA test: **Authentication Failed** | Wrong token. It must match `community_string` in `ncpa.cfg` on the agent. |
| NCPA test: **Timeout / Connection Failed** | Routing, firewall, DNS, or TLS verification with a self-signed agent certificate (untick *Verify certificate*). |
| Service **UNKNOWN: no NCPA credential found for srv-N** | The configuration was not applied after the token was set, or `managed-secrets` was deleted. Apply again. |
| Service **UNKNOWN: Incorrect credentials given** | The token in the portal differs from the agent's. Edit the server, enter the correct token, apply. |
| Windows **Event Log** check returns an error | NCPA versions differ in the event-log endpoint name. Edit the *Event Log* service definition's argument template (`windowslogs` vs `logs`). |
| Ping/TCP services **UNKNOWN (No such file)** | The standard plugins are missing: `apt install monitoring-plugins` (portal commands use `/usr/lib/nagios/plugins`). Note: on this server `/usr/local/nagios/libexec` contains only `check_ncpa.py`, so the stock `localhost` checks (`$USER1$/check_ping` etc.) fail. Either install the Nagios plugins into libexec or set `$USER1$` in resource.cfg to `/usr/lib/nagios/plugins`. |
| SNMP **collecting baseline** | Normal on the first interface utilization/bandwidth check. The rate needs two samples. |
| Charts empty | The worker samples performance data after each check. Check `systemctl status nagios-management-worker` and System Health → *Background worker*. |
| Acknowledge/Downtime: *"Nagios is not reading its command pipe"* | Nagios is stopped, or `check_external_commands=0`. `nagmgmt` must be in the `nagios` group (`id nagmgmt`). |
| Health shows **drift** | Files in `/usr/local/nagios/etc/managed` differ from the last applied version (manual edit or emergency restore). Apply again to regenerate. |
| Locked out | `sudo nmp-admin reset-password <user>`, then log in and change the password. |
| Lost `master.key` | Stored credentials cannot be decrypted. Generate a new key (`nmp-admin gen-key /etc/nagios-management/master.key`, then fix ownership to root:nagmgmt 0440), re-enter every NCPA token, SNMP credential and channel secret, and apply. |
| Roll back the whole installation | Uninstall, then extract `/var/lib/nagios-management/backups/pre-install-<ts>.tar.gz` (or the uninstall final backup), validate with `nagios -v`, and `systemctl reload nagios`. |

## Manual recovery of Nagios configuration

Every apply leaves a backup in `/var/lib/nagios-management/backups/<ts>-pre-apply-v<N>.tar.gz` containing `nagios.cfg`, `managed/` and every manual object file (`legacy/NNNN.cfg`, mapped in `backup-meta.json`). Use **Administration → Backups → Restore** or run:

```bash
sudo /opt/nagios-management/privileged/sbin/nagios-config-rollback <backup-name>   # validates before installing
```
