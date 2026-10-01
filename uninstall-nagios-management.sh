#!/usr/bin/env bash
# =============================================================================
#  uninstall-nagios-management.sh - remove the portal
#
#  Default: removes the portal (services, Apache site, sudoers, code) but KEEPS
#  monitoring exactly as it is: the generated objects in the managed directory
#  stay registered in nagios.cfg, so Nagios keeps monitoring those servers.
#
#  Options:
#    --remove-managed   also unregister the managed directory from nagios.cfg
#                       (validated + backed up; portal-managed hosts STOP being monitored)
#    --drop-database    drop the MariaDB database and user (a final dump is kept)
#    --purge            also delete /etc/nagios-management (master key!) and /var/lib/nagios-management
#    --yes              do not ask for confirmation
# =============================================================================
set -Eeuo pipefail
APP=/opt/nagios-management; ETC=/etc/nagios-management; VAR=/var/lib/nagios-management
REMOVE_MANAGED=0; DROP_DB=0; PURGE=0; YES=0
for a in "$@"; do case "$a" in
  --remove-managed) REMOVE_MANAGED=1 ;; --drop-database) DROP_DB=1 ;; --purge) PURGE=1 ;; --yes|-y) YES=1 ;;
  -h|--help) sed -n '2,16p' "$0"; exit 0 ;; *) echo "unknown option $a"; exit 2 ;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
TS="$(date +%Y%m%d-%H%M%S)"
echo "This will uninstall the Nagios Management Portal."
[ $REMOVE_MANAGED = 1 ] && echo " - the managed directory will be REMOVED from nagios.cfg (those hosts stop being monitored)"
[ $DROP_DB = 1 ] && echo " - the database will be DROPPED (a final dump is kept)"
[ $PURGE = 1 ] && echo " - configuration and backups will be DELETED (including the master key)"
if [ $YES = 0 ]; then read -r -p "Continue? [y/N] " x; [[ "$x" =~ ^[Yy] ]] || exit 1; fi

FINAL="/root/nagios-management-final-backup-$TS"
mkdir -p "$FINAL"; chmod 700 "$FINAL"
tar -czf "$FINAL/nagios-etc.tar.gz" /usr/local/nagios/etc 2>/dev/null || true
if [ -f "$ETC/app.env" ]; then
  set -a; . "$ETC/app.env"; set +a
  MYSQL_PWD="$(cat "$NMP_DB_PASSWORD_FILE")" mariadb-dump --single-transaction -u "$NMP_DB_USER" "$NMP_DB_NAME" 2>/dev/null | gzip > "$FINAL/database.sql.gz" || true
  cp -a "$ETC" "$FINAL/etc-nagios-management" 2>/dev/null || true
fi
echo "Final backup: $FINAL"

if [ $REMOVE_MANAGED = 1 ]; then
  "$APP/privileged/sbin/nagios-register-managed" unregister || { echo "unregister failed - nagios.cfg restored; aborting"; exit 1; }
fi
systemctl disable --now nagios-management-worker nagios-management 2>/dev/null || true
rm -f /etc/systemd/system/nagios-management.service /etc/systemd/system/nagios-management-worker.service
systemctl daemon-reload
if [ -f /etc/apache2/sites-available/nagios-management.conf ]; then
  a2dissite -q nagios-management || true; rm -f /etc/apache2/sites-available/nagios-management.conf
  apache2ctl configtest >/dev/null 2>&1 && systemctl reload apache2 || true
fi
rm -f /etc/sudoers.d/nagios-management /etc/logrotate.d/nagios-management /usr/local/sbin/nmp-admin
rm -rf "$APP"
if [ $DROP_DB = 1 ] && [ -n "${NMP_DB_NAME:-}" ]; then
  mariadb -e "DROP DATABASE IF EXISTS \`$NMP_DB_NAME\`; DROP USER IF EXISTS '$NMP_DB_USER'@'localhost';"
fi
if [ $PURGE = 1 ]; then rm -rf "$ETC" "$VAR"; fi
if [ $REMOVE_MANAGED = 0 ]; then
  echo "Managed Nagios objects remain in /usr/local/nagios/etc/managed and are still monitored."
  echo "The NCPA wrapper (/usr/local/nagios/libexec/nmp) and secrets (/usr/local/nagios/etc/managed-secrets) were kept for them."
else
  rm -rf /usr/local/nagios/libexec/nmp /usr/local/nagios/etc/managed-secrets
fi
id nagmgmt >/dev/null 2>&1 && userdel nagmgmt 2>/dev/null || true
echo "Uninstalled."
