#!/usr/bin/env bash
# =============================================================================
#  upgrade-nagios-management.sh - upgrade the portal in place
#
#  1. backs up the database (mariadb-dump) and the current application tree
#  2. stops the portal services (Nagios keeps running - monitoring is unaffected)
#  3. installs the new code, Python dependencies and check wrappers
#  4. runs database migrations and idempotent reference-data seeding
#  5. starts the services and runs health checks
#  On failure the previous code is restored and services restarted; the DB dump
#  can be re-imported (command printed below).
#  Usage: sudo ./upgrade-nagios-management.sh
# =============================================================================
set -Eeuo pipefail
umask 027
APP=/opt/nagios-management
ETC=/etc/nagios-management
VAR=/var/lib/nagios-management
APP_USER=nagmgmt
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
BK="$VAR/backups/upgrade-$TS"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -f "$ETC/app.env" ] || { echo "portal not installed (missing $ETC/app.env) - use install-nagios-management.sh"; exit 1; }
as_app() { runuser -u "$APP_USER" -- bash -c 'set -a; . "$0"; set +a; cd "$1"; shift; exec "$@"' "$ETC/app.env" "$APP/backend" "$@"; }
# shellcheck disable=SC1090
set -a; . "$ETC/app.env"; set +a
echo "Upgrading $(cat "$APP/VERSION" 2>/dev/null || echo '?') -> $(cat "$SRC/VERSION")"

mkdir -p "$BK"; chmod 700 "$BK"
echo "==> backing up database and application"
MYSQL_PWD="$(cat "$NMP_DB_PASSWORD_FILE")" mariadb-dump --single-transaction --routines -u "$NMP_DB_USER" "$NMP_DB_NAME" | gzip > "$BK/database.sql.gz"
tar -czf "$BK/app.tar.gz" --exclude="${APP#/}/venv" -C / "${APP#/}"
[ -f /etc/sudoers.d/nagios-management ] && cp -a /etc/sudoers.d/nagios-management "$BK/sudoers.nagios-management"
echo "    $BK"

restore() {
  echo "!! upgrade failed - restoring previous application code"
  rm -rf "$APP/backend" "$APP/frontend" "$APP/privileged"
  tar -xzf "$BK/app.tar.gz" -C /
  [ -f "$BK/sudoers.nagios-management" ] && install -o root -g root -m 440 "$BK/sudoers.nagios-management" /etc/sudoers.d/nagios-management
  systemctl start nagios-management nagios-management-worker || true
  echo "   Database backup: $BK/database.sql.gz"
  echo "   To restore it:   zcat $BK/database.sql.gz | mariadb $NMP_DB_NAME"
  exit 1
}
trap restore ERR

echo "==> stopping portal services (Nagios keeps running)"
systemctl stop nagios-management-worker nagios-management

echo "==> installing new code"
for d in backend frontend/dist privileged; do rm -rf "${APP:?}/$d"; mkdir -p "$(dirname "$APP/$d")"; cp -a "$SRC/$d" "$APP/$d"; done
rm -rf "$APP/backend/tests"; find "$APP/backend" -name '__pycache__' -prune -exec rm -rf {} +
cp "$SRC/VERSION" "$APP/VERSION"
chown -R root:root "$APP"; chmod -R u=rwX,go=rX "$APP"; chmod 755 "$APP"/privileged/sbin/*
( umask 022; "$APP/venv/bin/pip" install -q -r "$APP/backend/requirements.txt" )
chmod -R u=rwX,go=rX "$APP/venv"

LIBEXEC="$NMP_PLUGIN_DIR_NCPA"; NMPDIR="$NMP_PLUGIN_DIR_NMP"
NGROUP="$(stat -c %G "$NMPDIR")"
for f in check_ncpa_nmp.py check_snmp_nmp.py; do
  sed -e "s#^CHECK_NCPA = .*#CHECK_NCPA = \"$LIBEXEC/check_ncpa.py\"#" -e "s#^STATE_DIR = .*#STATE_DIR = \"$NMP_NAGIOS_BASE/var/nmp-snmp-state\"#" \
    "$APP/privileged/plugins/$f" > "$NMPDIR/$f.new"; chown root:"$NGROUP" "$NMPDIR/$f.new"; chmod 750 "$NMPDIR/$f.new"; mv "$NMPDIR/$f.new" "$NMPDIR/$f"
done
sed -e "s#^SECRETS_FILE = .*#SECRETS_FILE = \"$NMP_NAGIOS_BASE/etc/managed-secrets/nmp-secrets.tsv\"#" "$APP/privileged/plugins/nmp_secrets.py" > "$NMPDIR/nmp_secrets.py.new"
chown root:"$NGROUP" "$NMPDIR/nmp_secrets.py.new"; chmod 640 "$NMPDIR/nmp_secrets.py.new"; mv "$NMPDIR/nmp_secrets.py.new" "$NMPDIR/nmp_secrets.py"

echo "==> sudoers rule (whitelisted helper scripts only)"
TMP_SUDO="$(mktemp)"; cp "$SRC/deploy/sudoers/nagios-management" "$TMP_SUDO"
if command -v visudo >/dev/null; then visudo -cf "$TMP_SUDO" >/dev/null || { rm -f "$TMP_SUDO"; echo "sudoers file invalid"; false; }; fi
install -o root -g root -m 440 "$TMP_SUDO" /etc/sudoers.d/nagios-management; rm -f "$TMP_SUDO"
runuser -u "$APP_USER" -- sudo -n "$APP/privileged/sbin/nagios-status-check" >/dev/null 2>&1 || { echo "sudo rule not effective for $APP_USER"; false; }
if runuser -u "$APP_USER" -- sudo -n /usr/bin/id >/dev/null 2>&1; then echo "SECURITY: $APP_USER can run arbitrary commands via sudo"; false; fi

echo "==> database migrations"
as_app "$APP/venv/bin/python" -m nmp.cli migrate
as_app "$APP/venv/bin/python" -m nmp.cli bootstrap >/dev/null

PORT="$(grep -Eo -- '--port [0-9]+' /etc/systemd/system/nagios-management.service | awk '{print $2}')"
sed "s#@PORT@#${PORT:-8095}#g" "$SRC/deploy/systemd/nagios-management.service" > /etc/systemd/system/nagios-management.service
cp "$SRC/deploy/systemd/nagios-management-worker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl start nagios-management nagios-management-worker
sleep 3
curl -fsS "http://127.0.0.1:${PORT:-8095}/api/healthz" >/dev/null
trap - ERR
echo "==> upgrade complete ($(cat "$APP/VERSION")). Backup kept in $BK"
echo "    Generated Nagios configuration is unchanged until the next apply."
