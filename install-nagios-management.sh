#!/usr/bin/env bash
# =============================================================================
#  install-nagios-management.sh - Nagios Management Portal installer
# -----------------------------------------------------------------------------
#  Safe by design:
#    * Runs read-only pre-flight checks first and STOPS on any problem.
#    * Takes a full backup of /usr/local/nagios/etc, Apache and sudoers config
#      before changing anything.
#    * The only change to nagios.cfg (registering the managed directory and,
#      optionally, removing duplicate cfg_dir lines) goes through
#      BACKUP -> VALIDATE -> APPLY -> RELOAD -> VERIFY with automatic restore.
#    * Never reinstalls or restarts Nagios; never overwrites existing objects.
#
#  Usage (as root, from the extracted package directory):
#    sudo ./install-nagios-management.sh [options]
#
#  Options:
#    --server-name NAME     HTTPS server name for the portal (default: hostname -f)
#    --cert FILE --key FILE use this TLS certificate instead of a self-signed one
#    --admin-user NAME      initial Super Admin user name (default: admin)
#    --port N               internal API port (default 8095)
#    --no-dedupe            do not remove duplicate cfg_dir/cfg_file lines from nagios.cfg
#    --db-admin-user USER   MariaDB admin user if root socket auth is not available
#    --yes                  non-interactive (accept defaults, generate admin password)
#    --skip-apache          do not configure Apache (configure your proxy manually)
# =============================================================================
set -Eeuo pipefail
umask 027

APP=/opt/nagios-management
ETC=/etc/nagios-management
VAR=/var/lib/nagios-management
LOG=/var/log/nagios-management
NAGIOS_BASE=/usr/local/nagios
NAGIOS_CFG=$NAGIOS_BASE/etc/nagios.cfg
NAGIOS_BIN=$NAGIOS_BASE/bin/nagios
LIBEXEC=$NAGIOS_BASE/libexec
MANAGED=$NAGIOS_BASE/etc/managed
SECRETS=$NAGIOS_BASE/etc/managed-secrets
STD_PLUGINS=/usr/lib/nagios/plugins
APP_USER=nagmgmt
DB_NAME=nagios_mgmt
DB_USER=nagios_mgmt
PORT=8095
SERVER_NAME="$(hostname -f 2>/dev/null || hostname)"
CERT=""; KEY=""; ADMIN_USER="admin"; DEDUPE=1; YES=0; SKIP_APACHE=0; DB_ADMIN_USER=""
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"

while [ $# -gt 0 ]; do
  case "$1" in
    --server-name) SERVER_NAME="$2"; shift ;;
    --cert) CERT="$2"; shift ;;
    --key) KEY="$2"; shift ;;
    --admin-user) ADMIN_USER="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --no-dedupe) DEDUPE=0 ;;
    --db-admin-user) DB_ADMIN_USER="$2"; shift ;;
    --yes|-y) YES=1 ;;
    --skip-apache) SKIP_APACHE=1 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "Unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$LOG"
INSTALL_LOG="$LOG/install-$TS.log"
exec > >(tee -a "$INSTALL_LOG") 2>&1

c_ok()   { printf '  \033[32m[ OK ]\033[0m %s\n' "$*"; }
c_warn() { printf '  \033[33m[WARN]\033[0m %s\n' "$*"; }
c_err()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; }
step()   { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die()    { c_err "$*"; echo; echo "Installation stopped. Your Nagios configuration was not modified by this step."; echo "Log: $INSTALL_LOG"; exit 1; }
trap 'c_err "unexpected error on line $LINENO (see $INSTALL_LOG)"' ERR
confirm() { [ "$YES" = 1 ] && return 0; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }
# run a command as the service account with app.env loaded, from the backend directory
as_app() { runuser -u "$APP_USER" -- bash -c 'set -a; . "$0"; set +a; cd "$1"; shift; exec "$@"' "$ETC/app.env" "$APP/backend" "$@"; }

echo "Nagios Management Portal installer - $(date -Is)"
echo "Package: $SRC"

# =============================================================================
step "1. Detecting environment (read-only)"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
. /etc/os-release
c_ok "OS: $PRETTY_NAME"
[ -x "$NAGIOS_BIN" ] || die "Nagios binary not found at $NAGIOS_BIN"
[ -r "$NAGIOS_CFG" ] || die "nagios.cfg not found at $NAGIOS_CFG"
NV="$("$NAGIOS_BIN" --version 2>/dev/null | grep -Eo 'Nagios Core [0-9.]+' | head -1 || true)"
c_ok "$NV at $NAGIOS_BASE"
NAGIOS_USER="$(awk -F= '/^nagios_user=/{print $2}' "$NAGIOS_CFG" | tail -1)"; NAGIOS_USER="${NAGIOS_USER:-nagios}"
NAGIOS_GROUP="$(awk -F= '/^nagios_group=/{print $2}' "$NAGIOS_CFG" | tail -1)"; NAGIOS_GROUP="${NAGIOS_GROUP:-nagios}"
id "$NAGIOS_USER" >/dev/null 2>&1 || die "nagios user '$NAGIOS_USER' not found"
c_ok "Nagios runs as $NAGIOS_USER:$NAGIOS_GROUP"
for k in status_file log_file command_file object_cache_file log_archive_path lock_file; do
  v="$(awk -F= -v k="$k" '$1==k{print $2}' "$NAGIOS_CFG" | tail -1)"; printf -v "CFG_${k}" '%s' "$v"; c_ok "$k=$v"
done
NAGIOS_UNIT=""
for u in nagios nagios4; do systemctl list-unit-files "$u.service" >/dev/null 2>&1 && systemctl list-unit-files "$u.service" | grep -q "^$u.service" && { NAGIOS_UNIT=$u; break; }; done
[ -n "$NAGIOS_UNIT" ] || die "no systemd unit found for Nagios"
systemctl is-active --quiet "$NAGIOS_UNIT" || die "Nagios service '$NAGIOS_UNIT' is not running"
c_ok "systemd unit: $NAGIOS_UNIT (active)"
[ -f "$LIBEXEC/check_ncpa.py" ] && c_ok "check_ncpa.py found" || c_warn "check_ncpa.py not found in $LIBEXEC (NCPA checks will not work until installed)"
[ -d "$STD_PLUGINS" ] && c_ok "standard plugins: $STD_PLUGINS" || c_warn "$STD_PLUGINS missing - install 'monitoring-plugins' for ping/tcp checks"
systemctl is-active --quiet mariadb || systemctl is-active --quiet mysql || die "MariaDB is not running"
c_ok "MariaDB: $(mariadb --version 2>/dev/null | awk '{print $5}' | tr -d ,)"
if [ "$SKIP_APACHE" = 0 ]; then systemctl is-active --quiet apache2 || die "Apache is not running (use --skip-apache to configure a proxy yourself)"; c_ok "Apache: $(apache2 -v | head -1 | cut -d: -f2)"; fi
command -v python3 >/dev/null || die "python3 missing"
c_ok "Python: $(python3 --version)"
if ss -ltn "( sport = :$PORT )" | grep -q ":$PORT"; then
  if systemctl is-active --quiet nagios-management 2>/dev/null; then
    c_ok "port $PORT is used by an existing portal installation (re-run / repair)"
    systemctl stop nagios-management-worker nagios-management
  else
    die "TCP port $PORT is in use - choose another with --port"
  fi
else
  c_ok "port 127.0.0.1:$PORT is free"
fi
if [ -e "$MANAGED" ] && ! grep -q "^cfg_dir=$MANAGED" "$NAGIOS_CFG"; then
  LEFT="$(find "$MANAGED" "$SECRETS" -type f 2>/dev/null | head -20 || true)"
  if [ -n "$LEFT" ]; then
    echo "$LEFT" | sed 's/^/         /'
    die "$MANAGED contains files but is not registered in nagios.cfg - inspect/move them first"
  fi
  c_warn "$MANAGED exists (empty, left by an earlier interrupted run) - it will be reused"
fi

step "2. Pre-flight: validating the CURRENT Nagios configuration (as $NAGIOS_USER)"
if ! out="$(runuser -u "$NAGIOS_USER" -- "$NAGIOS_BIN" -v "$NAGIOS_CFG" 2>&1)"; then
  echo "$out" | grep -E "Error|Warning" | head -20
  die "the current Nagios configuration does not validate - fix it before installing the portal"
fi
c_ok "current configuration is valid ($(echo "$out" | grep -Eo 'Total Warnings: *[0-9]+'))"

# duplicate cfg lines report
DUPS="$(grep -E '^(cfg_dir|cfg_file)=' "$NAGIOS_CFG" | sort | uniq -d || true)"
if [ -n "$DUPS" ]; then
  c_warn "duplicate entries in nagios.cfg:"; echo "$DUPS" | sed 's/^/         /'
  [ "$DEDUPE" = 1 ] && c_ok "they will be removed (validated) - use --no-dedupe to keep them"
fi

echo
echo "Summary of changes:"
echo "  * create user '$APP_USER' (member of group '$NAGIOS_GROUP'), directories $APP $ETC $VAR $LOG"
echo "  * MariaDB database '$DB_NAME' and user '$DB_USER'@localhost"
echo "  * add 'cfg_dir=$MANAGED' to nagios.cfg$( [ "$DEDUPE" = 1 ] && [ -n "$DUPS" ] && echo ' and remove duplicate cfg_dir lines') (validated, backed up, reloaded)"
echo "  * NCPA/SNMP wrappers in $LIBEXEC/nmp, sudoers rule /etc/sudoers.d/nagios-management"
[ "$SKIP_APACHE" = 0 ] && echo "  * Apache HTTPS site for https://$SERVER_NAME/ (modules ssl, proxy, proxy_http, headers)"
echo "  * systemd services nagios-management and nagios-management-worker"
confirm "Proceed?" || die "aborted by user"

# =============================================================================
step "3. Backing up current configuration"
mkdir -p "$VAR/backups"; chmod 751 "$VAR"; chmod 750 "$VAR/backups"   # 751: nagios must traverse into work/ to validate
PRE="$VAR/backups/pre-install-$TS.tar.gz"
tar -czf "$PRE" --ignore-failed-read "$NAGIOS_BASE/etc" /etc/apache2 /etc/sudoers.d 2>/dev/null || true
chmod 600 "$PRE"
c_ok "backup: $PRE"

# =============================================================================
step "4. Installing OS dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-venv python3-dev build-essential snmp openssl curl >/dev/null
c_ok "python3-venv, python3-dev, snmp, openssl"

step "5. Service account and directories"
if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin --user-group "$APP_USER"
  c_ok "created user $APP_USER"
fi
usermod -a -G "$NAGIOS_GROUP" "$APP_USER"
c_ok "$APP_USER added to group $NAGIOS_GROUP (read status.dat / logs, write command pipe)"
install -d -o root -g root -m 755 "$APP"
install -d -o root -g "$APP_USER" -m 750 "$ETC"
install -d -o "$APP_USER" -g "$APP_USER" -m 750 "$VAR/staging"
install -d -o root -g "$NAGIOS_GROUP" -m 750 "$VAR/work"
install -d -o root -g "$APP_USER" -m 750 "$VAR/backups"
install -d -o "$APP_USER" -g "$APP_USER" -m 750 "$LOG"
# pre-create log files owned by the service account (root helpers append to them too)
for f in application.log configuration.log security.log audit.log error.log; do
  [ -e "$LOG/$f" ] || install -o "$APP_USER" -g "$APP_USER" -m 640 /dev/null "$LOG/$f"
  chown "$APP_USER:$APP_USER" "$LOG/$f"
done
chown root:"$APP_USER" "$VAR"; chmod 751 "$VAR"   # traverse-only for others; staging/backups stay closed

step "6. Installing application files"
for d in backend frontend/dist privileged; do
  rm -rf "${APP:?}/$d"; mkdir -p "$(dirname "$APP/$d")"; cp -a "$SRC/$d" "$APP/$d"
done
find "$APP/backend" -name '__pycache__' -prune -exec rm -rf {} + ; rm -rf "$APP/backend/tests"
cp "$SRC/VERSION" "$APP/VERSION" 2>/dev/null || true
chown -R root:root "$APP"; chmod -R u=rwX,go=rX "$APP"
chmod 755 "$APP"/privileged/sbin/*
c_ok "code in $APP (root-owned, read-only for $APP_USER)"

step "7. Python virtual environment"
# the venv must be readable/executable by the service account -> relax umask for this step
( umask 022
  if [ ! -x "$APP/venv/bin/python" ]; then python3 -m venv "$APP/venv"; fi
  "$APP/venv/bin/pip" install -q --upgrade pip
  "$APP/venv/bin/pip" install -q -r "$APP/backend/requirements.txt" )
chown -R root:root "$APP/venv"; chmod -R u=rwX,go=rX "$APP/venv"
runuser -u "$APP_USER" -- "$APP/venv/bin/python" -c 'import fastapi, sqlalchemy, pymysql' || die "service account cannot use $APP/venv"
c_ok "dependencies installed"

step "8. Database"
DBPW_FILE="$ETC/db.password"
MYSQL=(mariadb --protocol=socket)
[ -n "$DB_ADMIN_USER" ] && MYSQL=(mariadb -u "$DB_ADMIN_USER" -p)
"${MYSQL[@]}" -e "SELECT 1" >/dev/null || die "cannot connect to MariaDB as admin (use --db-admin-user)"
if [ ! -s "$DBPW_FILE" ]; then
  umask 077; openssl rand -base64 32 | tr -d '\n=/+' | cut -c1-32 > "$DBPW_FILE"; umask 027
fi
chown root:"$APP_USER" "$DBPW_FILE"; chmod 440 "$DBPW_FILE"
DBPW="$(cat "$DBPW_FILE")"
"${MYSQL[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DBPW';
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$DBPW';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, LOCK TABLES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL
unset DBPW
c_ok "database $DB_NAME and user $DB_USER@localhost (password in $DBPW_FILE)"

step "9. Secrets and configuration files"
if [ ! -s "$ETC/master.key" ]; then
  (umask 077; head -c 32 /dev/urandom | base64 > "$ETC/master.key")
  c_ok "generated encryption master key $ETC/master.key"
  c_warn "BACK UP $ETC/master.key securely - without it stored agent credentials cannot be decrypted"
else
  c_ok "keeping existing master key"
fi
chown root:"$APP_USER" "$ETC/master.key"; chmod 440 "$ETC/master.key"
cat > "$ETC/app.env" <<ENV
# Nagios Management Portal runtime configuration
NMP_DB_HOST=localhost
NMP_DB_NAME=$DB_NAME
NMP_DB_USER=$DB_USER
NMP_DB_PASSWORD_FILE=$DBPW_FILE
NMP_DB_SOCKET=/run/mysqld/mysqld.sock
NMP_MASTER_KEY_FILE=$ETC/master.key
NMP_NAGIOS_BASE=$NAGIOS_BASE
NMP_NAGIOS_CFG=$NAGIOS_CFG
NMP_NAGIOS_STATUS_FILE=${CFG_status_file}
NMP_NAGIOS_LOG_FILE=${CFG_log_file}
NMP_NAGIOS_LOG_ARCHIVE=${CFG_log_archive_path}
NMP_NAGIOS_COMMAND_FILE=${CFG_command_file}
NMP_NAGIOS_OBJECTS_CACHE=${CFG_object_cache_file}
NMP_NAGIOS_SERVICE=$NAGIOS_UNIT
NMP_MANAGED_DIR=$MANAGED
NMP_STAGING_DIR=$VAR/staging
NMP_BACKUP_DIR=$VAR/backups
NMP_PLUGIN_DIR_NCPA=$LIBEXEC
NMP_PLUGIN_DIR_NMP=$LIBEXEC/nmp
NMP_PLUGIN_DIR_STD=$STD_PLUGINS
NMP_PRIV_MODE=sudo
NMP_PRIV_SBIN=$APP/privileged/sbin
NMP_LOG_DIR=$LOG
NMP_FRONTEND_DIST=$APP/frontend/dist
NMP_COOKIE_SECURE=1
NMP_SESSION_IDLE_MINUTES=30
NMP_DISPLAY_TZ=Asia/Kolkata
ENV
chown root:"$APP_USER" "$ETC/app.env"; chmod 640 "$ETC/app.env"
cat > "$ETC/privileged.json" <<JSON
{
  "nagios_bin": "$NAGIOS_BIN",
  "nagios_cfg": "$NAGIOS_CFG",
  "nagios_user": "$NAGIOS_USER",
  "nagios_group": "$NAGIOS_GROUP",
  "managed_dir": "$MANAGED",
  "secrets_dir": "$SECRETS",
  "staging_dir": "$VAR/staging",
  "work_dir": "$VAR/work",
  "backup_dir": "$VAR/backups",
  "backup_keep": 200,
  "reload_method": "systemctl",
  "nagios_service": "$NAGIOS_UNIT",
  "app_user": "$APP_USER",
  "app_group": "$APP_USER",
  "verify_timeout": 60,
  "validate_timeout": 120,
  "log_file": "$LOG/configuration.log"
}
JSON
chown root:root "$ETC/privileged.json"; chmod 644 "$ETC/privileged.json"
c_ok "$ETC/app.env, $ETC/privileged.json"

step "10. Database migrations and reference data"
as_app "$APP/venv/bin/python" -m nmp.cli migrate
as_app "$APP/venv/bin/python" -m nmp.cli bootstrap
c_ok "schema migrated, roles/permissions/catalog/templates seeded, manual groups registered"

step "11. Nagios check wrappers"
install -d -o root -g "$NAGIOS_GROUP" -m 750 "$LIBEXEC/nmp"
for f in check_ncpa_nmp.py check_snmp_nmp.py; do
  sed -e "s#^CHECK_NCPA = .*#CHECK_NCPA = \"$LIBEXEC/check_ncpa.py\"#" \
      -e "s#^STATE_DIR = .*#STATE_DIR = \"$NAGIOS_BASE/var/nmp-snmp-state\"#" \
      "$APP/privileged/plugins/$f" > "$LIBEXEC/nmp/$f"
  chown root:"$NAGIOS_GROUP" "$LIBEXEC/nmp/$f"; chmod 750 "$LIBEXEC/nmp/$f"
done
sed -e "s#^SECRETS_FILE = .*#SECRETS_FILE = \"$SECRETS/nmp-secrets.tsv\"#" "$APP/privileged/plugins/nmp_secrets.py" > "$LIBEXEC/nmp/nmp_secrets.py"
chown root:"$NAGIOS_GROUP" "$LIBEXEC/nmp/nmp_secrets.py"; chmod 640 "$LIBEXEC/nmp/nmp_secrets.py"
c_ok "wrappers installed in $LIBEXEC/nmp"

step "12. Registering the managed directory in nagios.cfg (BACKUP -> VALIDATE -> APPLY -> RELOAD -> VERIFY)"
systemctl daemon-reload
ARGS=(register); [ "$DEDUPE" = 1 ] && ARGS+=(--dedupe)
RES="$("$APP/privileged/sbin/nagios-register-managed" "${ARGS[@]}" || true)"
echo "$RES" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   ", "changed" if d.get("changed") else "no change needed", "- removed:", d.get("removed"), "added:", d.get("added")); [print("    step", s["step"], s["status"], s.get("detail","")[:120]) for s in d.get("steps",[])]; sys.exit(0 if d.get("ok") else 1)' \
  || die "registering the managed directory failed - nagios.cfg was restored. Details: $RES"
chown -R root:"$NAGIOS_GROUP" "$MANAGED"
c_ok "nagios.cfg updated and Nagios reloaded"

step "13. sudoers rule"
TMP_SUDO="$(mktemp)"; cp "$SRC/deploy/sudoers/nagios-management" "$TMP_SUDO"
sed -i "s#/opt/nagios-management#$APP#g; s#^nagmgmt #$APP_USER #" "$TMP_SUDO"
if command -v visudo >/dev/null && visudo -cf "$TMP_SUDO" >/dev/null 2>&1; then c_ok "sudoers syntax valid"; else c_warn "visudo check unavailable/failed - review $TMP_SUDO"; visudo -cf "$TMP_SUDO" || die "sudoers file invalid"; fi
install -o root -g root -m 440 "$TMP_SUDO" /etc/sudoers.d/nagios-management; rm -f "$TMP_SUDO"
runuser -u "$APP_USER" -- sudo -n "$APP/privileged/sbin/nagios-status-check" >/dev/null 2>&1 && c_ok "service account can run the privileged helpers" || die "sudo rule not effective for $APP_USER"
if runuser -u "$APP_USER" -- sudo -n /usr/bin/id >/dev/null 2>&1; then die "SECURITY: $APP_USER can run arbitrary commands via sudo - review /etc/sudoers.d"; fi
c_ok "arbitrary commands are refused"

step "14. systemd services"
sed "s#@PORT@#$PORT#g" "$SRC/deploy/systemd/nagios-management.service" > /etc/systemd/system/nagios-management.service
cp "$SRC/deploy/systemd/nagios-management-worker.service" /etc/systemd/system/
cp "$SRC/deploy/logrotate/nagios-management" /etc/logrotate.d/nagios-management
systemctl daemon-reload
systemctl enable --now nagios-management.service nagios-management-worker.service
sleep 3
systemctl is-active --quiet nagios-management || die "portal service failed to start: journalctl -u nagios-management"
c_ok "services running"

if [ "$SKIP_APACHE" = 0 ]; then
  step "15. Apache HTTPS site"
  if [ -z "$CERT" ]; then
    install -d -o root -g root -m 755 "$ETC/tls"
    CERT="$ETC/tls/portal.crt"; KEY="$ETC/tls/portal.key"
    if [ ! -s "$CERT" ]; then
      openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -keyout "$KEY" -out "$CERT" \
        -subj "/CN=$SERVER_NAME" -addext "subjectAltName=DNS:$SERVER_NAME,DNS:$(hostname -s),IP:$(hostname -I | awk '{print $1}')" >/dev/null 2>&1
      chmod 600 "$KEY"; chmod 644 "$CERT"
      c_warn "self-signed certificate created ($CERT) - replace with a trusted certificate for production"
    fi
  fi
  a2enmod -q ssl proxy proxy_http headers >/dev/null
  sed -e "s#@SERVER_NAME@#$SERVER_NAME#g" -e "s#@CERT@#$CERT#g" -e "s#@KEY@#$KEY#g" -e "s#@PORT@#$PORT#g" \
    "$SRC/deploy/apache/nagios-management.conf" > /etc/apache2/sites-available/nagios-management.conf
  a2ensite -q nagios-management >/dev/null
  if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    systemctl reload apache2 && c_ok "Apache reloaded - https://$SERVER_NAME/"
  else
    apache2ctl configtest || true
    a2dissite -q nagios-management >/dev/null || true
    c_err "Apache configuration test failed - the portal site was disabled again; Apache left unchanged"
  fi
fi

step "16. Initial administrator"
EXISTS="$(as_app "$APP/venv/bin/python" -c 'from nmp.db import SessionLocal
from nmp.models import User
with SessionLocal() as db: print(db.query(User).count())')"
if [ "$EXISTS" = "0" ]; then
  if [ "$YES" = 1 ]; then
    ADMIN_PW="$(openssl rand -base64 18 | tr -d '/+=')Aa1!"
  else
    while :; do
      read -r -s -p "Password for '$ADMIN_USER' (12+ chars, 3 of lower/upper/digit/symbol): " ADMIN_PW; echo
      read -r -s -p "Repeat: " P2; echo
      if [ "$ADMIN_PW" != "$P2" ]; then echo "Passwords differ - try again"; continue; fi
      PERR="$(printf '%s' "$ADMIN_PW" | as_app "$APP/venv/bin/python" -c 'import sys; from nmp.security.passwords import password_policy_errors as p; e=p(sys.stdin.read(), sys.argv[1]); print("\n".join(e))' "$ADMIN_USER")"
      [ -z "$PERR" ] && break
      echo "$PERR"; echo "Please try again."
    done
  fi
  FORCE=(); [ "$YES" = 1 ] && FORCE=(--force-change)
  printf '%s\n' "$ADMIN_PW" | as_app "$APP/venv/bin/python" -m nmp.cli create-admin "$ADMIN_USER" --full-name "Super Admin" "${FORCE[@]}" \
    || die "could not create admin (password policy?) - run: nmp-admin create-admin"
  if [ "$YES" = 1 ]; then
    (umask 077; printf 'user: %s\npassword: %s\n(change at first login, then delete this file)\n' "$ADMIN_USER" "$ADMIN_PW" > /root/nagios-management-initial-admin.txt)
    c_ok "admin '$ADMIN_USER' created - password in /root/nagios-management-initial-admin.txt"
  else
    c_ok "admin '$ADMIN_USER' created"
  fi
  unset ADMIN_PW P2
else
  c_ok "users already exist - skipping"
fi

cat > /usr/local/sbin/nmp-admin <<WRAP
#!/bin/bash
# Nagios Management Portal administration CLI (runs as $APP_USER with $ETC/app.env)
exec runuser -u $APP_USER -- bash -c 'set -a; . $ETC/app.env; set +a; cd $APP/backend; exec $APP/venv/bin/python -m nmp.cli "\$@"' nmp-admin "\$@"
WRAP
chmod 750 /usr/local/sbin/nmp-admin

step "17. Health check"
sleep 2
curl -fsS "http://127.0.0.1:$PORT/api/healthz" >/dev/null && c_ok "API healthy" || c_warn "API health check failed"
[ "$SKIP_APACHE" = 0 ] && { curl -kfsS "https://127.0.0.1/api/healthz" -H "Host: $SERVER_NAME" >/dev/null && c_ok "HTTPS proxy healthy" || c_warn "HTTPS health check failed"; }
systemctl is-active --quiet "$NAGIOS_UNIT" && c_ok "Nagios still running" || c_err "Nagios is not running!"
runuser -u "$NAGIOS_USER" -- "$NAGIOS_BIN" -v "$NAGIOS_CFG" >/dev/null && c_ok "live Nagios configuration valid" || c_err "live configuration invalid"
systemctl is-active --quiet nagios-management-worker && c_ok "worker running" || c_warn "worker not running"

echo
echo "================================================================================"
echo " Nagios Management Portal installed."
echo "   URL:        https://$SERVER_NAME/"
echo "   Admin:      $ADMIN_USER"
echo "   Nagios UI:  https://$SERVER_NAME/nagios (unchanged)"
echo "   Next:       Administration > Import Configuration to take over existing hosts."
echo "   Backups:    $VAR/backups   (pre-install backup: $PRE)"
echo "   Logs:       $LOG"
echo "   IMPORTANT:  back up $ETC/master.key and $ETC/db.password"
echo "================================================================================"
