#!/usr/bin/env bash
# =============================================================================
#  nagios-discovery.sh  -  READ-ONLY environment inspection for the
#                          Nagios Management Portal project
# -----------------------------------------------------------------------------
#  What it does : Collects facts about Nagios Core, its configuration objects,
#                 NCPA integration, MariaDB, Apache/PHP, Python/Node, sudo,
#                 security posture and potential conflicts.
#  What it does NOT do : It never writes, edits, reloads or restarts anything
#                 outside its own output folder. The only Nagios command it
#                 runs is the built-in pre-flight check (nagios -v), which is
#                 read-only.
#  Secrets      : NCPA tokens, SNMP communities/passwords, $USERn$ values and
#                 custom-variable secrets are masked in every file it writes.
#                 Still, REVIEW the bundle before sharing it.
#
#  Usage        : sudo bash nagios-discovery.sh [--redact-ips] [--no-configs]
#                                               [--outdir DIR]
#     --redact-ips  replace IPv4 addresses with stable pseudonyms (ip-3fa21c)
#     --no-configs  do not copy (masked) Nagios object files into the bundle
#     --outdir DIR  where to write the bundle (default: /tmp)
# =============================================================================
set -u
umask 077
export LC_ALL=C

VERSION="1.0.0"
NAGIOS_BASE="${NAGIOS_BASE:-/usr/local/nagios}"
REDACT_IPS=0
COPY_CONFIGS=1
OUTBASE="/tmp"

while [ $# -gt 0 ]; do
  case "$1" in
    --redact-ips) REDACT_IPS=1 ;;
    --no-configs) COPY_CONFIGS=0 ;;
    --outdir) shift; OUTBASE="${1:?--outdir needs a value}" ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root - some files may be unreadable. Re-run with sudo for a complete report." >&2
fi

TS="$(date +%Y%m%d-%H%M%S)"
HOST_SHORT="$(hostname -s 2>/dev/null || echo host)"
OUT="${OUTBASE%/}/nagios-discovery-${HOST_SHORT}-${TS}"
mkdir -p "$OUT/config" || { echo "Cannot create $OUT" >&2; exit 1; }
REPORT="$OUT/report.txt"
SUMMARY="$OUT/summary.env"
OBJECTS="$OUT/objects.tsv"
FINDINGS="$OUT/findings.txt"
: > "$REPORT"; : > "$SUMMARY"; : > "$FINDINGS"

# ----------------------------------------------------------------- helpers ---
have() { command -v "$1" >/dev/null 2>&1; }
T() { timeout 20 "$@" 2>&1; }                # run with timeout, merge stderr
section() { printf '\n==================== %s ====================\n' "$1" >> "$REPORT"; echo ">> $1"; }
kv() { printf '%s=%q\n' "$1" "$2" >> "$SUMMARY"; printf '  %-34s %s\n' "$1" "$2" >> "$REPORT"; }
note() { echo "$*" >> "$REPORT"; }
finding() { # level message
  printf '[%s] %s\n' "$1" "$2" >> "$FINDINGS"
}

# Secret-masking filter (stdin -> stdout). Also optional IP pseudonymisation.
mask() {
  REDACT_IPS="$REDACT_IPS" perl -MDigest::MD5=md5_hex -pe '
    # value-taking flags whose values are secrets (skip numbers and $MACROS$)
    s{((?:^|[\s!])(?:-t|--token|-C|--community|-A|--authpassword|-X|--privpasswd|--password|--passwd|--pass|--secret|--apikey|--api-key|-p|-P|-U|--authpass|--privpass)\s+)(?![0-9]+(?:[\s!]|$))(?![\x27"]?\$)(\x27[^\x27]*\x27|"[^"]*"|[^\s!]+)}{$1***MASKED***}g;
    s{(--(?:token|password|passwd|community|secret|apikey|api-key|authpass|privpass)=)(?!\$)[^\s!]+}{$1***MASKED***}gi;
    s{((?:token|password|passwd|community|secret|apikey)=)(?!\$)[^&\s!\x27"]+}{$1***MASKED***}gi;
    # custom object variables that look secret, e.g. _NCPA_TOKEN, _SNMP_COMMUNITY
    s{^(\s*_\w*(?:TOKEN|PASS|PASSWORD|PASSWD|SECRET|COMMUNITY|KEY|AUTH|PRIV)\w*\s+)\S.*$}{$1***MASKED***}i;
    # resource.cfg: $USERn$=value  (keep plain filesystem paths)
    s{^(\s*\$USER\d+\$\s*=\s*)(?!/)(\S.*)$}{$1***MASKED***};
    if ($ENV{REDACT_IPS}) {
      s{\b((?:\d{1,3}\.){3}\d{1,3})\b}{ ($1 eq "127.0.0.1" || $1 eq "0.0.0.0" || $1 =~ /^255\./) ? $1 : "ip-".substr(md5_hex($1),0,6) }ge;
    }
  '
}

# strip comments/blank lines from a Nagios-style key=value cfg
nocomment() { grep -Ev '^[[:space:]]*([#;]|$)' "$1" 2>/dev/null; }
cfgval() { nocomment "$2" | awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,""); print}'; }

echo "Nagios discovery v$VERSION - writing to $OUT"
{
  echo "Nagios Management Portal - Environment Discovery Report"
  echo "Script version : $VERSION"
  echo "Generated      : $(date -Is)"
  echo "Run as         : $(id -un) (uid $(id -u))"
  echo "Options        : redact_ips=$REDACT_IPS copy_configs=$COPY_CONFIGS"
} >> "$REPORT"

# ================================================================ 1. SYSTEM ==
section "1. SYSTEM"
. /etc/os-release 2>/dev/null
kv os_pretty "${PRETTY_NAME:-unknown}"
kv os_version_id "${VERSION_ID:-unknown}"
kv kernel "$(uname -r)"
kv arch "$(uname -m)"
kv hostname_fqdn "$(hostname -f 2>/dev/null || hostname)"
kv timezone "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"
kv ntp_synced "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
kv cpu_count "$(nproc 2>/dev/null)"
kv mem_total_mb "$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo)"
kv uptime "$(uptime -p 2>/dev/null)"
note ""; note "--- Disk space ---"
df -hP / /usr/local /var /tmp 2>/dev/null | awk '!seen[$0]++' >> "$REPORT"
ROOT_FREE_MB="$(df -Pm / | awk 'NR==2{print $4}')"
kv root_free_mb "$ROOT_FREE_MB"
[ "${ROOT_FREE_MB:-0}" -lt 2048 ] && finding WARN "Less than 2 GB free on / - backups and build need space."
note ""; note "--- Security modules / firewall ---"
kv apparmor "$(T aa-status --enabled >/dev/null 2>&1 && echo enabled || echo disabled/absent)"
kv selinux "$(have getenforce && getenforce || echo absent)"
kv ufw "$(have ufw && T ufw status | head -1 || echo absent)"
note ""; note "--- Listening TCP ports ---"
T ss -tlnp | mask >> "$REPORT"

# ================================================================ 2. NAGIOS ==
section "2. NAGIOS CORE"
NAGIOS_BIN="$NAGIOS_BASE/bin/nagios"
NAGIOS_CFG="$NAGIOS_BASE/etc/nagios.cfg"
kv nagios_base "$NAGIOS_BASE"
kv nagios_bin_exists "$([ -x "$NAGIOS_BIN" ] && echo yes || echo NO)"
kv nagios_cfg_exists "$([ -r "$NAGIOS_CFG" ] && echo yes || echo NO)"
if [ -x "$NAGIOS_BIN" ]; then
  kv nagios_version "$("$NAGIOS_BIN" --version 2>/dev/null | grep -Eo 'Nagios Core [0-9.]+' | head -1)"
fi
[ -r "$NAGIOS_CFG" ] || finding BLOCKER "nagios.cfg not found/readable at $NAGIOS_CFG"

# service manager
note ""; note "--- Service unit ---"
NAGIOS_UNIT=""
for u in nagios nagios4 nagios-core; do
  if systemctl list-unit-files "$u.service" 2>/dev/null | grep -q "^$u.service"; then NAGIOS_UNIT="$u"; break; fi
done
kv nagios_systemd_unit "${NAGIOS_UNIT:-none}"
if [ -n "$NAGIOS_UNIT" ]; then
  kv nagios_active "$(systemctl is-active "$NAGIOS_UNIT" 2>/dev/null)"
  kv nagios_enabled "$(systemctl is-enabled "$NAGIOS_UNIT" 2>/dev/null)"
  EXEC_RELOAD="$(systemctl show -p ExecReload --value "$NAGIOS_UNIT" 2>/dev/null | grep -o 'argv\[\]=[^;]*' | head -1)"
  kv nagios_execreload "${EXEC_RELOAD:-NONE}"
  [ -z "$EXEC_RELOAD" ] && finding WARN "Nagios unit has no ExecReload - portal will use 'kill -HUP <pid>' via a controlled script instead of systemctl reload."
  note ""; T systemctl cat "$NAGIOS_UNIT" >> "$REPORT"
else
  [ -x /etc/init.d/nagios ] && kv nagios_initd "/etc/init.d/nagios" || finding WARN "No systemd unit or init script found for Nagios."
fi
NPID="$(pgrep -xo nagios 2>/dev/null)"
kv nagios_pid "${NPID:-not running}"
[ -n "$NPID" ] && kv nagios_process_user "$(ps -o user= -p "$NPID")"

# nagios.cfg directives
if [ -r "$NAGIOS_CFG" ]; then
  note ""; note "--- nagios.cfg: important directives ---"
  for k in log_file object_cache_file precached_object_file resource_file status_file status_update_interval \
           nagios_user nagios_group check_external_commands command_file query_socket lock_file temp_file temp_path \
           check_result_path retain_state_information state_retention_file log_archive_path log_rotation_method \
           process_performance_data host_perfdata_command service_perfdata_command host_perfdata_file service_perfdata_file \
           enable_notifications execute_service_checks date_format illegal_object_name_chars illegal_macro_output_chars \
           use_regexp_matching use_true_regexp_matching allow_empty_hostgroup_assignment; do
    v="$(cfgval "$k" "$NAGIOS_CFG" | head -1)"
    kv "cfg_$k" "${v:-<unset>}"
  done
  BROKERS="$(cfgval broker_module "$NAGIOS_CFG")"
  kv cfg_broker_modules "${BROKERS:-none}"
  echo "$BROKERS" | grep -qi livestatus && finding INFO "Livestatus broker detected - portal can use it for live status."
  echo "$BROKERS" | grep -qi ndo && finding INFO "NDOUtils broker detected."

  note ""; note "--- cfg_file / cfg_dir entries ---"
  CFG_FILES="$(cfgval cfg_file "$NAGIOS_CFG")"
  CFG_DIRS="$(cfgval cfg_dir "$NAGIOS_CFG")"
  echo "$CFG_FILES" | sed 's/^/  cfg_file=/' >> "$REPORT"
  echo "$CFG_DIRS"  | sed 's/^/  cfg_dir=/'  >> "$REPORT"
  kv cfg_file_count "$(printf '%s\n' "$CFG_FILES" | grep -c .)"
  kv cfg_dir_count "$(printf '%s\n' "$CFG_DIRS" | grep -c .)"

  # conflict: a cfg_dir that is a parent of the planned managed/staging dirs
  PLANNED_MANAGED="$NAGIOS_BASE/etc/managed"
  for d in $CFG_DIRS; do
    case "$PLANNED_MANAGED/" in
      "${d%/}/"*) finding CONFLICT "cfg_dir=$d already includes $PLANNED_MANAGED - staging files must live OUTSIDE it (portal will stage under /var/lib/nagios-management/staging)." ;;
    esac
  done
  [ -e "$PLANNED_MANAGED" ] && finding CONFLICT "$PLANNED_MANAGED already exists - inspect before install." || kv planned_managed_dir_free yes

  if [ "$(cfgval check_external_commands "$NAGIOS_CFG")" = "0" ]; then
    finding WARN "check_external_commands=0 - acknowledge/downtime/disable from the portal will not work until enabled."
  fi

  note ""; note "--- nagios.cfg (non-comment lines) ---"
  nocomment "$NAGIOS_CFG" | mask >> "$REPORT"
fi

# resource.cfg (masked)
RES_CFG="$(cfgval resource_file "$NAGIOS_CFG" 2>/dev/null | head -1)"
RES_CFG="${RES_CFG:-$NAGIOS_BASE/etc/resource.cfg}"
if [ -r "$RES_CFG" ]; then
  note ""; note "--- $RES_CFG (masked) ---"
  nocomment "$RES_CFG" | mask >> "$REPORT"
  kv resource_user_macros_used "$(nocomment "$RES_CFG" | grep -Eo '^\$USER[0-9]+\$' | tr '\n' ' ')"
fi

# Pre-flight verification (read-only)
note ""; note "--- Pre-flight verification: nagios -v ---"
if [ -x "$NAGIOS_BIN" ] && [ -r "$NAGIOS_CFG" ]; then
  VOUT="$(timeout 120 "$NAGIOS_BIN" -v "$NAGIOS_CFG" 2>&1)"; VRC=$?
  echo "$VOUT" | mask >> "$REPORT"
  kv nagios_verify_rc "$VRC"
  kv nagios_verify_warnings "$(echo "$VOUT" | grep -Eo 'Total Warnings: *[0-9]+' | grep -Eo '[0-9]+$')"
  kv nagios_verify_errors "$(echo "$VOUT" | grep -Eo 'Total Errors: *[0-9]+' | grep -Eo '[0-9]+$')"
  [ "$VRC" -ne 0 ] && finding BLOCKER "Current configuration does NOT validate (rc=$VRC). Fix before installing the portal."
  # object counts as reported by Nagios itself
  echo "$VOUT" | sed -nE 's/^[[:space:]]*Checked ([0-9]+) (.*)\.$/\2 \1/p' | while read -r line; do
    n="${line##* }"; what="${line% *}"; kv "nagios_checked_$(echo "$what" | tr ' ' '_')" "$n"; done
fi

# CGIs / JSON API
note ""; note "--- CGI / JSON API ---"
for c in statusjson.cgi objectjson.cgi archivejson.cgi cmd.cgi; do
  kv "cgi_$c" "$([ -x "$NAGIOS_BASE/sbin/$c" ] && echo present || echo absent)"
done
CGI_CFG="$NAGIOS_BASE/etc/cgi.cfg"
[ -r "$CGI_CFG" ] && { note ""; note "--- cgi.cfg (non-comment) ---"; nocomment "$CGI_CFG" | mask >> "$REPORT"; }

# status / command file access
STATUS_FILE="$(cfgval status_file "$NAGIOS_CFG" 2>/dev/null | head -1)"
CMD_FILE="$(cfgval command_file "$NAGIOS_CFG" 2>/dev/null | head -1)"
QH_SOCK="$(cfgval query_socket "$NAGIOS_CFG" 2>/dev/null | head -1)"
for f in "$STATUS_FILE" "$CMD_FILE" "$QH_SOCK" "${QH_SOCK:-$NAGIOS_BASE/var/rw/nagios.qh}"; do
  [ -n "$f" ] && [ -e "$f" ] && note "  $(ls -ld "$f")"
done
[ -n "$STATUS_FILE" ] && [ -r "$STATUS_FILE" ] && kv status_file_age_sec "$(( $(date +%s) - $(stat -c %Y "$STATUS_FILE") ))"

# users / groups
note ""; note "--- Users and groups ---"
for u in nagios www-data apache; do id "$u" >/dev/null 2>&1 && note "  $(id "$u")"; done
for g in nagios nagcmd; do getent group "$g" >/dev/null && note "  group $(getent group "$g")"; done

# log archive (needed for availability / event history reports)
LOG_ARCH="$(cfgval log_archive_path "$NAGIOS_CFG" 2>/dev/null | head -1)"
if [ -n "$LOG_ARCH" ] && [ -d "$LOG_ARCH" ]; then
  kv log_archive_files "$(find "$LOG_ARCH" -maxdepth 1 -type f | wc -l)"
  kv log_archive_oldest "$(ls -1tr "$LOG_ARCH" 2>/dev/null | head -1)"
  kv log_archive_size "$(du -sh "$LOG_ARCH" 2>/dev/null | cut -f1)"
fi

# performance graphing add-ons
note ""; note "--- Performance data add-ons ---"
for p in /usr/local/pnp4nagios /usr/share/pnp4nagios /opt/graphios /etc/nagflux /usr/local/nagflux; do
  [ -e "$p" ] && finding INFO "Perfdata add-on found: $p"
done
kv influxdb "$(have influx && echo present || echo absent)"

# ======================================================== 3. OBJECT INVENTORY ==
section "3. OBJECT INVENTORY (parsed from all cfg_file / cfg_dir entries)"
ALL_CFG_LIST="$OUT/cfg_files.list"
: > "$ALL_CFG_LIST"
if [ -r "$NAGIOS_CFG" ]; then
  for f in $CFG_FILES; do [ -f "$f" ] && echo "$f" >> "$ALL_CFG_LIST"; done
  for d in $CFG_DIRS; do [ -d "$d" ] && find -L "$d" -type f -name '*.cfg' 2>/dev/null | sort >> "$ALL_CFG_LIST"; done
  sort -u -o "$ALL_CFG_LIST" "$ALL_CFG_LIST"
fi
kv object_file_count "$(grep -c . "$ALL_CFG_LIST")"
note ""; note "--- Object files (perm owner size mtime sha256) ---"
while read -r f; do
  printf '  %s %s %8s %s %s %s\n' "$(stat -c '%A %U:%G' "$f")" "" "$(stat -c %s "$f")" \
    "$(date -d "@$(stat -c %Y "$f")" '+%F %T')" "$(sha256sum "$f" | cut -c1-16)" "$f" >> "$REPORT"
done < "$ALL_CFG_LIST"

# Parse every define block -> TSV
printf 'file\tline\ttype\tname\tprimary_key\tservice_description\tuse\tregister\taddress\tcheck_command\thostgroups\n' > "$OBJECTS"
if [ -s "$ALL_CFG_LIST" ]; then
  xargs -d '\n' perl -e '
    my ($t,%h,$start);
    while (<>) {
    chomp; s/\r$//; s/^\s+//;
    next if /^[#;]/ || $_ eq "";
    s/(?<!\\);.*$//; s/\s+$//;
    if (/^define\s+(\w+)\s*\{?\s*(.*)$/) { $t=$1; %h=(); $start=$.; next }
    if ($t && /^\}/) {
      my $pk = $h{host_name} // $h{hostgroup_name} // $h{command_name} // $h{contact_name} // $h{contactgroup_name}
            // $h{timeperiod_name} // $h{servicegroup_name} // "-";
      print join("\t", $ARGV, $start, $t, $h{name}//"-", $pk, $h{service_description}//"-", $h{use}//"-",
                 $h{register}//"1", $h{address}//"-", $h{check_command} // $h{command_line} // "-", $h{hostgroups}//"-"), "\n";
      $t=""; next;
    }
    $h{$1}=$2 if $t && /^(\S+)\s+(.*)$/;
    } continue { close ARGV if eof }' < "$ALL_CFG_LIST" | mask >> "$OBJECTS"
fi

note ""; note "--- Object counts by type (register 1 = real object, 0 = template) ---"
awk -F'\t' 'NR>1{k=$3 (($8=="0")?" (template)":""); c[k]++} END{for(k in c) printf "  %-28s %d\n",k,c[k]}' "$OBJECTS" | sort >> "$REPORT"

note ""; note "--- Templates (register 0) ---"
awk -F'\t' 'NR>1 && $8=="0"{printf "  %-12s %-32s use=%s  (%s:%s)\n",$3,$4,$7,$1,$2}' "$OBJECTS" >> "$REPORT"

note ""; note "--- Hosts ---"
awk -F'\t' 'NR>1 && $3=="host" && $8!="0"{printf "  %-30s addr=%-18s use=%-24s hostgroups=%s  (%s)\n",$5,$9,$7,$11,$1}' "$OBJECTS" >> "$REPORT"
HOSTS_N="$(awk -F'\t' 'NR>1 && $3=="host" && $8!="0"' "$OBJECTS" | wc -l)"
SVCS_N="$(awk -F'\t' 'NR>1 && $3=="service" && $8!="0"' "$OBJECTS" | wc -l)"
kv parsed_hosts "$HOSTS_N"; kv parsed_services "$SVCS_N"

note ""; note "--- Hostgroups ---"
awk -F'\t' 'NR>1 && $3=="hostgroup"{printf "  %s  (%s)\n",$5,$1}' "$OBJECTS" >> "$REPORT"

note ""; note "--- Commands (masked) ---"
awk -F'\t' 'NR>1 && $3=="command"{printf "  %-32s %s\n",$5,$10}' "$OBJECTS" >> "$REPORT"

note ""; note "--- Contacts / contact groups / timeperiods ---"
awk -F'\t' 'NR>1 && ($3=="contact"||$3=="contactgroup"||$3=="timeperiod") && $8!="0"{printf "  %-14s %s\n",$3,$5}' "$OBJECTS" >> "$REPORT"

note ""; note "--- Service check_command usage (top 40) ---"
awk -F'\t' 'NR>1 && $3=="service" && $8!="0"{split($10,a,"!"); c[a[1]]++} END{for(k in c) printf "%6d  %s\n",c[k],k}' "$OBJECTS" | sort -rn | head -40 >> "$REPORT"

# Duplicate object names (potential import conflicts)
DUPS="$(awk -F'\t' 'NR>1 && $8!="0" && $5!="-" {k=$3"|"$5"|"$6; c[k]++} END{for(k in c) if(c[k]>1) print c[k]"x "k}' "$OBJECTS")"
if [ -n "$DUPS" ]; then note ""; note "--- Duplicate object keys ---"; echo "$DUPS" >> "$REPORT"; finding WARN "Duplicate object definitions found (see report section 3)."; fi

# ============================================================ 4. NCPA =======
section "4. NCPA INTEGRATION"
LIBEXEC="$NAGIOS_BASE/libexec"
NCPA_PLUGIN="$LIBEXEC/check_ncpa.py"
kv check_ncpa_present "$([ -f "$NCPA_PLUGIN" ] && echo yes || echo NO)"
if [ -f "$NCPA_PLUGIN" ]; then
  note "  $(ls -l "$NCPA_PLUGIN")"
  kv check_ncpa_shebang "$(head -1 "$NCPA_PLUGIN")"
  kv check_ncpa_version "$(T "$NCPA_PLUGIN" --version | head -1)"
  kv check_ncpa_help_ok "$(T "$NCPA_PLUGIN" --help >/dev/null && echo yes || echo NO)"
  note ""; note "--- check_ncpa.py --help ---"; T "$NCPA_PLUGIN" --help | head -60 >> "$REPORT"
else
  finding BLOCKER "check_ncpa.py not found at $NCPA_PLUGIN"
fi
note ""; note "--- Commands that call check_ncpa ---"
awk -F'\t' 'NR>1 && $3=="command" && $10 ~ /check_ncpa/ {printf "  %-28s %s\n",$5,$10}' "$OBJECTS" >> "$REPORT"
note ""; note "--- NCPA services by check_command (masked) ---"
awk -F'\t' 'NR>1 && $3=="service" && $10 ~ /ncpa/ {printf "  %-24s %-28s %s\n",$5,$6,$10}' "$OBJECTS" | head -80 >> "$REPORT"
NCPA_HOSTS="$(awk -F'\t' 'NR>1 && $3=="service" && $10 ~ /ncpa/ && $5!="-"{print $5}' "$OBJECTS" | tr ',' '\n' | sed 's/^ *//' | sort -u)"
kv ncpa_host_count "$(printf '%s' "$NCPA_HOSTS" | grep -c .)"
# token storage style
if grep -Eqs '_NCPA_?TOKEN|_TOKEN' $(cat "$ALL_CFG_LIST") 2>/dev/null; then kv ncpa_token_style "host custom variable"
elif grep -Eqs 'check_ncpa.*-t *\$USER' $(cat "$ALL_CFG_LIST") 2>/dev/null; then kv ncpa_token_style "resource.cfg \$USERn\$"
elif grep -Eqs 'check_ncpa.*-t' $(cat "$ALL_CFG_LIST") 2>/dev/null; then kv ncpa_token_style "inline in command/service"; finding WARN "NCPA token appears inline in object files - the portal will move it to encrypted storage."
else kv ncpa_token_style "unknown"; fi

# TCP reachability of NCPA port 5693 on up to 10 NCPA hosts (no auth, no token)
note ""; note "--- TCP 5693 reachability (first 10 NCPA hosts, 3s timeout) ---"
n=0
for h in $NCPA_HOSTS; do
  [ $n -ge 10 ] && break; n=$((n+1))
  addr="$(awk -F'\t' -v h="$h" 'NR>1 && $3=="host" && $5==h{print $9; exit}' "$OBJECTS")"
  [ -z "$addr" ] || [ "$addr" = "-" ] && continue
  case "$addr" in ip-*|*MASK*) note "  $h: address redacted, skipped"; continue ;; esac
  if timeout 3 bash -c "exec 3<>/dev/tcp/$addr/5693" 2>/dev/null; then r=open; else r="closed/filtered"; fi
  note "  $h ($addr): $r"
done

note ""; note "--- Other plugins in libexec ---"
ls -1 "$LIBEXEC" 2>/dev/null | tr '\n' ' ' | fold -w 110 >> "$REPORT"; echo >> "$REPORT"
for p in check_nrpe check_snmp check_ping check_icmp check_ifstatus check_ifoperstatus check_snmp_int.pl check_by_ssh; do
  kv "plugin_$p" "$([ -x "$LIBEXEC/$p" ] && echo yes || echo no)"
done

# ============================================================ 5. MARIADB ====
section "5. MARIADB"
MYSQL_CLI="$(command -v mariadb || command -v mysql || true)"
kv mariadb_client "${MYSQL_CLI:-absent}"
kv mariadb_client_version "$([ -n "$MYSQL_CLI" ] && "$MYSQL_CLI" --version 2>/dev/null)"
for u in mariadb mysql; do systemctl list-unit-files "$u.service" 2>/dev/null | grep -q "^$u.service" && { kv mariadb_unit "$u"; kv mariadb_active "$(systemctl is-active $u)"; break; }; done
if [ -n "$MYSQL_CLI" ] && [ "$(id -u)" -eq 0 ]; then
  Q() { timeout 10 "$MYSQL_CLI" --protocol=socket -N -B -e "$1" 2>/dev/null; }
  if Q "SELECT 1" >/dev/null; then
    kv mariadb_root_socket_auth yes
    kv mariadb_server_version "$(Q 'SELECT VERSION()')"
    note ""; note "--- Server variables ---"
    Q "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('bind_address','port','socket','character_set_server','collation_server','default_storage_engine','innodb_file_per_table','sql_mode','max_connections','lower_case_table_names','have_ssl','require_secure_transport','time_zone','system_time_zone','event_scheduler','log_bin')" | sed 's/^/  /' >> "$REPORT"
    note ""; note "--- Databases ---"
    Q "SHOW DATABASES" | sed 's/^/  /' >> "$REPORT"
    Q "SHOW DATABASES" | grep -qx 'nagios_mgmt' && finding CONFLICT "Database 'nagios_mgmt' already exists."
    Q "SELECT COUNT(*) FROM mysql.user WHERE User='nagios_mgmt'" | grep -qx '[1-9][0-9]*' && finding CONFLICT "MariaDB user 'nagios_mgmt' already exists."
    note ""; note "--- Accounts (user@host only) ---"
    Q "SELECT CONCAT(User,'@',Host) FROM mysql.user" | sed 's/^/  /' >> "$REPORT"
  else
    kv mariadb_root_socket_auth "no (installer will prompt for admin credentials)"
  fi
fi

# ============================================================ 6. WEB STACK ==
section "6. APACHE / PHP / TLS"
kv apache_version "$(apache2 -v 2>/dev/null | head -1)"
kv apache_active "$(systemctl is-active apache2 2>/dev/null)"
kv apache_mpm "$(apache2ctl -V 2>/dev/null | awk -F': ' '/Server MPM/{print $2}')"
MODS="$(apache2ctl -M 2>/dev/null | awk 'NR>1{print $1}' | tr '\n' ' ')"
kv apache_modules "$MODS"
for m in ssl_module proxy_module proxy_http_module headers_module rewrite_module cgi_module cgid_module; do
  echo "$MODS" | grep -qw "$m" || note "  (module not loaded: $m)"
done
note ""; note "--- Enabled sites / conf ---"
ls -l /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null >> "$REPORT"
note ""; note "--- Apache vhosts ---"
T apache2ctl -S >> "$REPORT"
for f in /etc/apache2/sites-enabled/*.conf /etc/apache2/conf-enabled/nagios*.conf /etc/apache2/sites-available/nagios*.conf; do
  [ -r "$f" ] || continue
  note ""; note "--- $f (non-comment, masked) ---"
  nocomment "$f" | mask >> "$REPORT"
done
note ""; note "--- TLS certificates referenced by Apache ---"
grep -rhoE 'SSLCertificate(Key)?File\s+\S+' /etc/apache2/sites-enabled 2>/dev/null | sort -u | while read -r _ path; do
  if [ -r "$path" ] && grep -q CERTIFICATE "$path" 2>/dev/null; then
    note "  $path : $(openssl x509 -in "$path" -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
  else note "  $path"; fi
done
kv php_version "$(php -v 2>/dev/null | head -1)"
kv openssl_version "$(openssl version 2>/dev/null)"
for p in 80 443 8000 8080 8443 9000; do ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$p$" && note "  port $p in use"; done

# ================================================================ 7. RUNTIMES ==
section "7. PYTHON / NODE / BUILD TOOLS"
kv python3_version "$(python3 --version 2>&1)"
kv python3_path "$(command -v python3)"
kv python3_venv "$(python3 -c 'import venv, ensurepip' >/dev/null 2>&1 && echo ok || echo 'MISSING (apt install python3-venv)')"
kv python3_ssl "$(python3 -c 'import ssl;print(ssl.OPENSSL_VERSION)' 2>&1)"
kv pip "$(python3 -m pip --version 2>&1 | head -1)"
kv node_version "$(node --version 2>/dev/null || echo absent)"
kv npm_version "$(npm --version 2>/dev/null || echo absent)"
kv gcc "$(have gcc && gcc -dumpfullversion || echo absent)"
note ""; note "--- Relevant packages (dpkg) ---"
dpkg-query -W -f='  ${db:Status-Abbrev} ${Package} ${Version}\n' \
  python3 python3-venv python3-dev python3-pip build-essential pkg-config libmariadb-dev libmariadb-dev-compat \
  mariadb-server mariadb-client apache2 libapache2-mod-php php php-mysql openssl sudo nodejs npm \
  snmp libsnmp-dev nagios-plugins monitoring-plugins fping curl jq 2>/dev/null >> "$REPORT"

# ================================================================ 8. SUDO ==
section "8. SUDO / PRIVILEGE MODEL"
kv sudo_version "$(sudo -V 2>/dev/null | head -1)"
note "--- /etc/sudoers.d ---"; ls -l /etc/sudoers.d 2>/dev/null >> "$REPORT"
grep -rlsE 'nagios|www-data|nagmgmt' /etc/sudoers /etc/sudoers.d 2>/dev/null | while read -r f; do
  note ""; note "--- $f (entries mentioning nagios/www-data) ---"
  grep -E 'nagios|www-data|nagmgmt' "$f" | grep -v '^#' >> "$REPORT"
done
id nagmgmt >/dev/null 2>&1 && finding CONFLICT "System user 'nagmgmt' already exists."
for d in /opt/nagios-management /etc/nagios-management /var/lib/nagios-management /var/log/nagios-management /config-backups; do
  [ -e "$d" ] && finding CONFLICT "$d already exists." || note "  free: $d"
done

# ================================================================ 9. NETWORK ==
section "9. OUTBOUND CONNECTIVITY (for package install)"
for url in https://pypi.org/simple/pip/ https://registry.npmjs.org/ https://archive.ubuntu.com/ubuntu/; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 6 "$url" 2>/dev/null)"
  kv "egress_$(echo "$url" | awk -F/ '{print $3}')" "${code:-fail}"
done

# ================================================================ 10. COPIES ==
if [ "$COPY_CONFIGS" -eq 1 ]; then
  section "10. MASKED CONFIG COPIES"
  { echo "$NAGIOS_CFG"; echo "$CGI_CFG"; echo "$RES_CFG"; cat "$ALL_CFG_LIST"; } | sort -u | while read -r f; do
    [ -r "$f" ] || continue
    dest="$OUT/config$f"; mkdir -p "$(dirname "$dest")"
    mask < "$f" > "$dest"
  done
  note "  Copied $(find "$OUT/config" -type f | wc -l) masked files into config/"
fi

# ================================================================ FINDINGS ==
section "FINDINGS"
if [ -s "$FINDINGS" ]; then sort -u "$FINDINGS" | sort -t']' -k1,1 >> "$REPORT"; else note "  No conflicts or blockers detected."; fi
kv findings_blockers "$(grep -c '^\[BLOCKER\]' "$FINDINGS")"
kv findings_conflicts "$(grep -c '^\[CONFLICT\]' "$FINDINGS")"
kv findings_warnings "$(grep -c '^\[WARN\]' "$FINDINGS")"

# final leak check: warn if something token-like survived masking
if grep -rEnis '(-t|--token)\s+[A-Za-z0-9_\-]{12,}' "$OUT" --exclude=report.txt >/dev/null 2>&1; then
  echo "NOTE: possible unmasked token-like strings remain - review before sharing:" >&2
  grep -rEnis '(-t|--token)\s+[A-Za-z0-9_\-]{12,}' "$OUT" | cut -c1-160 >&2
fi

BUNDLE="$OUT.tar.gz"
tar -C "$(dirname "$OUT")" -czf "$BUNDLE" "$(basename "$OUT")"
chmod 600 "$BUNDLE"
echo
echo "Done. Nothing on this server was modified."
echo "  Report : $REPORT"
echo "  Bundle : $BUNDLE"
echo
echo "Findings:"; [ -s "$FINDINGS" ] && sort -u "$FINDINGS" || echo "  none"
echo
echo "Review the bundle (masked secrets, IPs) and upload $BUNDLE to the chat."
