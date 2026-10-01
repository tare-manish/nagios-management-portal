"""Built-in commands, service definitions and monitoring templates (seed data).

arg_template mini-language (rendered by generator.render_args):
  {name}        -> parameter / threshold value (validated, see validators.PARAM_PATTERNS)
  [[ ... ]]     -> optional segment, dropped unless every {token} inside is non-empty
Tokens always available: {warning} {critical}. For mount params, {<name>_ncpa}
is the NCPA path form ('/' -> '|').
"""
from __future__ import annotations

THRESH = "[[ -w {warning}]][[ -c {critical}]]"

SYSTEM_COMMANDS = [
    {
        "name": "nmp_check_ncpa",
        "command_line": "{NMP}/check_ncpa_nmp.py --nmp-key $_HOSTNMP_KEY$ --nmp-ssl=$_HOSTNCPA_SSL$ "
                        "-H $HOSTADDRESS$ -P $_HOSTNCPA_PORT$ -T $_HOSTNCPA_TIMEOUT$ $ARG1$",
        "description": "NCPA agent check (token read from secured store, never on the command line)",
    },
    {
        "name": "nmp_check_snmp",
        "command_line": "{NMP}/check_snmp_nmp.py --nmp-key $_HOSTNMP_KEY$ -H $HOSTADDRESS$ $ARG1$",
        "description": "SNMP v2c/v3 check (credentials read from secured store)",
    },
    {
        "name": "nmp_check_host_alive",
        "command_line": "{STD}/check_ping -H $HOSTADDRESS$ -w 3000.0,80% -c 5000.0,100% -p 5",
        "description": "Host alive via ICMP",
    },
    {
        "name": "nmp_check_ping",
        "command_line": "{STD}/check_ping -H $HOSTADDRESS$ -w $ARG1$ -c $ARG2$ -p 5",
        "description": "Ping round-trip time and packet loss",
    },
    {
        "name": "nmp_check_tcp",
        "command_line": "{STD}/check_tcp -H $HOSTADDRESS$ -p $ARG1$",
        "description": "TCP port check",
    },
    {
        "name": "nmp_check_nrpe",
        "command_line": "{STD}/check_nrpe -H $HOSTADDRESS$ -p $_HOSTNRPE_PORT$ -t $_HOSTNRPE_TIMEOUT$ -c $ARG1$ $ARG2$",
        "description": "NRPE remote command",
    },
]

ALL_OS = ["windows", "linux", "unix", "network", "other"]
SERVER_OS = ["windows", "linux", "unix"]

SERVICES = [
    # --- availability -------------------------------------------------------
    dict(code="ping", name="Ping", category="availability", monitoring_method="ping", os_types=ALL_OS,
         command="nmp_check_ping", arg_template="{warning}!{critical}", params_schema=[],
         default_description="Ping", default_warning="200.0,20%", default_critical="500.0,60%",
         unit="ms", description="ICMP latency (rta) and packet loss. Thresholds: rta,loss%"),
    dict(code="tcp_port", name="TCP Port", category="availability", monitoring_method="ping", os_types=ALL_OS,
         command="nmp_check_tcp", arg_template="{port}",
         params_schema=[{"name": "port", "type": "int", "label": "Port", "required": True, "default": "443"}],
         default_description="TCP {port}", unit=None, description="TCP connect check"),
    # --- NCPA -----------------------------------------------------------------
    dict(code="ncpa_cpu", name="CPU Usage", category="cpu", monitoring_method="ncpa", os_types=SERVER_OS,
         command="nmp_check_ncpa", arg_template="-M cpu/percent -q 'aggregate=avg'" + THRESH, params_schema=[],
         default_description="CPU Usage", default_warning="80", default_critical="90", unit="%"),
    dict(code="ncpa_memory", name="Memory Usage", category="memory", monitoring_method="ncpa", os_types=SERVER_OS,
         command="nmp_check_ncpa", arg_template="-M memory/virtual/percent" + THRESH, params_schema=[],
         default_description="Memory Usage", default_warning="80", default_critical="90", unit="%"),
    dict(code="ncpa_disk_windows", name="Drive Usage", category="disk", monitoring_method="ncpa", os_types=["windows"],
         command="nmp_check_ncpa", arg_template="-M 'disk/logical/{drive}:|/used_percent'" + THRESH,
         params_schema=[{"name": "drive", "type": "drive", "label": "Drive letter", "required": True, "default": "C"}],
         default_description="{drive} Drive Usage", default_warning="80", default_critical="90", unit="%"),
    dict(code="ncpa_disk_linux", name="Filesystem Usage", category="disk", monitoring_method="ncpa",
         os_types=["linux", "unix"], command="nmp_check_ncpa",
         arg_template="-M 'disk/logical/{mount_ncpa}/used_percent'" + THRESH,
         params_schema=[{"name": "mount", "type": "mount", "label": "Mount point", "required": True, "default": "/"}],
         default_description="Disk {mount}", default_warning="80", default_critical="90", unit="%"),
    dict(code="ncpa_processes", name="Process Count", category="processes", monitoring_method="ncpa",
         os_types=SERVER_OS, command="nmp_check_ncpa", arg_template="-M processes" + THRESH, params_schema=[],
         default_description="Process Count", default_warning="300", default_critical="400"),
    dict(code="ncpa_process_named", name="Process Running", category="processes", monitoring_method="ncpa",
         os_types=SERVER_OS, command="nmp_check_ncpa", arg_template="-M processes -q 'name={process}'" + THRESH,
         params_schema=[{"name": "process", "type": "process", "label": "Process name", "required": True}],
         default_description="Process {process}", default_warning="1:", default_critical="1:",
         description="Number of processes with this name (default: alert when none running)"),
    dict(code="ncpa_windows_service", name="Windows Service", category="services", monitoring_method="ncpa",
         os_types=["windows"], command="nmp_check_ncpa",
         arg_template="--nmp-mismatch={mismatch} -M services -q 'service={service},status={state}'",
         params_schema=[
             {"name": "service", "type": "winservice", "label": "Service name", "required": True},
             {"name": "display_name", "type": "text", "label": "Display name", "required": False},
             {"name": "state", "type": "state", "label": "Expected state", "required": True, "default": "running"},
             {"name": "mismatch", "type": "mismatch", "label": "State when not as expected", "required": True,
              "default": "critical"},
         ],
         default_description="Service {service}", default_warning=None, default_critical=None,
         description="Checks a Windows service is in the expected state"),
    dict(code="ncpa_network", name="Network Usage", category="network", monitoring_method="ncpa", os_types=SERVER_OS,
         command="nmp_check_ncpa", arg_template="-M 'interface/{interface}/bytes_{direction}' -d -u M" + THRESH,
         params_schema=[
             {"name": "interface", "type": "interface", "label": "Interface name", "required": True, "default": "Ethernet"},
             {"name": "direction", "type": "direction", "label": "Direction", "required": True, "default": "recv"},
         ],
         default_description="Network {direction} {interface}", unit="MB/s",
         description="Interface throughput per second (delta)"),
    dict(code="ncpa_uptime", name="Uptime", category="uptime", monitoring_method="ncpa", os_types=SERVER_OS,
         command="nmp_check_ncpa", arg_template="-M system/uptime" + THRESH, params_schema=[],
         default_description="Uptime", unit="s", description="Seconds since boot; e.g. critical '600:' alerts after a reboot"),
    dict(code="ncpa_pagefile", name="Page File Usage", category="memory", monitoring_method="ncpa", os_types=["windows"],
         command="nmp_check_ncpa", arg_template="-M memory/swap/percent" + THRESH, params_schema=[],
         default_description="Page File Usage", default_warning="80", default_critical="90", unit="%"),
    dict(code="ncpa_swap", name="Swap Usage", category="memory", monitoring_method="ncpa", os_types=["linux", "unix"],
         command="nmp_check_ncpa", arg_template="-M memory/swap/percent" + THRESH, params_schema=[],
         default_description="Swap Usage", default_warning="50", default_critical="80", unit="%"),
    dict(code="ncpa_eventlog", name="Event Log", category="eventlog", monitoring_method="ncpa", os_types=["windows"],
         command="nmp_check_ncpa",
         arg_template="-M windowslogs -q 'name={logname},severity={severity},logged_after={window}'" + THRESH,
         params_schema=[
             {"name": "logname", "type": "logname", "label": "Log name", "required": True, "default": "System"},
             {"name": "severity", "type": "severity", "label": "Severity", "required": True, "default": "ERROR"},
             {"name": "window", "type": "window", "label": "Look-back window", "required": True, "default": "1h"},
         ],
         default_description="Event Log {logname}", default_warning="1", default_critical="10",
         description="Count of matching Windows event log entries in the window"),
    dict(code="ncpa_users", name="Logged-in Users", category="users", monitoring_method="ncpa", os_types=SERVER_OS,
         command="nmp_check_ncpa", arg_template="-M user/count" + THRESH, params_schema=[],
         default_description="Users", default_warning="5", default_critical="10"),
    dict(code="ncpa_load", name="CPU Load", category="cpu", monitoring_method="ncpa", os_types=["linux", "unix"],
         command="nmp_check_ncpa", arg_template="-M 'plugins/check_load' -a '-w {warning} -c {critical}'",
         params_schema=[], default_description="Load", default_warning="5,4,3", default_critical="10,8,6",
         description="Requires the check_load plugin in the NCPA agent plugins directory"),
    dict(code="ncpa_custom", name="Custom NCPA Query", category="custom", monitoring_method="ncpa", os_types=ALL_OS,
         command="nmp_check_ncpa", arg_template="-M '{metric}'[[ -q '{query}']][[ -u {units}]]" + THRESH,
         params_schema=[
             {"name": "metric", "type": "metric", "label": "Metric path (e.g. cpu/percent)", "required": True},
             {"name": "query", "type": "query", "label": "Query args (k=v,k=v)", "required": False},
             {"name": "units", "type": "units", "label": "Unit prefix", "required": False},
         ],
         default_description="NCPA {metric}"),
    dict(code="ncpa_plugin", name="NCPA Agent Plugin", category="custom", monitoring_method="ncpa", os_types=ALL_OS,
         command="nmp_check_ncpa", arg_template="-M 'plugins/{plugin}'[[ -a '{args}']]",
         params_schema=[
             {"name": "plugin", "type": "plugin", "label": "Plugin file on the agent", "required": True},
             {"name": "args", "type": "args", "label": "Plugin arguments", "required": False},
         ],
         default_description="Plugin {plugin}"),
    # --- SNMP -------------------------------------------------------------------
    dict(code="snmp_uptime", name="Device Uptime", category="uptime", monitoring_method="snmp",
         os_types=["network", "linux", "unix", "other"], command="nmp_check_snmp",
         arg_template="--mode uptime" + THRESH, params_schema=[], default_description="Device Uptime",
         default_critical="300:", unit="s", description="sysUpTime; default alerts after a reboot"),
    dict(code="snmp_ifstatus", name="Interface Status", category="network", monitoring_method="snmp",
         os_types=["network", "linux", "unix", "other"], command="nmp_check_snmp",
         arg_template="--mode ifstatus --if-index {ifindex}",
         params_schema=[{"name": "ifindex", "type": "int", "label": "ifIndex", "required": True, "default": "1"}],
         default_description="Interface {ifindex} Status"),
    dict(code="snmp_ifutil", name="Interface Utilization", category="network", monitoring_method="snmp",
         os_types=["network", "linux", "unix", "other"], command="nmp_check_snmp",
         arg_template="--mode ifutil --if-index {ifindex}[[ --if-speed {speed}]]" + THRESH,
         params_schema=[{"name": "ifindex", "type": "int", "label": "ifIndex", "required": True, "default": "1"},
                        {"name": "speed", "type": "int", "label": "Speed override (Mbps)", "required": False}],
         default_description="Interface {ifindex} Utilization", default_warning="70", default_critical="90", unit="%"),
    dict(code="snmp_bandwidth", name="Interface Bandwidth", category="network", monitoring_method="snmp",
         os_types=["network", "linux", "unix", "other"], command="nmp_check_snmp",
         arg_template="--mode bandwidth --if-index {ifindex}" + THRESH,
         params_schema=[{"name": "ifindex", "type": "int", "label": "ifIndex", "required": True, "default": "1"}],
         default_description="Interface {ifindex} Bandwidth", unit="Mbps"),
    dict(code="snmp_oid", name="SNMP OID", category="custom", monitoring_method="snmp", os_types=ALL_OS,
         command="nmp_check_snmp", arg_template="--mode oid --oid {oid}" + THRESH,
         params_schema=[{"name": "oid", "type": "oid", "label": "Numeric OID", "required": True}],
         default_description="OID {oid}"),
    # --- NRPE -------------------------------------------------------------------
    dict(code="nrpe_command", name="NRPE Command", category="custom", monitoring_method="nrpe", os_types=SERVER_OS,
         command="nmp_check_nrpe", arg_template="{command}![[-a {args}]]",
         params_schema=[{"name": "command", "type": "plugin", "label": "NRPE command name", "required": True},
                        {"name": "args", "type": "args", "label": "Arguments", "required": False}],
         default_description="NRPE {command}"),
]

WIN_TPL = [
    ("ping", "Ping", {}),
    ("ncpa_cpu", "CPU Usage", {}),
    ("ncpa_memory", "Memory Usage", {}),
    ("ncpa_disk_windows", "C Drive Usage", {"drive": "C"}),
    ("ncpa_disk_windows", "D Drive Usage", {"drive": "D"}),
    ("ncpa_disk_windows", "E Drive Usage", {"drive": "E"}),
    ("ncpa_uptime", "Uptime", {}),
    ("ncpa_processes", "Process Count", {}),
]

TEMPLATES = [
    {"name": "Windows Standard", "os_type": "windows", "monitoring_method": "ncpa",
     "description": "Baseline Windows server monitoring through NCPA", "items": WIN_TPL},
    {"name": "Windows Application Server", "os_type": "windows", "monitoring_method": "ncpa",
     "description": "Windows server running SQL Server and IIS",
     "items": [
         ("ping", "Ping", {}), ("ncpa_cpu", "CPU Usage", {}), ("ncpa_memory", "Memory Usage", {}),
         ("ncpa_disk_windows", "C Drive Usage", {"drive": "C"}),
         ("ncpa_disk_windows", "D Drive Usage", {"drive": "D"}),
         ("ncpa_windows_service", "SQL Server Service", {"service": "MSSQLSERVER", "display_name": "SQL Server"}),
         ("ncpa_windows_service", "SQL Agent Service", {"service": "SQLSERVERAGENT", "display_name": "SQL Server Agent"}),
         ("ncpa_windows_service", "IIS Service", {"service": "W3SVC", "display_name": "World Wide Web Publishing"}),
         ("ncpa_network", "Network recv Ethernet", {"interface": "Ethernet", "direction": "recv"}),
         ("ncpa_network", "Network sent Ethernet", {"interface": "Ethernet", "direction": "sent"}),
     ]},
    {"name": "Linux Standard", "os_type": "linux", "monitoring_method": "ncpa",
     "description": "Baseline Linux server monitoring through NCPA",
     "items": [
         ("ping", "Ping", {}), ("ncpa_cpu", "CPU Usage", {}), ("ncpa_memory", "Memory Usage", {}),
         ("ncpa_disk_linux", "Root Disk", {"mount": "/"}), ("ncpa_disk_linux", "Data Disk", {"mount": "/data"}),
         ("ncpa_load", "Load", {}), ("ncpa_users", "Users", {}), ("ncpa_processes", "Processes", {}),
         ("ncpa_swap", "Swap Usage", {}),
     ]},
    {"name": "Network Device Standard", "os_type": "network", "monitoring_method": "snmp",
     "description": "Switch/router/firewall basics over SNMP",
     "items": [
         ("ping", "Ping", {}), ("snmp_uptime", "Device Uptime", {}),
         ("snmp_ifstatus", "Interface 1 Status", {"ifindex": "1"}),
         ("snmp_ifutil", "Interface 1 Utilization", {"ifindex": "1"}),
     ]},
    {"name": "Ping Only", "os_type": "other", "monitoring_method": "ping",
     "description": "Reachability only", "items": [("ping", "Ping", {})]},
]

# Default host groups: registered as external when already defined in manual config.
DEFAULT_GROUPS = [
    ("windows-servers", "Windows Servers"),
    ("linux-servers", "Linux Servers"),
    ("network-devices", "Network Devices"),
]

DEFAULT_SETTINGS = {
    "display_timezone": "Asia/Kolkata",
    "default_contact_group": "admins",
    "ncpa_default_port": 5693,
    "ncpa_default_timeout": 30,
    "ncpa_default_verify_ssl": False,
    "perf_retention_days": 90,
    "sla_targets": {"production": 99.9, "uat": 99.0, "development": 95.0, "dr": 99.5, "test": 95.0},
    "host_notification_command": "notify-host-by-email",
    "service_notification_command": "notify-service-by-email",
    "health_thresholds": {"cpu": 85, "memory": 85, "disk": 85},
    "session_idle_minutes": 30,
}
