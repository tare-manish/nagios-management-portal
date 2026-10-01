"""Role-based access control: permission catalogue and default roles."""
from __future__ import annotations

PERMISSIONS: dict[str, tuple[str, str]] = {
    # code: (category, description)
    "dashboard.view": ("Monitoring", "View dashboard"),
    "monitoring.view": ("Monitoring", "View live hosts, services, problems and events"),
    "monitoring.acknowledge": ("Monitoring", "Acknowledge problems"),
    "monitoring.downtime": ("Monitoring", "Schedule and cancel downtime"),
    "monitoring.control": ("Monitoring", "Re-check now, enable/disable checks via Nagios commands"),
    "servers.view": ("Infrastructure", "View server inventory"),
    "servers.create": ("Infrastructure", "Add servers and network devices"),
    "servers.edit": ("Infrastructure", "Edit servers, services and thresholds"),
    "servers.delete": ("Infrastructure", "Delete servers"),
    "servers.test": ("Infrastructure", "Run agent connection tests"),
    "groups.manage": ("Infrastructure", "Manage host groups"),
    "templates.view": ("Infrastructure", "View monitoring templates"),
    "templates.manage": ("Infrastructure", "Create and edit monitoring templates"),
    "catalog.manage": ("Configuration", "Manage service definitions and commands"),
    "contacts.manage": ("Configuration", "Manage contacts and contact groups"),
    "config.view": ("Configuration", "View configuration versions and pending changes"),
    "config.validate": ("Configuration", "Generate and validate Nagios configuration"),
    "config.apply": ("Configuration", "Apply configuration and reload Nagios"),
    "config.rollback": ("Configuration", "Roll back to a previous configuration version"),
    "config.import": ("Configuration", "Import existing Nagios configuration"),
    "reports.view": ("Reports", "View and export reports"),
    "audit.view": ("Reports", "View audit log"),
    "notifications.manage": ("Administration", "Manage notification channels and rules"),
    "users.manage": ("Administration", "Manage users"),
    "roles.manage": ("Administration", "Manage roles and permissions"),
    "settings.manage": ("Administration", "Change system settings"),
    "backups.manage": ("Administration", "Create, download and restore configuration backups"),
    "health.view": ("Administration", "View system health"),
    "maintenance.cleanup": ("Administration", "Clean up junk and stale data (Super Admin only)"),
}

# Permissions that only the Super Admin role may ever hold. They are never part of
# another default role, cannot be added to custom roles, and the API additionally
# requires the super_admin role itself.
SUPER_ADMIN_ONLY = frozenset({"maintenance.cleanup"})

_VIEW = [
    "dashboard.view", "monitoring.view", "servers.view", "templates.view",
    "config.view", "reports.view", "health.view",
]
_OPERATOR = _VIEW + ["monitoring.acknowledge", "monitoring.downtime", "monitoring.control", "servers.test"]
_ADMIN = sorted(set(PERMISSIONS) - {"users.manage", "roles.manage", "settings.manage"} - SUPER_ADMIN_ONLY)

DEFAULT_ROLES: dict[str, dict] = {
    "super_admin": {"display_name": "Super Admin", "description": "Full access", "permissions": sorted(PERMISSIONS)},
    "administrator": {"display_name": "Administrator", "description": "Server and monitoring management", "permissions": _ADMIN},
    "operator": {"display_name": "Operator", "description": "View monitoring and acknowledge alerts", "permissions": _OPERATOR},
    "viewer": {"display_name": "Viewer", "description": "Read-only access", "permissions": _VIEW},
}
