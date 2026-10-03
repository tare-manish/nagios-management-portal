"""ORM models - the management/configuration layer.

MariaDB holds inventory, configuration intent, credentials (encrypted),
audit and version history. Live monitoring state stays in Nagios.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    JSON,
)
from sqlalchemy.dialects.mysql import LONGBLOB, MEDIUMTEXT
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship

from .db import Base, utcnow

LongText = Text().with_variant(MEDIUMTEXT(), "mysql").with_variant(MEDIUMTEXT(), "mariadb")
LongBlob = LargeBinary().with_variant(LONGBLOB(), "mysql").with_variant(LONGBLOB(), "mariadb")

ENVIRONMENTS = ("production", "uat", "development", "dr", "test")
OS_TYPES = ("windows", "linux", "unix", "network", "other")
MON_METHODS = ("ncpa", "snmp", "nrpe", "ping", "custom")
DEVICE_TYPES = ("server", "network_device")
CONFIG_STATES = ("draft", "pending", "applied", "error")
MANAGED_BY = ("portal", "external")
VERSION_STATUSES = (
    "generated", "validation_failed", "validated", "applying", "applied",
    "apply_failed", "rolled_back", "superseded",
)
AUDIT_RESULTS = ("success", "failure", "denied")
CRED_TYPES = ("ncpa", "snmp", "nrpe", "custom")
EVENT_TYPES = (
    "host_down", "service_critical", "service_warning", "recovery",
    "high_cpu", "high_memory", "high_disk", "network_down",
)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class AuditMixin(TimestampMixin):
    @declared_attr
    def created_by(cls) -> Mapped[Optional[int]]:
        return mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    @declared_attr
    def updated_by(cls) -> Mapped[Optional[int]]:
        return mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


# --------------------------------------------------------------- identity ---
class Role(TimestampMixin, Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    permissions: Mapped[list["Permission"]] = relationship(secondary="role_permissions", lazy="selectin")


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    email: Mapped[Optional[str]] = mapped_column(String(190))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45))
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    roles: Mapped[list[Role]] = relationship(secondary="user_roles", lazy="selectin")
    companies: Mapped[list["Company"]] = relationship(secondary="user_companies", lazy="selectin", order_by="Company.name")
    locations: Mapped[list["Location"]] = relationship(secondary="user_locations", lazy="selectin", order_by="Location.name")


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256(token)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"
    bucket_key: Mapped[str] = mapped_column(String(190), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


# ------------------------------------------------- companies & locations ----
class Company(AuditMixin, Base):
    """A group company. Managed by Super Admin; other users see only the companies assigned to them.

    Companies are never hard-deleted (configuration snapshots reference them); retire with is_active=False.
    """
    __tablename__ = "companies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Location(AuditMixin, Base):
    """A site (Daman, Vapi, ...). Optionally narrows a user's companies to particular sites."""
    __tablename__ = "locations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class UserCompany(Base):
    """Companies a non-Super-Admin user may monitor (one or several)."""
    __tablename__ = "user_companies"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id", ondelete="CASCADE"), primary_key=True)


class UserLocation(Base):
    __tablename__ = "user_locations"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    location_id: Mapped[int] = mapped_column(ForeignKey("locations.id", ondelete="CASCADE"), primary_key=True)


# ------------------------------------------------------------ inventory -----
class ServerGroup(AuditMixin, Base):
    """Nagios hostgroup. is_managed=False => defined outside the portal (referenced only)."""
    __tablename__ = "server_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    alias: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_managed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Contact(AuditMixin, Base):
    __tablename__ = "contacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    alias: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(190))
    phone: Mapped[Optional[str]] = mapped_column(String(32))
    host_notification_options: Mapped[str] = mapped_column(String(20), default="d,u,r", nullable=False)
    service_notification_options: Mapped[str] = mapped_column(String(20), default="w,u,c,r", nullable=False)
    notification_period: Mapped[str] = mapped_column(String(64), default="24x7", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_managed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ContactGroup(AuditMixin, Base):
    __tablename__ = "contact_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    alias: Mapped[str] = mapped_column(String(120), nullable=False)
    is_managed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    members: Mapped[list[Contact]] = relationship(secondary="contact_group_members", lazy="selectin")


class ContactGroupMember(Base):
    __tablename__ = "contact_group_members"
    contact_group_id: Mapped[int] = mapped_column(ForeignKey("contact_groups.id", ondelete="CASCADE"), primary_key=True)
    contact_id: Mapped[int] = mapped_column(ForeignKey("contacts.id", ondelete="CASCADE"), primary_key=True)


class Command(AuditMixin, Base):
    __tablename__ = "commands"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    command_line: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Service(AuditMixin, Base):
    """Service catalog entry: a reusable check definition (CPU via NCPA, Ping...)."""
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)  # cpu, memory, disk, ...
    monitoring_method: Mapped[str] = mapped_column(Enum(*MON_METHODS, name="mon_method"), nullable=False)
    os_types: Mapped[list] = mapped_column(JSON, nullable=False)
    command_id: Mapped[int] = mapped_column(ForeignKey("commands.id", ondelete="RESTRICT"), nullable=False)
    arg_template: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    params_schema: Mapped[list] = mapped_column(JSON, nullable=False)
    default_description: Mapped[str] = mapped_column(String(100), nullable=False)
    default_warning: Mapped[Optional[str]] = mapped_column(String(40))
    default_critical: Mapped[Optional[str]] = mapped_column(String(40))
    default_check_interval: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    default_retry_interval: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    default_notification_interval: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    unit: Mapped[Optional[str]] = mapped_column(String(16))
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    command: Mapped[Command] = relationship(lazy="joined")


class MonitoringTemplate(AuditMixin, Base):
    __tablename__ = "monitoring_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    os_type: Mapped[str] = mapped_column(Enum(*OS_TYPES, name="os_type"), nullable=False)
    monitoring_method: Mapped[str] = mapped_column(Enum(*MON_METHODS, name="mon_method"), nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    items: Mapped[list["TemplateService"]] = relationship(
        back_populates="template", cascade="all, delete-orphan", lazy="selectin",
        order_by="TemplateService.sort_order",
    )


class TemplateService(Base):
    __tablename__ = "template_services"
    __table_args__ = (UniqueConstraint("template_id", "service_description", name="uq_tpl_svc_desc"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("monitoring_templates.id", ondelete="CASCADE"), nullable=False)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="RESTRICT"), nullable=False)
    service_description: Mapped[str] = mapped_column(String(100), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, nullable=False)
    warning: Mapped[Optional[str]] = mapped_column(String(40))
    critical: Mapped[Optional[str]] = mapped_column(String(40))
    check_interval: Mapped[Optional[int]] = mapped_column(Integer)
    retry_interval: Mapped[Optional[int]] = mapped_column(Integer)
    notification_interval: Mapped[Optional[int]] = mapped_column(Integer)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    template: Mapped[MonitoringTemplate] = relationship(back_populates="items")
    service: Mapped[Service] = relationship(lazy="joined")


class Server(AuditMixin, Base):
    __tablename__ = "servers"
    __table_args__ = (
        UniqueConstraint("hostname", "deleted_token", name="uq_server_hostname"),
        Index("ix_server_env", "environment"),
        Index("ix_server_os", "os_type"),
        Index("ix_server_state", "config_state"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    location: Mapped[Optional[str]] = mapped_column(String(120))
    environment: Mapped[str] = mapped_column(Enum(*ENVIRONMENTS, name="environment"), nullable=False)
    os_type: Mapped[str] = mapped_column(Enum(*OS_TYPES, name="os_type"), nullable=False)
    os_version: Mapped[Optional[str]] = mapped_column(String(120))
    device_type: Mapped[str] = mapped_column(Enum(*DEVICE_TYPES, name="device_type"), default="server", nullable=False)
    monitoring_method: Mapped[str] = mapped_column(Enum(*MON_METHODS, name="mon_method"), nullable=False)
    host_check: Mapped[str] = mapped_column(String(16), default="agent", nullable=False)  # agent | ping
    template_id: Mapped[Optional[int]] = mapped_column(ForeignKey("monitoring_templates.id", ondelete="SET NULL"))
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id", ondelete="RESTRICT"), index=True)
    location_id: Mapped[Optional[int]] = mapped_column(ForeignKey("locations.id", ondelete="RESTRICT"), index=True)
    check_interval: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    retry_interval: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    max_check_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    notification_interval: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    check_period: Mapped[str] = mapped_column(String(64), default="24x7", nullable=False)
    notification_period: Mapped[str] = mapped_column(String(64), default="24x7", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config_state: Mapped[str] = mapped_column(Enum(*CONFIG_STATES, name="config_state"), default="pending", nullable=False)
    managed_by: Mapped[str] = mapped_column(Enum(*MANAGED_BY, name="managed_by"), default="portal", nullable=False)
    imported_from: Mapped[Optional[str]] = mapped_column(String(255))
    tags: Mapped[Optional[list]] = mapped_column(JSON)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    deleted_token: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    groups: Mapped[list[ServerGroup]] = relationship(secondary="server_group_members", lazy="selectin")
    contact_groups: Mapped[list[ContactGroup]] = relationship(secondary="server_contact_groups", lazy="selectin")
    credentials: Mapped[list["ServerCredential"]] = relationship(
        back_populates="server", cascade="all, delete-orphan", lazy="selectin")
    services: Mapped[list["ServerService"]] = relationship(
        back_populates="server", cascade="all, delete-orphan", lazy="selectin",
        order_by="ServerService.service_description")
    template: Mapped[Optional[MonitoringTemplate]] = relationship(lazy="joined")
    company: Mapped[Optional[Company]] = relationship(lazy="joined")
    site: Mapped[Optional[Location]] = relationship(lazy="joined")

    @property
    def nagios_key(self) -> str:
        return f"srv-{self.id}"


class ServerGroupMember(Base):
    __tablename__ = "server_group_members"
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id", ondelete="CASCADE"), primary_key=True)


class ServerContactGroup(Base):
    __tablename__ = "server_contact_groups"
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    contact_group_id: Mapped[int] = mapped_column(ForeignKey("contact_groups.id", ondelete="CASCADE"), primary_key=True)


class ServerCredential(AuditMixin, Base):
    """Agent/SNMP connection settings. Secrets live only in secret_ciphertext (AES-256-GCM)."""
    __tablename__ = "server_credentials"
    __table_args__ = (UniqueConstraint("server_id", "credential_type", name="uq_server_cred_type"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    credential_type: Mapped[str] = mapped_column(Enum(*CRED_TYPES, name="cred_type"), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer)
    ssl_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timeout: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    snmp_version: Mapped[Optional[str]] = mapped_column(String(8))
    snmp_username: Mapped[Optional[str]] = mapped_column(String(64))
    snmp_auth_protocol: Mapped[Optional[str]] = mapped_column(String(16))
    snmp_priv_protocol: Mapped[Optional[str]] = mapped_column(String(16))
    snmp_security_level: Mapped[Optional[str]] = mapped_column(String(16))
    secret_ciphertext: Mapped[Optional[str]] = mapped_column(Text)
    last_test_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_test_result: Mapped[Optional[str]] = mapped_column(String(40))
    server: Mapped[Server] = relationship(back_populates="credentials")


class ServerService(AuditMixin, Base):
    __tablename__ = "server_services"
    __table_args__ = (UniqueConstraint("server_id", "service_description", name="uq_server_svc_desc"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="RESTRICT"), nullable=False)
    service_description: Mapped[str] = mapped_column(String(100), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    from_template_id: Mapped[Optional[int]] = mapped_column(ForeignKey("monitoring_templates.id", ondelete="SET NULL"))
    server: Mapped[Server] = relationship(back_populates="services")
    service: Mapped[Service] = relationship(lazy="joined")
    threshold: Mapped[Optional["ServiceThreshold"]] = relationship(
        back_populates="server_service", cascade="all, delete-orphan", uselist=False, lazy="joined")


class ServiceThreshold(TimestampMixin, Base):
    __tablename__ = "service_thresholds"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_service_id: Mapped[int] = mapped_column(
        ForeignKey("server_services.id", ondelete="CASCADE"), unique=True, nullable=False)
    warning: Mapped[Optional[str]] = mapped_column(String(40))
    critical: Mapped[Optional[str]] = mapped_column(String(40))
    check_interval: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    retry_interval: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    max_check_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    notification_interval: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    server_service: Mapped[ServerService] = relationship(back_populates="threshold")


# ------------------------------------------------------ configuration mgmt --
class ConfigurationVersion(Base):
    __tablename__ = "configuration_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(Enum(*VERSION_STATUSES, name="version_status"), nullable=False)
    config_hash: Mapped[Optional[str]] = mapped_column(String(64))
    validation_output: Mapped[Optional[str]] = mapped_column(LongText)
    validation_errors: Mapped[Optional[list]] = mapped_column(JSON)
    validation_warnings: Mapped[Optional[list]] = mapped_column(JSON)
    apply_log: Mapped[Optional[list]] = mapped_column(JSON)
    backup_id: Mapped[Optional[int]] = mapped_column(ForeignKey("config_backups.id", ondelete="SET NULL"))
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    applied_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    rollback_of_version: Mapped[Optional[int]] = mapped_column(Integer)
    snapshot: Mapped[Optional[bytes]] = mapped_column(LongBlob)
    legacy_overrides: Mapped[Optional[list]] = mapped_column(JSON)
    files: Mapped[list["ConfigurationVersionFile"]] = relationship(
        cascade="all, delete-orphan", lazy="select", order_by="ConfigurationVersionFile.path")


class ConfigurationVersionFile(Base):
    __tablename__ = "configuration_version_files"
    __table_args__ = (UniqueConstraint("version_id", "path", name="uq_version_file"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("configuration_versions.id", ondelete="CASCADE"), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(LongText, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class ConfigurationChange(Base):
    """Pending (version_id NULL) or applied change to managed objects."""
    __tablename__ = "configuration_changes"
    __table_args__ = (Index("ix_change_pending", "version_id", "created_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version_id: Mapped[Optional[int]] = mapped_column(ForeignKey("configuration_versions.id", ondelete="SET NULL"))
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[Optional[int]] = mapped_column(Integer)
    entity_name: Mapped[str] = mapped_column(String(190), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    old_value: Mapped[Optional[dict]] = mapped_column(JSON)
    new_value: Mapped[Optional[dict]] = mapped_column(JSON)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class ConfigBackup(Base):
    __tablename__ = "config_backups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64))
    version_id: Mapped[Optional[int]] = mapped_column(Integer)
    files: Mapped[Optional[list]] = mapped_column(JSON)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_time", "occurred_at"),
        Index("ix_audit_entity", "entity_type", "entity_id"),
        Index("ix_audit_user", "user_id"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    username: Mapped[Optional[str]] = mapped_column(String(64))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[Optional[str]] = mapped_column(String(32))
    entity_id: Mapped[Optional[int]] = mapped_column(Integer)
    entity_name: Mapped[Optional[str]] = mapped_column(String(190))
    old_value: Mapped[Optional[dict]] = mapped_column(JSON)
    new_value: Mapped[Optional[dict]] = mapped_column(JSON)
    result: Mapped[str] = mapped_column(Enum(*AUDIT_RESULTS, name="audit_result"), nullable=False)
    detail: Mapped[Optional[str]] = mapped_column(String(1024))


# ----------------------------------------------------------- notifications --
class NotificationChannel(AuditMixin, Base):
    __tablename__ = "notification_channels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # registry key
    settings: Mapped[dict] = mapped_column(JSON, nullable=False)      # non-secret settings
    secret_ciphertext: Mapped[Optional[str]] = mapped_column(Text)   # secret settings (encrypted JSON)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class NotificationRule(AuditMixin, Base):
    __tablename__ = "notification_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    event_types: Mapped[list] = mapped_column(JSON, nullable=False)
    filters: Mapped[dict] = mapped_column(JSON, nullable=False)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False)
    throttle_minutes: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    channel: Mapped[NotificationChannel] = relationship(lazy="joined")


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notif_time", "created_at"), Index("ix_notif_throttle", "rule_id", "object_key", "created_at"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("notification_rules.id", ondelete="SET NULL"))
    channel_id: Mapped[Optional[int]] = mapped_column(ForeignKey("notification_channels.id", ondelete="SET NULL"))
    server_id: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    object_key: Mapped[str] = mapped_column(String(190), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # sent|failed|suppressed
    error: Mapped[Optional[str]] = mapped_column(String(512))
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime)


# ------------------------------------------------------------ perf / misc --
class PerfSample(Base):
    __tablename__ = "perf_samples"
    __table_args__ = (
        UniqueConstraint("server_id", "service_description", "label", "sampled_at", name="uq_perf_sample"),
        Index("ix_perf_lookup", "server_id", "service_description", "sampled_at"),
        Index("ix_perf_time", "sampled_at"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, nullable=False)
    service_description: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    uom: Mapped[Optional[str]] = mapped_column(String(16))
    warn: Mapped[Optional[float]] = mapped_column(Float)
    crit: Mapped[Optional[float]] = mapped_column(Float)
    sampled_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class MonitorStateCache(Base):
    """Last HARD state seen by the notification engine (engine bookkeeping only)."""
    __tablename__ = "monitor_state_cache"
    object_key: Mapped[str] = mapped_column(String(190), primary_key=True)
    state: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeat"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    detail: Mapped[Optional[dict]] = mapped_column(JSON)


# Tables whose rows make up the "desired configuration" (snapshotted per version).
SNAPSHOT_TABLES = [
    "commands", "services", "server_groups", "contacts", "contact_groups", "contact_group_members",
    "servers", "server_group_members", "server_contact_groups", "server_credentials",
    "server_services", "service_thresholds",
]
