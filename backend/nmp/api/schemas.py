"""Pydantic request models (validation reuses nmp.validators)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from .. import validators as V

Env = Literal["production", "uat", "development", "dr", "test"]
OsType = Literal["windows", "linux", "unix", "network", "other"]
Method = Literal["ncpa", "snmp", "nrpe", "ping", "custom"]


class NcpaIn(BaseModel):
    port: int = Field(5693, ge=1, le=65535)
    token: Optional[str] = Field(None, max_length=256)
    ssl_enabled: bool = True
    verify_ssl: bool = False
    timeout: int = Field(30, ge=3, le=120)

    @field_validator("token")
    @classmethod
    def _token(cls, v):
        if v is None or v == "":
            return None
        if any(c in v for c in "\n\r\t\x00") or len(v.strip()) != len(v):
            raise ValueError("token contains invalid characters")
        return v


class SnmpIn(BaseModel):
    version: Literal["2c", "3"] = "2c"
    community: Optional[str] = Field(None, max_length=128)
    username: Optional[str] = Field(None, max_length=64)
    security_level: Optional[Literal["noAuthNoPriv", "authNoPriv", "authPriv"]] = "authPriv"
    auth_protocol: Optional[Literal["MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]] = None
    auth_password: Optional[str] = Field(None, max_length=128)
    priv_protocol: Optional[Literal["DES", "AES", "AES-192", "AES-256"]] = None
    priv_password: Optional[str] = Field(None, max_length=128)

    @field_validator("community", "auth_password", "priv_password", "username")
    @classmethod
    def _no_ctl(cls, v):
        if v is not None and any(c in v for c in "\n\r\t\x00"):
            raise ValueError("contains invalid characters")
        return v or None


class NrpeIn(BaseModel):
    port: int = Field(5666, ge=1, le=65535)
    timeout: int = Field(30, ge=3, le=120)


class ServiceItemIn(BaseModel):
    id: Optional[int] = None
    service_id: int
    service_description: str
    params: dict = Field(default_factory=dict)
    is_enabled: bool = True
    warning: Optional[str] = None
    critical: Optional[str] = None
    check_interval: int = Field(5, ge=1, le=1440)
    retry_interval: int = Field(1, ge=1, le=1440)
    max_check_attempts: int = Field(3, ge=1, le=20)
    notification_interval: int = Field(60, ge=0, le=10080)
    notifications_enabled: bool = True

    @field_validator("service_description")
    @classmethod
    def _desc(cls, v):
        return V.check_service_description(v)

    @field_validator("warning", "critical")
    @classmethod
    def _thr(cls, v, info):
        return V.check_threshold(v, info.field_name)


class ServerIn(BaseModel):
    hostname: str
    display_name: str
    address: str
    description: Optional[str] = None
    location: Optional[str] = None
    environment: Env = "production"
    os_type: OsType
    os_version: Optional[str] = None
    device_type: Literal["server", "network_device"] = "server"
    monitoring_method: Method
    host_check: Literal["agent", "ping"] = "agent"
    group_ids: list[int] = Field(default_factory=list)
    contact_group_ids: list[int] = Field(default_factory=list)
    template_id: Optional[int] = None
    check_interval: int = Field(5, ge=1, le=1440)
    retry_interval: int = Field(1, ge=1, le=1440)
    max_check_attempts: int = Field(5, ge=1, le=20)
    notification_interval: int = Field(60, ge=0, le=10080)
    notifications_enabled: bool = True
    check_period: str = "24x7"
    notification_period: str = "24x7"
    is_enabled: bool = True
    tags: list[str] = Field(default_factory=list, max_length=20)
    ncpa: Optional[NcpaIn] = None
    snmp: Optional[SnmpIn] = None
    nrpe: Optional[NrpeIn] = None
    services: Optional[list[ServiceItemIn]] = None
    action: Literal["draft", "save", "validate", "apply"] = "save"

    @field_validator("hostname")
    @classmethod
    def _hn(cls, v):
        return V.check_hostname(v)

    @field_validator("address")
    @classmethod
    def _addr(cls, v):
        return V.check_address(v)

    @field_validator("display_name")
    @classmethod
    def _dn(cls, v):
        return V.check_free_text(v, "display_name", 120, required=True)

    @field_validator("description")
    @classmethod
    def _desc(cls, v):
        return V.check_free_text(v, "description", 255)

    @field_validator("location", "os_version")
    @classmethod
    def _txt(cls, v, info):
        return V.check_free_text(v, info.field_name, 120)

    @field_validator("check_period", "notification_period")
    @classmethod
    def _tp(cls, v, info):
        return V.check_timeperiod(v, info.field_name)

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        return [V.check_free_text(t, "tags", 40, required=True) for t in v]


class ConnectionTestIn(BaseModel):
    address: str
    monitoring_method: Method
    ncpa: Optional[NcpaIn] = None
    snmp: Optional[SnmpIn] = None
    server_id: Optional[int] = None

    @field_validator("address")
    @classmethod
    def _addr(cls, v):
        return V.check_address(v)


class ActionIn(BaseModel):
    action: Literal["save", "validate", "apply"] = "save"
