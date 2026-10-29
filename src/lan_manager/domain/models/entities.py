"""Pure Python domain entities independent of SQLAlchemy ORM and PySide6 UI widgets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from lan_manager.domain.enums.system_enums import (
    AuditResult,
    DeviceStatusEnum,
    DeviceType,
    DiagnosticCheckType,
    DiagnosticSeverity,
    RiskLevel,
    RoleType,
    TaskStatus,
    TaskType,
)

_MAC_HEX_RE = re.compile(r"^[0-9A-F]{12}$")


def normalize_mac_address(raw_mac: str | None) -> str | None:
    """
    Normalize a MAC address into uppercase EUI-48 format 'AA:BB:CC:DD:EE:FF'.
    Returns None if empty, invalid, broadcast, or all-zero.
    """
    if not raw_mac:
        return None
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", raw_mac).upper()
    if not _MAC_HEX_RE.match(hex_only):
        return None
    if hex_only in {"000000000000", "FFFFFFFFFFFF"}:
        return None
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(UTC)


@dataclass
class Role:
    """Role entity defining authorization tier."""

    id: UUID = field(default_factory=uuid4)
    name: RoleType = RoleType.VIEWER
    description: str = ""
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class User:
    """User account entity."""

    id: UUID = field(default_factory=uuid4)
    username: str = ""
    full_name: str = ""
    password_hash: str = ""
    role_id: UUID | None = None
    role_name: RoleType = RoleType.VIEWER
    is_active: bool = True
    last_login_at: datetime | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


@dataclass
class Printer:
    """Printer-specific profile linked 1-to-1 with a Device."""

    id: UUID = field(default_factory=uuid4)
    device_id: UUID = field(default_factory=uuid4)
    printer_name: str = ""
    serial_number: str | None = None
    firmware_version: str | None = None
    supported_protocols: list[str] = field(default_factory=list)
    snmp_enabled: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


@dataclass
class Device:
    """Managed network device entity."""

    id: UUID = field(default_factory=uuid4)
    hostname: str | None = None
    ip_address: str = ""
    mac_address: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    manufacturer: str | None = None
    model: str | None = None
    location: str | None = None
    status: DeviceStatusEnum = DeviceStatusEnum.UNCHECKED
    first_seen_at: datetime = field(default_factory=utc_now)
    last_seen_at: datetime | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    printer_info: Printer | None = None

    def __post_init__(self) -> None:
        self.mac_address = normalize_mac_address(self.mac_address)


@dataclass
class DeviceStatusRecord:
    """Historical point-in-time connectivity check for a device."""

    id: int | None = None
    device_id: UUID = field(default_factory=uuid4)
    status: DeviceStatusEnum = DeviceStatusEnum.UNKNOWN
    latency_ms: int | None = None
    open_ports: list[int] = field(default_factory=list)
    snmp_reachable: bool = False
    status_detail: str | None = None
    checked_at: datetime = field(default_factory=utc_now)


@dataclass
class DiagnosticResult:
    """Outcome of a diagnostic check on a device or printer."""

    id: UUID = field(default_factory=uuid4)
    device_id: UUID = field(default_factory=uuid4)
    check_type: DiagnosticCheckType = DiagnosticCheckType.FULL_DIAGNOSTIC
    severity: DiagnosticSeverity = DiagnosticSeverity.UNKNOWN
    probable_cause: str = ""
    diagnostic_data: dict[str, Any] = field(default_factory=dict)
    performed_by: UUID | None = None
    checked_at: datetime = field(default_factory=utc_now)


@dataclass
class RemoteTask:
    """Controlled administrative remediation task record."""

    id: UUID = field(default_factory=uuid4)
    target_device_id: UUID = field(default_factory=uuid4)
    task_type: TaskType = TaskType.RECHECK_CONNECTIVITY
    requested_by: UUID | None = None
    requested_by_username: str = ""
    status: TaskStatus = TaskStatus.PENDING
    risk_level: RiskLevel = RiskLevel.LOW
    parameters: dict[str, Any] = field(default_factory=dict)
    requested_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result_summary: str | None = None
    error_message: str | None = None


@dataclass
class AuditLog:
    """Immutable administrative audit record."""

    id: int | None = None
    user_id: UUID | None = None
    username: str = "system"
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    result: AuditResult = AuditResult.SUCCESS
    safe_metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
