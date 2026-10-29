"""SQLAlchemy 2.0 ORM models for PostgreSQL schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from lan_manager.infrastructure.database.base import (
    Base,
    IPAddressType,
    JSONVariant,
    TZDateTime,
    utc_now,
)


class RoleORM(Base):
    """Roles table for RBAC authorization."""

    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)

    users: Mapped[list[UserORM]] = relationship("UserORM", back_populates="role")


class UserORM(Base):
    """Users table for operator authentication and audit attribution."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    role: Mapped[RoleORM] = relationship("RoleORM", back_populates="users", lazy="joined")


class DeviceORM(Base):
    """Central managed network devices table."""

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("ip_address", name="uq_devices_ip_address"),
        Index("ix_devices_mac_address", "mac_address"),
        Index("ix_devices_type_status", "device_type", "status"),
        Index("ix_devices_last_seen_at", "last_seen_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(IPAddressType(), nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    device_type: Mapped[str] = mapped_column(String(50), nullable=False, default="UNKNOWN")
    manufacturer: Mapped[str | None] = mapped_column(String(120), nullable=True)
    model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="UNCHECKED")
    first_seen_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    printer: Mapped[PrinterORM | None] = relationship(
        "PrinterORM", back_populates="device", uselist=False, cascade="all, delete-orphan"
    )
    status_history: Mapped[list[DeviceStatusHistoryORM]] = relationship(
        "DeviceStatusHistoryORM", back_populates="device", cascade="all, delete-orphan"
    )
    diagnostics: Mapped[list[DiagnosticResultORM]] = relationship(
        "DiagnosticResultORM", back_populates="device", cascade="all, delete-orphan"
    )
    remote_tasks: Mapped[list[RemoteTaskORM]] = relationship(
        "RemoteTaskORM", back_populates="target_device", cascade="all, delete-orphan"
    )


class PrinterORM(Base):
    """Printer-specific details linked 1-to-1 with a device."""

    __tablename__ = "printers"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_printers_device_id"),
        Index("ix_printers_serial_number", "serial_number"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    printer_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    serial_number: Mapped[str | None] = mapped_column(String(120), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    supported_protocols: Mapped[list[str]] = mapped_column(
        JSONVariant, nullable=False, default=list
    )
    snmp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    printer_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONVariant, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    device: Mapped[DeviceORM] = relationship("DeviceORM", back_populates="printer")


class DeviceStatusHistoryORM(Base):
    """Historical log of device connectivity states and probe latency."""

    __tablename__ = "device_status_history"
    __table_args__ = (Index("ix_status_history_device_checked", "device_id", "checked_at"),)

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    open_ports: Mapped[list[int]] = mapped_column(JSONVariant, nullable=False, default=list)
    snmp_reachable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status_detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)

    device: Mapped[DeviceORM] = relationship("DeviceORM", back_populates="status_history")


class DiagnosticResultORM(Base):
    """Diagnostic execution results and probable root-cause records."""

    __tablename__ = "diagnostic_results"
    __table_args__ = (
        Index("ix_diagnostics_device_checked", "device_id", "checked_at"),
        Index("ix_diagnostics_severity", "severity"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    check_type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    probable_cause: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    diagnostic_data: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant, nullable=False, default=dict
    )
    performed_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    checked_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)

    device: Mapped[DeviceORM] = relationship("DeviceORM", back_populates="diagnostics")


class RemoteTaskORM(Base):
    """Controlled administrative remediation task history."""

    __tablename__ = "remote_tasks"
    __table_args__ = (
        Index("ix_remote_tasks_device_requested", "target_device_id", "requested_at"),
        Index("ix_remote_tasks_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    target_device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    task_type: Mapped[str] = mapped_column(String(80), nullable=False)
    requested_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_by_username: Mapped[str] = mapped_column(
        String(100), nullable=False, default="system"
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="PENDING")
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False, default=dict)
    requested_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    target_device: Mapped[DeviceORM] = relationship("DeviceORM", back_populates="remote_tasks")


class AuditLogORM(Base):
    """Immutable administrative audit log table."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_action_result", "action", "result"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    username: Mapped[str] = mapped_column(String(100), nullable=False, default="system", index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[str] = mapped_column(String(120), nullable=False)
    result: Mapped[str] = mapped_column(String(30), nullable=False)
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utc_now)
