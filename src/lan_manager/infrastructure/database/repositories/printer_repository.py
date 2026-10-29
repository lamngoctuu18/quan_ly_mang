"""Printer repository for managing specialized printer profiles and statuses."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from lan_manager.domain.enums.system_enums import DeviceStatusEnum, DeviceType
from lan_manager.domain.models.entities import Device, Printer, utc_now
from lan_manager.infrastructure.database.models import DeviceORM, PrinterORM
from lan_manager.infrastructure.database.repositories.device_repository import (
    _device_orm_to_domain,
    _printer_orm_to_domain,
)


class PrinterRepository:
    """Persistence operations for Printer entities."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def upsert_printer(
        self,
        device_id: UUID,
        printer_name: str,
        serial_number: str | None = None,
        firmware_version: str | None = None,
        supported_protocols: list[str] | None = None,
        snmp_enabled: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> Printer:
        """Create or update printer-specific record linked to device_id."""
        now = utc_now()
        orm_obj = self._session.scalar(select(PrinterORM).where(PrinterORM.device_id == device_id))
        if orm_obj is None:
            orm_obj = PrinterORM(
                device_id=device_id,
                printer_name=printer_name or "Unknown Printer",
                serial_number=serial_number,
                firmware_version=firmware_version,
                supported_protocols=list(supported_protocols or []),
                snmp_enabled=snmp_enabled,
                printer_metadata=dict(metadata or {}),
                created_at=now,
                updated_at=now,
            )
            self._session.add(orm_obj)
        else:
            if printer_name:
                orm_obj.printer_name = printer_name
            if serial_number:
                orm_obj.serial_number = serial_number
            if firmware_version:
                orm_obj.firmware_version = firmware_version
            if supported_protocols is not None:
                orm_obj.supported_protocols = list(supported_protocols)
            orm_obj.snmp_enabled = snmp_enabled
            if metadata:
                merged = dict(orm_obj.printer_metadata or {})
                merged.update(metadata)
                orm_obj.printer_metadata = merged
            orm_obj.updated_at = now

        self._session.flush()
        result = _printer_orm_to_domain(orm_obj)
        assert result is not None
        return result

    def get_by_device_id(self, device_id: UUID) -> Printer | None:
        orm_obj = self._session.scalar(select(PrinterORM).where(PrinterORM.device_id == device_id))
        return _printer_orm_to_domain(orm_obj)

    def list_printer_devices(
        self,
        search_query: str | None = None,
        status: DeviceStatusEnum | None = None,
    ) -> list[Device]:
        """Return all devices classified as PRINTER along with their joined Printer profile."""
        stmt = (
            select(DeviceORM)
            .options(joinedload(DeviceORM.printer))
            .where(DeviceORM.device_type == DeviceType.PRINTER.value)
            .order_by(desc(DeviceORM.last_seen_at), DeviceORM.ip_address)
        )
        if status is not None:
            stmt = stmt.where(DeviceORM.status == status.value)

        rows = self._session.scalars(stmt).unique().all()
        devices = [_device_orm_to_domain(r) for r in rows]
        if search_query and search_query.strip():
            q = search_query.strip().lower()
            devices = [
                d
                for d in devices
                if q in d.ip_address.lower()
                or (d.hostname and q in d.hostname.lower())
                or (d.model and q in d.model.lower())
                or (d.manufacturer and q in d.manufacturer.lower())
                or (d.printer_info and q in d.printer_info.printer_name.lower())
                or (
                    d.printer_info
                    and d.printer_info.serial_number
                    and q in d.printer_info.serial_number.lower()
                )
            ]
        return devices

    def list_printers_needing_attention(self, limit: int = 10) -> list[Device]:
        """Return printers currently in OFFLINE, ERROR, WARNING, or UNCHECKED state."""
        stmt = (
            select(DeviceORM)
            .options(joinedload(DeviceORM.printer))
            .where(
                DeviceORM.device_type == DeviceType.PRINTER.value,
                DeviceORM.status.in_(
                    [
                        DeviceStatusEnum.ERROR.value,
                        DeviceStatusEnum.OFFLINE.value,
                        DeviceStatusEnum.WARNING.value,
                        DeviceStatusEnum.UNCHECKED.value,
                    ]
                ),
            )
            .order_by(desc(DeviceORM.updated_at))
            .limit(limit)
        )
        rows = self._session.scalars(stmt).unique().all()
        return [_device_orm_to_domain(r) for r in rows]
