"""Device repository with DHCP-aware MAC/IP deduplication, filtering, and status history."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from lan_manager.domain.enums.system_enums import DeviceStatusEnum, DeviceType
from lan_manager.domain.models.entities import (
    Device,
    DeviceStatusRecord,
    Printer,
    normalize_mac_address,
    utc_now,
)
from lan_manager.infrastructure.database.models import (
    DeviceORM,
    DeviceStatusHistoryORM,
    PrinterORM,
)


def _printer_orm_to_domain(orm_obj: PrinterORM | None) -> Printer | None:
    if orm_obj is None:
        return None
    return Printer(
        id=orm_obj.id,
        device_id=orm_obj.device_id,
        printer_name=orm_obj.printer_name,
        serial_number=orm_obj.serial_number,
        firmware_version=orm_obj.firmware_version,
        supported_protocols=list(orm_obj.supported_protocols or []),
        snmp_enabled=orm_obj.snmp_enabled,
        metadata=dict(orm_obj.printer_metadata or {}),
        created_at=orm_obj.created_at,
        updated_at=orm_obj.updated_at,
    )


def _device_orm_to_domain(orm_obj: DeviceORM) -> Device:
    return Device(
        id=orm_obj.id,
        hostname=orm_obj.hostname,
        ip_address=str(orm_obj.ip_address),
        mac_address=orm_obj.mac_address,
        device_type=DeviceType(orm_obj.device_type),
        manufacturer=orm_obj.manufacturer,
        model=orm_obj.model,
        location=orm_obj.location,
        status=DeviceStatusEnum(orm_obj.status),
        first_seen_at=orm_obj.first_seen_at,
        last_seen_at=orm_obj.last_seen_at,
        created_at=orm_obj.created_at,
        updated_at=orm_obj.updated_at,
        printer_info=_printer_orm_to_domain(orm_obj.printer),
    )


class DeviceRepository:
    """Handles persistence and deduplication of LAN devices and status history."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def upsert_scanned_device(
        self,
        ip_address: str,
        status: DeviceStatusEnum,
        device_type: DeviceType = DeviceType.UNKNOWN,
        hostname: str | None = None,
        mac_address: str | None = None,
        manufacturer: str | None = None,
        model: str | None = None,
        location: str | None = None,
    ) -> tuple[Device, bool]:
        """
        Insert or update a discovered device while preventing duplicate entries across scans.
        Returns (Device, is_newly_created).

        Deduplication Priority:
        1. Match by normalized MAC address (handles DHCP IP reassignment).
           If another stale record holds the new IP without a conflicting active MAC,
           remove or reassign the stale IP conflict before updating.
        2. Match by IP address.
        3. Insert new Device record.
        """
        now = utc_now()
        norm_mac = normalize_mac_address(mac_address)
        ip_str = str(ip_address).strip()

        existing_by_ip = self._session.scalar(
            select(DeviceORM)
            .options(joinedload(DeviceORM.printer))
            .where(DeviceORM.ip_address == ip_str)
        )

        existing_by_mac: DeviceORM | None = None
        if norm_mac:
            existing_by_mac = self._session.scalar(
                select(DeviceORM)
                .options(joinedload(DeviceORM.printer))
                .where(DeviceORM.mac_address == norm_mac)
            )

        target_orm: DeviceORM | None = None
        is_created = False

        if existing_by_mac is not None:
            target_orm = existing_by_mac
            if existing_by_ip is not None and existing_by_ip.id != existing_by_mac.id:
                # Another record currently occupies ip_str (e.g. scanned earlier without MAC)
                self._session.delete(existing_by_ip)
                self._session.flush()
            target_orm.ip_address = ip_str
        elif existing_by_ip is not None:
            target_orm = existing_by_ip
            if norm_mac:
                target_orm.mac_address = norm_mac

        if target_orm is None:
            is_created = True
            target_orm = DeviceORM(
                ip_address=ip_str,
                mac_address=norm_mac,
                hostname=hostname,
                device_type=device_type.value,
                manufacturer=manufacturer,
                model=model,
                location=location,
                status=status.value,
                first_seen_at=now,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
            self._session.add(target_orm)
        else:
            target_orm.status = status.value
            target_orm.last_seen_at = now
            target_orm.updated_at = now
            if hostname:
                target_orm.hostname = hostname
            if norm_mac:
                target_orm.mac_address = norm_mac
            if manufacturer:
                target_orm.manufacturer = manufacturer
            if model:
                target_orm.model = model
            if location:
                target_orm.location = location
            # Upgrade device_type if previously UNKNOWN and now verified
            if device_type != DeviceType.UNKNOWN and (
                target_orm.device_type == DeviceType.UNKNOWN.value
                or device_type == DeviceType.PRINTER
            ):
                target_orm.device_type = device_type.value

        self._session.flush()
        return _device_orm_to_domain(target_orm), is_created

    def record_status_history(
        self,
        device_id: UUID,
        status: DeviceStatusEnum,
        latency_ms: int | None = None,
        open_ports: list[int] | None = None,
        snmp_reachable: bool = False,
        status_detail: str | None = None,
    ) -> DeviceStatusRecord:
        """Append a connectivity check record to device_status_history."""
        now = utc_now()
        history_orm = DeviceStatusHistoryORM(
            device_id=device_id,
            status=status.value,
            latency_ms=latency_ms,
            open_ports=list(open_ports or []),
            snmp_reachable=snmp_reachable,
            status_detail=status_detail,
            checked_at=now,
        )
        self._session.add(history_orm)
        self._session.flush()
        return DeviceStatusRecord(
            id=history_orm.id,
            device_id=history_orm.device_id,
            status=DeviceStatusEnum(history_orm.status),
            latency_ms=history_orm.latency_ms,
            open_ports=list(history_orm.open_ports or []),
            snmp_reachable=history_orm.snmp_reachable,
            status_detail=history_orm.status_detail,
            checked_at=history_orm.checked_at,
        )

    def get_by_id(self, device_id: UUID) -> Device | None:
        orm_obj = self._session.scalar(
            select(DeviceORM)
            .options(joinedload(DeviceORM.printer))
            .where(DeviceORM.id == device_id)
        )
        return _device_orm_to_domain(orm_obj) if orm_obj else None

    def get_by_ip(self, ip_address: str) -> Device | None:
        orm_obj = self._session.scalar(
            select(DeviceORM)
            .options(joinedload(DeviceORM.printer))
            .where(DeviceORM.ip_address == str(ip_address).strip())
        )
        return _device_orm_to_domain(orm_obj) if orm_obj else None

    def update_device_info(
        self,
        device_id: UUID,
        hostname: str | None = None,
        device_type: DeviceType | None = None,
        manufacturer: str | None = None,
        model: str | None = None,
        location: str | None = None,
        status: DeviceStatusEnum | None = None,
    ) -> Device | None:
        orm_obj = self._session.scalar(
            select(DeviceORM)
            .options(joinedload(DeviceORM.printer))
            .where(DeviceORM.id == device_id)
        )
        if orm_obj is None:
            return None
        if hostname is not None:
            orm_obj.hostname = hostname
        if device_type is not None:
            orm_obj.device_type = device_type.value
        if manufacturer is not None:
            orm_obj.manufacturer = manufacturer
        if model is not None:
            orm_obj.model = model
        if location is not None:
            orm_obj.location = location
        if status is not None:
            orm_obj.status = status.value
            orm_obj.last_seen_at = utc_now()
        orm_obj.updated_at = utc_now()
        self._session.flush()
        return _device_orm_to_domain(orm_obj)

    def list_devices(
        self,
        search_query: str | None = None,
        device_type: DeviceType | None = None,
        status: DeviceStatusEnum | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[Device], int]:
        """List devices with search, type/status filtering, and pagination."""
        stmt = select(DeviceORM).options(joinedload(DeviceORM.printer))
        count_stmt = select(func.count(DeviceORM.id))

        filters = []
        if device_type is not None:
            filters.append(DeviceORM.device_type == device_type.value)
        if status is not None:
            filters.append(DeviceORM.status == status.value)
        if search_query and search_query.strip():
            q = f"%{search_query.strip()}%"
            filters.append(
                or_(
                    DeviceORM.hostname.ilike(q),
                    DeviceORM.mac_address.ilike(q),
                    DeviceORM.manufacturer.ilike(q),
                    DeviceORM.model.ilike(q),
                    DeviceORM.location.ilike(q),
                )
            )

        for cond in filters:
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)

        # If search query looks like an IP prefix/address, filter in Python if INET ilike is dialect-sensitive
        total_count = int(self._session.scalar(count_stmt) or 0)
        stmt = (
            stmt.order_by(desc(DeviceORM.last_seen_at), DeviceORM.ip_address)
            .offset(offset)
            .limit(limit)
        )
        rows = self._session.scalars(stmt).unique().all()
        devices = [_device_orm_to_domain(row) for row in rows]

        if search_query and search_query.strip() and not devices:
            # Fallback match on stringified IP address
            q_lower = search_query.strip().lower()
            all_stmt = select(DeviceORM).options(joinedload(DeviceORM.printer))
            for cond in filters[:-1]:
                all_stmt = all_stmt.where(cond)
            all_rows = self._session.scalars(all_stmt).unique().all()
            matched = [
                _device_orm_to_domain(r)
                for r in all_rows
                if q_lower in str(r.ip_address).lower()
                or (r.hostname and q_lower in r.hostname.lower())
                or (r.mac_address and q_lower in r.mac_address.lower())
                or (r.manufacturer and q_lower in r.manufacturer.lower())
                or (r.model and q_lower in r.model.lower())
            ]
            return matched[offset : offset + limit], len(matched)

        return devices, total_count

    def get_status_history(self, device_id: UUID, limit: int = 50) -> list[DeviceStatusRecord]:
        stmt = (
            select(DeviceStatusHistoryORM)
            .where(DeviceStatusHistoryORM.device_id == device_id)
            .order_by(desc(DeviceStatusHistoryORM.checked_at))
            .limit(limit)
        )
        rows = self._session.scalars(stmt).all()
        return [
            DeviceStatusRecord(
                id=r.id,
                device_id=r.device_id,
                status=DeviceStatusEnum(r.status),
                latency_ms=r.latency_ms,
                open_ports=list(r.open_ports or []),
                snmp_reachable=r.snmp_reachable,
                status_detail=r.status_detail,
                checked_at=r.checked_at,
            )
            for r in rows
        ]

    def get_dashboard_counts(self) -> dict[str, int]:
        """Compute real-time KPI counts directly from PostgreSQL."""
        total_devices = int(self._session.scalar(select(func.count(DeviceORM.id))) or 0)
        total_printers = int(
            self._session.scalar(
                select(func.count(DeviceORM.id)).where(
                    DeviceORM.device_type == DeviceType.PRINTER.value
                )
            )
            or 0
        )
        online_devices = int(
            self._session.scalar(
                select(func.count(DeviceORM.id)).where(
                    DeviceORM.status == DeviceStatusEnum.ONLINE.value
                )
            )
            or 0
        )
        offline_devices = int(
            self._session.scalar(
                select(func.count(DeviceORM.id)).where(
                    DeviceORM.status.in_(
                        [DeviceStatusEnum.OFFLINE.value, DeviceStatusEnum.ERROR.value]
                    )
                )
            )
            or 0
        )
        warning_devices = int(
            self._session.scalar(
                select(func.count(DeviceORM.id)).where(
                    DeviceORM.status == DeviceStatusEnum.WARNING.value
                )
            )
            or 0
        )
        return {
            "total_devices": total_devices,
            "total_printers": total_printers,
            "online_devices": online_devices,
            "offline_devices": offline_devices,
            "warning_devices": warning_devices,
        }
