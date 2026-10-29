"""LAN discovery orchestration service with deduplication and audit logging."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from lan_manager.application.dto.schemas import ScanSummaryDTO
from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.core.security import UserSessionContext, require_role
from lan_manager.domain.enums.system_enums import AuditResult, DeviceType, RoleType
from lan_manager.domain.models.entities import Device
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import (
    AuditRepository,
    DeviceRepository,
    PrinterRepository,
)
from lan_manager.infrastructure.network.scanner import (
    ControlledNetworkScanner,
    DiscoveredHostInfo,
)

logger = get_logger(__name__)


class ScanService:
    """Coordinates controlled LAN scanning, device/printer deduplication, and persistence."""

    def __init__(
        self,
        config: AppConfig | None = None,
        db_manager: DatabaseManager | None = None,
        scanner: ControlledNetworkScanner | None = None,
    ) -> None:
        self._config = config or get_config()
        self._db = db_manager or get_db_manager(self._config)
        self._scanner = scanner or ControlledNetworkScanner(self._config)

    def scan_and_persist(
        self,
        user_ctx: UserSessionContext,
        target_cidr: str,
        enable_snmp: bool | None = None,
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[int, int, DiscoveredHostInfo | None], None] | None = None,
    ) -> ScanSummaryDTO:
        """
        Validate permissions and subnet, scan hosts with rate/concurrency limits,
        upsert discovered devices and printers into PostgreSQL, and write an audit log.
        """
        require_role(user_ctx, RoleType.TECHNICIAN, "Quét khám phá mạng LAN")

        hosts = self._config.validate_scan_target(target_cidr)
        start_time = time.perf_counter()

        discovered_hosts = self._scanner.scan_cidr(
            target_cidr=target_cidr,
            enable_snmp=enable_snmp,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
        )
        duration = round(time.perf_counter() - start_time, 2)
        was_cancelled = bool(cancel_event and cancel_event.is_set())

        new_count = 0
        updated_count = 0
        printers_count = 0
        persisted_devices: list[Device] = []

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            prn_repo = PrinterRepository(session)
            audit_repo = AuditRepository(session)

            for host in discovered_hosts:
                device, is_created = dev_repo.upsert_scanned_device(
                    ip_address=host.ip_address,
                    status=host.status,
                    device_type=host.device_type,
                    hostname=host.hostname,
                    mac_address=host.mac_address,
                    manufacturer=host.manufacturer,
                    model=host.model,
                    location=host.location,
                )
                if is_created:
                    new_count += 1
                else:
                    updated_count += 1

                dev_repo.record_status_history(
                    device_id=device.id,
                    status=host.status,
                    latency_ms=host.latency_ms,
                    open_ports=host.open_ports,
                    snmp_reachable=host.snmp_profile.reachable,
                    status_detail=host.classification_reason,
                )

                if host.device_type == DeviceType.PRINTER:
                    printers_count += 1
                    prn_name = (
                        host.snmp_profile.printer_name
                        or host.model
                        or host.hostname
                        or f"Printer {host.ip_address}"
                    )
                    prn_repo.upsert_printer(
                        device_id=device.id,
                        printer_name=prn_name,
                        serial_number=host.snmp_profile.serial_number,
                        firmware_version=host.snmp_profile.firmware_version,
                        supported_protocols=host.supported_protocols,
                        snmp_enabled=host.snmp_profile.reachable,
                        metadata=host.metadata,
                    )
                    refreshed = dev_repo.get_by_id(device.id)
                    if refreshed:
                        device = refreshed

                persisted_devices.append(device)

            audit_repo.append(
                action="SCAN_LAN_SUBNET",
                target_type="SUBNET",
                target_id=target_cidr.strip(),
                result=AuditResult.SUCCESS,
                username=user_ctx.username,
                user_id=user_ctx.user_id,
                metadata={
                    "total_probed": len(hosts),
                    "alive_count": len(discovered_hosts),
                    "new_devices": new_count,
                    "updated_devices": updated_count,
                    "printers_found": printers_count,
                    "cancelled": was_cancelled,
                    "duration_sec": duration,
                },
            )

        return ScanSummaryDTO(
            target_cidr=target_cidr.strip(),
            total_hosts_probed=len(hosts),
            alive_count=len(discovered_hosts),
            new_devices_count=new_count,
            updated_devices_count=updated_count,
            printers_found=printers_count,
            cancelled=was_cancelled,
            duration_sec=duration,
            devices=persisted_devices,
        )
