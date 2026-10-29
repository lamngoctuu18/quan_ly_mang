"""Printer and device connectivity monitoring service."""

from __future__ import annotations

from uuid import UUID

from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.domain.enums.system_enums import DeviceType
from lan_manager.domain.exceptions import DeviceNotFoundError
from lan_manager.domain.models.entities import Device
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import DeviceRepository, PrinterRepository
from lan_manager.infrastructure.network.scanner import ControlledNetworkScanner

logger = get_logger(__name__)


class MonitoringService:
    """
    Executes active health checks on tracked devices and printers, updating their live status,
    SNMP telemetry, and device_status_history.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        db_manager: DatabaseManager | None = None,
        scanner: ControlledNetworkScanner | None = None,
    ) -> None:
        self._config = config or get_config()
        self._db = db_manager or get_db_manager(self._config)
        self._scanner = scanner or ControlledNetworkScanner(self._config)

    def check_device_now(self, device_id: UUID) -> Device:
        """Probe a single tracked device/printer and persist its updated status and history."""
        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            device = dev_repo.get_by_id(device_id)
            if device is None:
                raise DeviceNotFoundError(f"Không tìm thấy thiết bị với ID {device_id}.")
            ip_address = device.ip_address

        host_info = self._scanner.inspect_single_host(ip_address, enable_snmp=True)

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            prn_repo = PrinterRepository(session)

            current = dev_repo.get_by_id(device_id)
            if current is None:
                raise DeviceNotFoundError(f"Không tìm thấy thiết bị với ID {device_id}.")

            effective_type = (
                host_info.device_type
                if host_info.device_type != DeviceType.UNKNOWN
                else current.device_type
            )
            updated = dev_repo.update_device_info(
                device_id=device_id,
                hostname=host_info.hostname or current.hostname,
                device_type=effective_type,
                manufacturer=host_info.manufacturer or current.manufacturer,
                model=host_info.model or current.model,
                location=host_info.location or current.location,
                status=host_info.status,
            )
            assert updated is not None

            dev_repo.record_status_history(
                device_id=device_id,
                status=host_info.status,
                latency_ms=host_info.latency_ms,
                open_ports=host_info.open_ports,
                snmp_reachable=host_info.snmp_profile.reachable,
                status_detail=host_info.classification_reason
                or f"Kiểm tra trạng thái: {host_info.status.value}",
            )

            if effective_type == DeviceType.PRINTER:
                prn_name = (
                    host_info.snmp_profile.printer_name
                    or updated.model
                    or updated.hostname
                    or f"Printer {updated.ip_address}"
                )
                prn_repo.upsert_printer(
                    device_id=device_id,
                    printer_name=prn_name,
                    serial_number=host_info.snmp_profile.serial_number,
                    firmware_version=host_info.snmp_profile.firmware_version,
                    supported_protocols=host_info.supported_protocols,
                    snmp_enabled=host_info.snmp_profile.reachable,
                    metadata=host_info.metadata,
                )
                updated = dev_repo.get_by_id(device_id) or updated

            return updated
