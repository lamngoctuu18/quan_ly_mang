"""Printer inventory and detailed 6-tab profile service."""

from __future__ import annotations

from uuid import UUID

from lan_manager.application.dto.schemas import PrinterFullDetailDTO
from lan_manager.domain.enums.system_enums import DeviceStatusEnum
from lan_manager.domain.exceptions import DeviceNotFoundError
from lan_manager.domain.models.entities import Device
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import (
    DeviceRepository,
    DiagnosticRepository,
    PrinterRepository,
    TaskRepository,
)


class PrinterService:
    """Provides specialized printer listing and full 6-tab printer detail aggregation."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()

    def list_printers(
        self,
        search_query: str | None = None,
        status: DeviceStatusEnum | None = None,
    ) -> list[Device]:
        """Return all managed IP printers with their Printer profile attached."""
        with self._db.session_scope() as session:
            repo = PrinterRepository(session)
            return repo.list_printer_devices(search_query=search_query, status=status)

    def get_printer_full_detail(self, device_id: UUID) -> PrinterFullDetailDTO:
        """
        Load complete printer details for the 6 tabs:
        Overview, Connectivity, SNMP Info, Diagnostics, Tasks, and History.
        """
        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            diag_repo = DiagnosticRepository(session)
            task_repo = TaskRepository(session)

            device = dev_repo.get_by_id(device_id)
            if device is None:
                raise DeviceNotFoundError(f"Không tìm thấy máy in/thiết bị với ID {device_id}.")

            history = dev_repo.get_status_history(device_id, limit=50)
            diagnostics = diag_repo.list_by_device(device_id, limit=30)
            tasks = task_repo.list_by_device(device_id, limit=30)

            return PrinterFullDetailDTO(
                device=device,
                status_history=history,
                diagnostics=diagnostics,
                tasks=tasks,
            )
