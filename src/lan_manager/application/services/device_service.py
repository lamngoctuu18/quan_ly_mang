"""Device management and Dashboard aggregation service."""

from __future__ import annotations

from uuid import UUID

from lan_manager.application.dto.schemas import DashboardSummaryDTO
from lan_manager.core.logging_config import get_logger
from lan_manager.core.security import UserSessionContext, require_role
from lan_manager.domain.enums.system_enums import (
    AuditResult,
    DeviceStatusEnum,
    DeviceType,
    RoleType,
)
from lan_manager.domain.exceptions import DeviceNotFoundError
from lan_manager.domain.models.entities import Device, DeviceStatusRecord
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import (
    AuditRepository,
    DeviceRepository,
    DiagnosticRepository,
    PrinterRepository,
    TaskRepository,
)

logger = get_logger(__name__)


class DeviceService:
    """Provides device inventory querying, metadata updates, and real-time Dashboard metrics."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()

    def get_dashboard_summary(self) -> DashboardSummaryDTO:
        """
        Fetch real-time operational statistics and recent lists directly from PostgreSQL.
        Never generates fake or demo metrics.
        """
        ok, status_msg = self._db.check_connection()
        if not ok:
            return DashboardSummaryDTO(
                db_connected=False,
                db_status_message=status_msg,
            )

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            prn_repo = PrinterRepository(session)
            diag_repo = DiagnosticRepository(session)
            task_repo = TaskRepository(session)

            counts = dev_repo.get_dashboard_counts()
            open_issues = diag_repo.count_open_issues()
            recent_diags = diag_repo.list_recent_issues(limit=8)
            printers_attention = prn_repo.list_printers_needing_attention(limit=8)
            recent_tasks = task_repo.list_recent_tasks(limit=8)

            issues_with_dev = [(diag, dev_repo.get_by_id(diag.device_id)) for diag in recent_diags]
            tasks_with_dev = [
                (task, dev_repo.get_by_id(task.target_device_id)) for task in recent_tasks
            ]

            return DashboardSummaryDTO(
                db_connected=True,
                db_status_message=status_msg,
                total_devices=counts["total_devices"],
                total_printers=counts["total_printers"],
                online_devices=counts["online_devices"],
                offline_devices=counts["offline_devices"],
                open_issues_count=open_issues,
                recent_issues=issues_with_dev,
                printers_needing_check=printers_attention,
                recent_tasks=tasks_with_dev,
            )

    def list_devices(
        self,
        search_query: str | None = None,
        device_type: DeviceType | None = None,
        status: DeviceStatusEnum | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[Device], int]:
        """List managed devices with search, filter, and pagination."""
        with self._db.session_scope() as session:
            repo = DeviceRepository(session)
            return repo.list_devices(
                search_query=search_query,
                device_type=device_type,
                status=status,
                offset=offset,
                limit=limit,
            )

    def get_device_by_id(self, device_id: UUID) -> Device:
        with self._db.session_scope() as session:
            repo = DeviceRepository(session)
            device = repo.get_by_id(device_id)
            if device is None:
                raise DeviceNotFoundError(f"Không tìm thấy thiết bị với ID {device_id}.")
            return device

    def get_device_status_history(
        self, device_id: UUID, limit: int = 50
    ) -> list[DeviceStatusRecord]:
        with self._db.session_scope() as session:
            repo = DeviceRepository(session)
            return repo.get_status_history(device_id=device_id, limit=limit)

    def update_device_details(
        self,
        user_ctx: UserSessionContext,
        device_id: UUID,
        hostname: str | None = None,
        device_type: DeviceType | None = None,
        manufacturer: str | None = None,
        model: str | None = None,
        location: str | None = None,
    ) -> Device:
        """Update administrative metadata for a device with RBAC enforcement and audit logging."""
        require_role(user_ctx, RoleType.TECHNICIAN, "Cập nhật thông tin thiết bị")

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            prn_repo = PrinterRepository(session)
            audit_repo = AuditRepository(session)

            updated = dev_repo.update_device_info(
                device_id=device_id,
                hostname=hostname,
                device_type=device_type,
                manufacturer=manufacturer,
                model=model,
                location=location,
            )
            if updated is None:
                raise DeviceNotFoundError(f"Không tìm thấy thiết bị ID {device_id}.")

            if updated.device_type == DeviceType.PRINTER and updated.printer_info is None:
                prn_repo.upsert_printer(
                    device_id=updated.id,
                    printer_name=updated.model
                    or updated.hostname
                    or f"Printer {updated.ip_address}",
                )
                updated = dev_repo.get_by_id(device_id) or updated

            audit_repo.append(
                action="UPDATE_DEVICE_METADATA",
                target_type="DEVICE",
                target_id=str(device_id),
                result=AuditResult.SUCCESS,
                username=user_ctx.username,
                user_id=user_ctx.user_id,
                metadata={
                    "ip_address": updated.ip_address,
                    "device_type": updated.device_type.value,
                    "location": updated.location,
                },
            )
            return updated
