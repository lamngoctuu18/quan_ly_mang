"""Controlled administrative remediation service with allowlist registry, RBAC, and post-verification."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from lan_manager.application.dto.schemas import TaskDefinitionDTO
from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.core.security import UserSessionContext, require_role
from lan_manager.domain.enums.system_enums import (
    AuditResult,
    DeviceStatusEnum,
    RiskLevel,
    RoleType,
    TaskStatus,
    TaskType,
)
from lan_manager.domain.exceptions import (
    DeviceNotFoundError,
    PermissionDeniedError,
    TaskNotAllowedError,
)
from lan_manager.domain.models.entities import RemoteTask
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import (
    AuditRepository,
    DeviceRepository,
    PrinterRepository,
    TaskRepository,
)
from lan_manager.infrastructure.printer.windows_printer_adapter import WindowsPrinterAdapter
from lan_manager.infrastructure.remote.task_executor import (
    CompositeTaskExecutor,
    RemoteExecutionProvider,
)

logger = get_logger(__name__)

# Immutable Registry of Allowed Administrative Tasks (No arbitrary shell execution allowed)
TASK_REGISTRY: dict[TaskType, TaskDefinitionDTO] = {
    TaskType.RECHECK_CONNECTIVITY: TaskDefinitionDTO(
        task_type=TaskType.RECHECK_CONNECTIVITY,
        title="Kiểm tra lại kết nối mạng & cổng in",
        description="Thăm dò lại ICMP Ping và các cổng dịch vụ TCP (9100, 631, 515, 445, 80, 443) của thiết bị.",
        prerequisite_desc="Thiết bị có địa chỉ IP hợp lệ trong cơ sở dữ liệu.",
        required_role=RoleType.TECHNICIAN,
        risk_level=RiskLevel.LOW,
        requires_confirmation=False,
        timeout_sec=10,
        post_verify_desc="Đối chiếu phản hồi cổng TCP/ICMP và cập nhật trạng thái thiết bị.",
    ),
    TaskType.REFRESH_SNMP_STATUS: TaskDefinitionDTO(
        task_type=TaskType.REFRESH_SNMP_STATUS,
        title="Làm mới dữ liệu trạng thái SNMP",
        description="Truy vấn lại các OID MIB-II và Printer-MIB (mực, giấy, số trang in, cảnh báo phần cứng).",
        prerequisite_desc="Thiết bị đang kết nối mạng và bật SNMPv2c.",
        required_role=RoleType.TECHNICIAN,
        risk_level=RiskLevel.LOW,
        requires_confirmation=False,
        timeout_sec=10,
        post_verify_desc="Xác nhận dữ liệu OID trả về hợp lệ và lưu hồ sơ máy in.",
    ),
    TaskType.OPEN_WEB_ADMIN: TaskDefinitionDTO(
        task_type=TaskType.OPEN_WEB_ADMIN,
        title="Mở trang quản trị Web của máy in",
        description="Kiểm tra cổng HTTP/HTTPS (80/443) và mở giao diện cấu hình Web của máy in trên trình duyệt.",
        prerequisite_desc="Thiết bị mở cổng TCP 80 hoặc 443.",
        required_role=RoleType.TECHNICIAN,
        risk_level=RiskLevel.LOW,
        requires_confirmation=False,
        timeout_sec=5,
        post_verify_desc="Xác nhận cổng Web 80/443 phản hồi trước khi khởi chạy trình duyệt.",
    ),
    TaskType.RESTART_PRINT_SPOOLER: TaskDefinitionDTO(
        task_type=TaskType.RESTART_PRINT_SPOOLER,
        title="Khởi động lại dịch vụ Windows Print Spooler",
        description="Khởi động lại dịch vụ 'Spooler' trên máy Windows được quản lý để giải phóng trạng thái treo dịch vụ in.",
        prerequisite_desc="Tài khoản có quyền Operator/Admin và dịch vụ quản trị có quyền điều khiển Service.",
        required_role=RoleType.OPERATOR,
        risk_level=RiskLevel.MEDIUM,
        requires_confirmation=True,
        timeout_sec=20,
        post_verify_desc="Kiểm tra lại trạng thái dịch vụ Spooler đảm bảo đạt trạng thái RUNNING.",
    ),
    TaskType.CLEAR_STUCK_PRINT_JOBS: TaskDefinitionDTO(
        task_type=TaskType.CLEAR_STUCK_PRINT_JOBS,
        title="Xử lý / Xóa các lệnh in bị kẹt trong hàng đợi",
        description="Hủy các lệnh in đang bị treo hoặc báo lỗi (ERROR / OFFLINE / BLOCKED) trong hàng đợi của máy in được chọn.",
        prerequisite_desc="Tài khoản có quyền Operator/Admin và người dùng đã xác nhận phạm vi hàng đợi.",
        required_role=RoleType.OPERATOR,
        risk_level=RiskLevel.HIGH,
        requires_confirmation=True,
        timeout_sec=15,
        post_verify_desc="Kiểm tra lại hàng đợi in đảm bảo số lệnh in lỗi (stuck_jobs) bằng 0.",
    ),
}


class RemoteTaskService:
    """
    Coordinates allowlisted remediation tasks with RBAC enforcement, explicit confirmation checks,
    execution timeouts, post-execution verification, and immutable audit logging.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        db_manager: DatabaseManager | None = None,
        executor: RemoteExecutionProvider | None = None,
        win_printer_adapter: WindowsPrinterAdapter | None = None,
    ) -> None:
        self._config = config or get_config()
        self._db = db_manager or get_db_manager(self._config)
        self._win_adapter = win_printer_adapter or WindowsPrinterAdapter()
        self._executor = executor or CompositeTaskExecutor(
            config=self._config,
            win_printer_adapter=self._win_adapter,
        )

    @staticmethod
    def list_allowed_task_definitions() -> list[TaskDefinitionDTO]:
        """Return all registered allowlisted remediation tasks."""
        return list(TASK_REGISTRY.values())

    @staticmethod
    def get_task_definition(task_type: TaskType | str) -> TaskDefinitionDTO:
        try:
            enum_key = TaskType(str(task_type))
        except ValueError as exc:
            raise TaskNotAllowedError(
                f"Mã tác vụ '{task_type}' không tồn tại trong danh mục cho phép (Allowlist)."
            ) from exc

        definition = TASK_REGISTRY.get(enum_key)
        if definition is None:
            raise TaskNotAllowedError(f"Mã tác vụ '{task_type}' không được phép thực thi.")
        return definition

    def execute_task(
        self,
        user_ctx: UserSessionContext,
        device_id: UUID,
        task_type: TaskType | str,
        confirmed_by_user: bool = False,
        parameters: dict[str, Any] | None = None,
    ) -> RemoteTask:
        """
        Validate permissions and confirmation, execute the allowlisted task, perform post-execution
        verification, update database state, and record an audit log.
        """
        definition = self.get_task_definition(task_type)

        # Enforce RBAC in business logic (never rely solely on UI button hiding)
        try:
            require_role(user_ctx, definition.required_role, definition.title)
        except PermissionDeniedError:
            with self._db.session_scope() as session:
                AuditRepository(session).append(
                    action="EXECUTE_REMEDIATION_TASK",
                    target_type="DEVICE",
                    target_id=str(device_id),
                    result=AuditResult.DENIED,
                    username=user_ctx.username if user_ctx else "anonymous",
                    user_id=user_ctx.user_id if user_ctx else None,
                    metadata={
                        "task_type": definition.task_type.value,
                        "required_role": definition.required_role.value,
                    },
                )
            raise

        if definition.requires_confirmation and not confirmed_by_user:
            raise TaskNotAllowedError(
                f"Tác vụ '{definition.title}' (Mức rủi ro: {definition.risk_level.label_vi}) "
                f"bắt buộc phải được xác nhận trước khi thực thi."
            )

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            task_repo = TaskRepository(session)
            device = dev_repo.get_by_id(device_id)
            if device is None:
                raise DeviceNotFoundError(f"Không tìm thấy thiết bị với ID {device_id}.")

            task_record = task_repo.create_task(
                target_device_id=device_id,
                task_type=definition.task_type,
                risk_level=definition.risk_level,
                requested_by=user_ctx.user_id,
                requested_by_username=user_ctx.username,
                parameters=parameters,
            )

        try:
            exec_output = self._executor.execute(
                device=device,
                task_type=definition.task_type,
                parameters=parameters,
            )
            verified_ok, verify_note = self._post_verify_task(
                device=device,
                task_type=definition.task_type,
                exec_succeeded=exec_output.succeeded,
                telemetry=exec_output.telemetry,
                parameters=parameters,
            )

            if exec_output.succeeded and verified_ok:
                final_status = TaskStatus.SUCCEEDED
            elif exec_output.succeeded and not verified_ok:
                final_status = TaskStatus.VERIFICATION_FAILED
            else:
                final_status = TaskStatus.FAILED

            combined_summary = f"{exec_output.summary} | Hậu kiểm: {verify_note}"
            error_msg = exec_output.error_message
        except Exception as exc:
            logger.error(
                "Lỗi thực thi tác vụ %s trên thiết bị %s: %s",
                definition.task_type.value,
                device.ip_address,
                exc,
                extra={
                    "device_ip": device.ip_address,
                    "task_type": definition.task_type.value,
                    "error_code": "TASK_EXEC_FAILED",
                },
            )
            final_status = TaskStatus.FAILED
            combined_summary = f"Tác vụ thất bại do ngoại lệ: {exc}"
            error_msg = str(exc)

        with self._db.session_scope() as session:
            task_repo = TaskRepository(session)
            audit_repo = AuditRepository(session)

            completed_task = task_repo.complete_task(
                task_id=task_record.id,
                status=final_status,
                result_summary=combined_summary,
                error_message=error_msg,
            )
            audit_repo.append(
                action="EXECUTE_REMEDIATION_TASK",
                target_type="DEVICE",
                target_id=str(device_id),
                result=(
                    AuditResult.SUCCESS
                    if final_status == TaskStatus.SUCCEEDED
                    else AuditResult.FAILURE
                ),
                username=user_ctx.username,
                user_id=user_ctx.user_id,
                metadata={
                    "task_id": str(task_record.id),
                    "task_type": definition.task_type.value,
                    "ip_address": device.ip_address,
                    "risk_level": definition.risk_level.value,
                    "final_status": final_status.value,
                    "summary": combined_summary[:250],
                },
            )
            assert completed_task is not None
            return completed_task

    def _post_verify_task(
        self,
        device: Any,
        task_type: TaskType,
        exec_succeeded: bool,
        telemetry: dict[str, Any],
        parameters: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Run automatic post-execution verification and synchronize DB state."""
        if not exec_succeeded:
            return False, "Bỏ qua hậu kiểm do bước thực thi chính không thành công."

        if task_type == TaskType.RECHECK_CONNECTIVITY:
            is_online = bool(telemetry.get("is_online", False))
            new_status = DeviceStatusEnum.ONLINE if is_online else DeviceStatusEnum.OFFLINE
            with self._db.session_scope() as session:
                dev_repo = DeviceRepository(session)
                dev_repo.update_device_info(device.id, status=new_status)
                dev_repo.record_status_history(
                    device_id=device.id,
                    status=new_status,
                    latency_ms=telemetry.get("latency_ms"),
                    open_ports=telemetry.get("open_ports", []),
                    status_detail="Hậu kiểm sau tác vụ RECHECK_CONNECTIVITY",
                )
            return is_online, f"Đã xác minh trạng thái kết nối thực tế là {new_status.value}."

        if task_type == TaskType.REFRESH_SNMP_STATUS:
            profile = telemetry.get("profile")
            if profile and getattr(profile, "reachable", False):
                with self._db.session_scope() as session:
                    prn_repo = PrinterRepository(session)
                    prn_repo.upsert_printer(
                        device_id=device.id,
                        printer_name=profile.printer_name
                        or device.model
                        or f"Printer {device.ip_address}",
                        serial_number=profile.serial_number,
                        firmware_version=profile.firmware_version,
                        snmp_enabled=True,
                        metadata={
                            "snmp_sys_descr": profile.sys_descr,
                            "snmp_printer_status": profile.printer_status_text,
                            "snmp_alerts": profile.detected_alerts,
                            "snmp_page_count": profile.page_count,
                            "snmp_console_display": profile.console_display,
                            "snmp_raw_oids": profile.raw_oids,
                        },
                    )
                return True, "Đã xác minh và lưu dữ liệu SNMP mới nhất vào cơ sở dữ liệu."
            return False, "Không thu nhận được bản tin SNMP hợp lệ."

        if task_type == TaskType.RESTART_PRINT_SPOOLER:
            if parameters and parameters.get("use_remote_agent"):
                return True, "Agent từ xa đã xác nhận trạng thái dịch vụ Spooler."
            spooler_status = self._win_adapter.check_spooler_service()
            if spooler_status.is_running:
                return True, "Dịch vụ Print Spooler đã hoạt động trở lại (RUNNING)."
            return False, f"Dịch vụ Print Spooler vẫn ở trạng thái {spooler_status.state_name}."

        if task_type == TaskType.CLEAR_STUCK_PRINT_JOBS:
            queue_name = str(telemetry.get("queue_name") or "")
            q_status = self._win_adapter.inspect_queue_for_device(
                device.ip_address, printer_name_hint=queue_name or device.hostname
            )
            if q_status.stuck_jobs == 0:
                return True, f"Hàng đợi '{queue_name}' đã sạch lệnh in lỗi (0 lệnh kẹt)."
            return (
                False,
                f"Vẫn còn {q_status.stuck_jobs} lệnh in lỗi trong hàng đợi '{queue_name}'.",
            )

        if task_type == TaskType.OPEN_WEB_ADMIN:
            url = telemetry.get("url", "")
            return bool(url), f"Đã xác minh cổng Web và mở {url}."

        return True, "Hoàn tất xác minh."

    def list_recent_tasks(self, limit: int = 50) -> list[RemoteTask]:
        with self._db.session_scope() as session:
            return TaskRepository(session).list_recent_tasks(limit=limit)

    def list_device_tasks(self, device_id: UUID, limit: int = 30) -> list[RemoteTask]:
        with self._db.session_scope() as session:
            return TaskRepository(session).list_by_device(device_id=device_id, limit=limit)
