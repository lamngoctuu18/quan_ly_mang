"""Step-by-step printer & device diagnostic service (strictly read-only)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from lan_manager.application.dto.schemas import (
    DiagnosticStepDTO,
    FullDiagnosticReportDTO,
)
from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.core.security import UserSessionContext, require_role
from lan_manager.domain.enums.system_enums import (
    AuditResult,
    DeviceStatusEnum,
    DeviceType,
    DiagnosticCheckType,
    DiagnosticSeverity,
    RoleType,
    TaskType,
)
from lan_manager.domain.exceptions import DeviceNotFoundError
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import (
    AuditRepository,
    DeviceRepository,
    DiagnosticRepository,
)
from lan_manager.infrastructure.network.port_checker import (
    DEFAULT_DISCOVERY_PORTS,
    PRINTER_PORTS,
    icmp_ping,
    probe_multiple_ports,
)
from lan_manager.infrastructure.network.snmp_client import SNMPClient
from lan_manager.infrastructure.printer.windows_printer_adapter import WindowsPrinterAdapter

logger = get_logger(__name__)


class DiagnosticService:
    """
    Executes multi-step read-only diagnostics on a device/printer to identify probable root causes.
    Separated strictly from remediation execution.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        db_manager: DatabaseManager | None = None,
        snmp_client: SNMPClient | None = None,
        win_printer_adapter: WindowsPrinterAdapter | None = None,
    ) -> None:
        self._config = config or get_config()
        self._db = db_manager or get_db_manager(self._config)
        self._snmp = snmp_client or SNMPClient(
            community=self._config.snmp_community,
            port=self._config.snmp_port,
            timeout_sec=self._config.snmp_timeout_sec,
            retries=self._config.snmp_retries,
        )
        self._win_adapter = win_printer_adapter or WindowsPrinterAdapter()

    def run_full_diagnostic(
        self,
        user_ctx: UserSessionContext,
        device_id: UUID,
    ) -> FullDiagnosticReportDTO:
        """
        Execute 5-step diagnostic workflow on device_id:
        1. IP & Network Reachability (ICMP + TCP)
        2. Print Service Ports (9100 RAW, 631 IPP, 515 LPD)
        3. SNMP Telemetry & Hardware Alerts
        4. Windows Print Spooler Service Status
        5. Windows Print Queue Inspection
        """
        require_role(user_ctx, RoleType.TECHNICIAN, "Chẩn đoán sự cố thiết bị/máy in")

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            device = dev_repo.get_by_id(device_id)
            if device is None:
                raise DeviceNotFoundError(f"Không tìm thấy thiết bị với ID {device_id}.")

        ip_addr = device.ip_address
        steps: list[DiagnosticStepDTO] = []
        probable_causes: list[str] = []
        recommended_tasks: list[TaskType] = []

        # Step 1: IP & Network Reachability
        ping_ok, ping_ms = icmp_ping(ip_addr, timeout_ms=self._config.icmp_timeout_ms)
        port_summary = probe_multiple_ports(
            ip_addr,
            ports=DEFAULT_DISCOVERY_PORTS,
            timeout_sec=self._config.tcp_probe_timeout_sec,
        )
        is_reachable = ping_ok or len(port_summary.open_ports) > 0
        best_latency = port_summary.best_latency_ms or ping_ms

        if is_reachable:
            step1_sev = DiagnosticSeverity.NORMAL
            step1_msg = (
                f"Thiết bị {ip_addr} có phản hồi mạng (Độ trễ: {best_latency or 1} ms, "
                f"ICMP={'OK' if ping_ok else 'Chặn/Timeout'}, Cổng mở={port_summary.open_ports})."
            )
        else:
            step1_sev = DiagnosticSeverity.ERROR
            step1_msg = f"Không thể kết nối tới {ip_addr} qua cả ICMP và các cổng dịch vụ TCP."
            probable_causes.append(
                "Thiết bị mất nguồn, tuột cáp mạng LAN, sai địa chỉ IP/VLAN hoặc bị đổi IP do DHCP."
            )
            recommended_tasks.append(TaskType.RECHECK_CONNECTIVITY)

        steps.append(
            DiagnosticStepDTO(
                step_number=1,
                step_code="CONNECTIVITY",
                title="Kiểm tra kết nối IP & Mạng LAN",
                severity=step1_sev,
                summary=step1_msg,
                evidence={
                    "ping_ok": ping_ok,
                    "latency_ms": best_latency,
                    "open_ports": port_summary.open_ports,
                },
            )
        )

        # Step 2: Print Service Ports
        open_print_ports = [p for p in port_summary.open_ports if p in PRINTER_PORTS]
        if open_print_ports:
            step2_sev = DiagnosticSeverity.NORMAL
            proto_names = [PRINTER_PORTS[p] for p in open_print_ports]
            step2_msg = f"Cổng dịch vụ in đang mở sẵn sàng: {', '.join(proto_names)}."
        elif not is_reachable:
            step2_sev = DiagnosticSeverity.ERROR
            step2_msg = "Không thể kiểm tra cổng in do thiết bị đang mất kết nối mạng."
        elif device.device_type == DeviceType.PRINTER:
            step2_sev = DiagnosticSeverity.ERROR
            step2_msg = (
                "Thiết bị phản hồi mạng nhưng tất cả cổng in chuẩn (9100, 631, 515) đều đóng."
            )
            probable_causes.append(
                "Dịch vụ nhận lệnh in (RAW 9100 / IPP 631 / LPD 515) trên máy in bị tắt hoặc treo card mạng in."
            )
            if any(p in port_summary.open_ports for p in (80, 443)):
                recommended_tasks.append(TaskType.OPEN_WEB_ADMIN)
        else:
            step2_sev = DiagnosticSeverity.NORMAL
            step2_msg = (
                "Thiết bị không mở cổng máy in trực tiếp (Phù hợp với máy trạm / thiết bị mạng)."
            )

        steps.append(
            DiagnosticStepDTO(
                step_number=2,
                step_code="PRINT_PORTS",
                title="Kiểm tra cổng dịch vụ in (9100 / 631 / 515)",
                severity=step2_sev,
                summary=step2_msg,
                evidence={"open_print_ports": open_print_ports},
            )
        )

        # Step 3: SNMP Status & Hardware Alerts
        snmp_profile = self._snmp.query_device_profile(ip_addr) if is_reachable else None
        if snmp_profile and snmp_profile.reachable:
            if snmp_profile.detected_alerts:
                critical = any(
                    any(k in a for k in ("Hết giấy", "Hết mực", "Kẹt giấy", "Offline", "Nắp máy"))
                    for a in snmp_profile.detected_alerts
                )
                step3_sev = DiagnosticSeverity.ERROR if critical else DiagnosticSeverity.WARNING
                alerts_str = "; ".join(snmp_profile.detected_alerts)
                step3_msg = f"Phát hiện cảnh báo phần cứng qua SNMP: {alerts_str}."
                probable_causes.append(f"Cảnh báo trực tiếp từ máy in: {alerts_str}.")
                recommended_tasks.append(TaskType.REFRESH_SNMP_STATUS)
            else:
                step3_sev = DiagnosticSeverity.NORMAL
                step3_msg = (
                    f"SNMP hoạt động tốt (Trạng thái: {snmp_profile.printer_status_text or 'Sẵn sàng'}, "
                    f"Màn hình máy in: {snmp_profile.console_display or 'Bình thường'})."
                )
        else:
            step3_sev = DiagnosticSeverity.UNKNOWN if is_reachable else DiagnosticSeverity.WARNING
            step3_msg = (
                "Thiết bị không phản hồi SNMP v2c (Có thể SNMP đã tắt hoặc khác Community String)."
            )

        steps.append(
            DiagnosticStepDTO(
                step_number=3,
                step_code="SNMP_STATUS",
                title="Kiểm tra thông tin & cảnh báo SNMP",
                severity=step3_sev,
                summary=step3_msg,
                evidence={
                    "snmp_reachable": bool(snmp_profile and snmp_profile.reachable),
                    "alerts": snmp_profile.detected_alerts if snmp_profile else [],
                    "printer_status": snmp_profile.printer_status_text if snmp_profile else None,
                },
            )
        )

        # Step 4: Windows Print Spooler Service
        spooler = self._win_adapter.check_spooler_service()
        if not spooler.supported:
            step4_sev = DiagnosticSeverity.UNKNOWN
            step4_msg = spooler.detail
        elif spooler.is_running:
            step4_sev = DiagnosticSeverity.NORMAL
            step4_msg = spooler.detail
        else:
            step4_sev = DiagnosticSeverity.ERROR
            step4_msg = spooler.detail
            probable_causes.append(
                "Dịch vụ Windows Print Spooler trên máy quản lý đang bị dừng hoặc treo."
            )
            recommended_tasks.append(TaskType.RESTART_PRINT_SPOOLER)

        steps.append(
            DiagnosticStepDTO(
                step_number=4,
                step_code="WINDOWS_SPOOLER",
                title="Kiểm tra dịch vụ Windows Print Spooler",
                severity=step4_sev,
                summary=step4_msg,
                evidence={
                    "supported": spooler.supported,
                    "is_running": spooler.is_running,
                    "state_name": spooler.state_name,
                },
            )
        )

        # Step 5: Windows Print Queue Inspection
        printer_hint = (
            device.printer_info.printer_name
            if device.printer_info and device.printer_info.printer_name
            else device.hostname
        )
        queue_info = self._win_adapter.inspect_queue_for_device(
            ip_addr, printer_name_hint=printer_hint
        )
        if queue_info.stuck_jobs > 0:
            step5_sev = DiagnosticSeverity.ERROR
            step5_msg = queue_info.detail
            probable_causes.append(
                f"Có {queue_info.stuck_jobs} lệnh in bị lỗi/kẹt đang chặn hàng đợi '{queue_info.matched_queue_name}'."
            )
            recommended_tasks.append(TaskType.CLEAR_STUCK_PRINT_JOBS)
            recommended_tasks.append(TaskType.RESTART_PRINT_SPOOLER)
        elif queue_info.total_jobs > 0:
            step5_sev = DiagnosticSeverity.WARNING
            step5_msg = queue_info.detail
        else:
            step5_sev = DiagnosticSeverity.NORMAL
            step5_msg = queue_info.detail

        steps.append(
            DiagnosticStepDTO(
                step_number=5,
                step_code="PRINT_QUEUE",
                title="Kiểm tra hàng đợi lệnh in (Print Queue)",
                severity=step5_sev,
                summary=step5_msg,
                evidence={
                    "matched_queue_name": queue_info.matched_queue_name,
                    "total_jobs": queue_info.total_jobs,
                    "stuck_jobs": queue_info.stuck_jobs,
                },
            )
        )

        # Overall classification
        severities = [s.severity for s in steps]
        if DiagnosticSeverity.ERROR in severities:
            overall = DiagnosticSeverity.ERROR
        elif DiagnosticSeverity.WARNING in severities:
            overall = DiagnosticSeverity.WARNING
        elif all(s == DiagnosticSeverity.UNKNOWN for s in severities):
            overall = DiagnosticSeverity.UNKNOWN
        else:
            overall = DiagnosticSeverity.NORMAL

        if not probable_causes:
            probable_cause_summary = (
                "Không phát hiện bất thường. Kết nối mạng, cổng in và dịch vụ in đều ổn định."
            )
            recommended_tasks.append(TaskType.RECHECK_CONNECTIVITY)
        else:
            probable_cause_summary = " | ".join(probable_causes)

        # Deduplicate recommended tasks while preserving order
        unique_recommendations: list[TaskType] = []
        for t in recommended_tasks:
            if t not in unique_recommendations:
                unique_recommendations.append(t)

        diag_payload: dict[str, Any] = {
            "steps": [
                {
                    "step_number": s.step_number,
                    "step_code": s.step_code,
                    "title": s.title,
                    "severity": s.severity.value,
                    "summary": s.summary,
                    "evidence": s.evidence,
                }
                for s in steps
            ],
            "recommended_tasks": [t.value for t in unique_recommendations],
        }

        new_device_status = (
            DeviceStatusEnum.OFFLINE
            if not is_reachable
            else (
                DeviceStatusEnum.ERROR
                if overall == DiagnosticSeverity.ERROR
                else (
                    DeviceStatusEnum.WARNING
                    if overall == DiagnosticSeverity.WARNING
                    else DeviceStatusEnum.ONLINE
                )
            )
        )

        with self._db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            diag_repo = DiagnosticRepository(session)
            audit_repo = AuditRepository(session)

            updated_device = dev_repo.update_device_info(
                device_id=device_id,
                status=new_device_status,
            )
            saved_result = diag_repo.create(
                device_id=device_id,
                check_type=DiagnosticCheckType.FULL_DIAGNOSTIC,
                severity=overall,
                probable_cause=probable_cause_summary[:500],
                diagnostic_data=diag_payload,
                performed_by=user_ctx.user_id,
            )
            audit_repo.append(
                action="RUN_DIAGNOSTIC",
                target_type="DEVICE",
                target_id=str(device_id),
                result=AuditResult.SUCCESS,
                username=user_ctx.username,
                user_id=user_ctx.user_id,
                metadata={
                    "ip_address": ip_addr,
                    "overall_severity": overall.value,
                    "probable_cause": probable_cause_summary[:200],
                },
            )

        return FullDiagnosticReportDTO(
            device=updated_device or device,
            saved_result=saved_result,
            overall_severity=overall,
            probable_cause=probable_cause_summary,
            steps=steps,
            recommended_tasks=unique_recommendations,
        )
