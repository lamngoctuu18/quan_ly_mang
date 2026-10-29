"""Abstraction for executing allowlisted remediation tasks locally or via remote agent."""

from __future__ import annotations

import ipaddress
import webbrowser
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from lan_manager.core.config import AppConfig, get_config
from lan_manager.domain.enums.system_enums import TaskType
from lan_manager.domain.models.entities import Device
from lan_manager.infrastructure.network.port_checker import (
    DEFAULT_DISCOVERY_PORTS,
    check_tcp_port,
    icmp_ping,
    probe_multiple_ports,
)
from lan_manager.infrastructure.network.snmp_client import SNMPClient
from lan_manager.infrastructure.printer.windows_printer_adapter import WindowsPrinterAdapter
from lan_manager.infrastructure.remote.agent_client import AuthenticatedAgentClient


@dataclass
class TaskExecutionOutput:
    """Standardized output returned by a task execution provider."""

    succeeded: bool
    summary: str
    error_message: str | None = None
    telemetry: dict[str, Any] = field(default_factory=dict)


class RemoteExecutionProvider(ABC):
    """Abstract interface decoupling business logic from specific execution protocols."""

    @abstractmethod
    def execute(
        self,
        device: Device,
        task_type: TaskType,
        parameters: dict[str, Any] | None = None,
    ) -> TaskExecutionOutput:
        """Execute an allowlisted task against a target device."""


class CompositeTaskExecutor(RemoteExecutionProvider):
    """
    Executes allowlisted administrative tasks using the appropriate adapter:
    - Network/SNMP adapters for connectivity and SNMP refresh tasks.
    - Validated browser launcher for printer web administration console.
    - WindowsPrinterAdapter (local) or AuthenticatedAgentClient (remote mode) for Spooler/Queue tasks.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        snmp_client: SNMPClient | None = None,
        win_printer_adapter: WindowsPrinterAdapter | None = None,
        agent_client: AuthenticatedAgentClient | None = None,
    ) -> None:
        self._config = config or get_config()
        self._snmp_client = snmp_client or SNMPClient(
            community=self._config.snmp_community,
            port=self._config.snmp_port,
            timeout_sec=self._config.snmp_timeout_sec,
            retries=self._config.snmp_retries,
        )
        self._win_adapter = win_printer_adapter or WindowsPrinterAdapter()
        self._agent_client = agent_client or AuthenticatedAgentClient(self._config)

    def execute(
        self,
        device: Device,
        task_type: TaskType,
        parameters: dict[str, Any] | None = None,
    ) -> TaskExecutionOutput:
        params = parameters or {}
        validated_ip = str(ipaddress.ip_address(device.ip_address))

        if task_type == TaskType.RECHECK_CONNECTIVITY:
            ping_ok, ping_ms = icmp_ping(validated_ip, timeout_ms=self._config.icmp_timeout_ms)
            port_summary = probe_multiple_ports(
                validated_ip,
                ports=DEFAULT_DISCOVERY_PORTS,
                timeout_sec=self._config.tcp_probe_timeout_sec,
            )
            is_online = ping_ok or len(port_summary.open_ports) > 0
            latency = port_summary.best_latency_ms or ping_ms
            if is_online:
                ports_str = ", ".join(str(p) for p in port_summary.open_ports) or "ICMP only"
                return TaskExecutionOutput(
                    succeeded=True,
                    summary=f"Thiết bị {validated_ip} phản hồi kết nối (Độ trễ: {latency or 1} ms, Cổng mở: {ports_str}).",
                    telemetry={
                        "is_online": True,
                        "latency_ms": latency,
                        "open_ports": port_summary.open_ports,
                        "supported_protocols": port_summary.supported_protocols,
                    },
                )
            return TaskExecutionOutput(
                succeeded=False,
                summary=f"Thiết bị {validated_ip} không phản hồi ICMP và mọi cổng TCP dịch vụ đều đóng.",
                error_message="Host unreachable / all probed TCP ports closed.",
                telemetry={"is_online": False, "open_ports": []},
            )

        if task_type == TaskType.REFRESH_SNMP_STATUS:
            profile = self._snmp_client.query_device_profile(validated_ip)
            if not profile.reachable:
                return TaskExecutionOutput(
                    succeeded=False,
                    summary=f"Thiết bị {validated_ip} không phản hồi truy vấn SNMP (UDP {self._config.snmp_port}).",
                    error_message="SNMP timeout or disabled on target device.",
                    telemetry={"snmp_reachable": False},
                )
            alerts_str = (
                ", ".join(profile.detected_alerts)
                if profile.detected_alerts
                else "Không có cảnh báo"
            )
            return TaskExecutionOutput(
                succeeded=True,
                summary=(
                    f"Đã cập nhật SNMP từ {validated_ip}: trạng thái={profile.printer_status_text or 'online'}, "
                    f"số trang={profile.page_count if profile.page_count is not None else 'N/A'}, cảnh báo={alerts_str}."
                ),
                telemetry={
                    "snmp_reachable": True,
                    "profile": profile,
                },
            )

        if task_type == TaskType.OPEN_WEB_ADMIN:
            https_open, _ = check_tcp_port(validated_ip, 443, timeout_sec=1.5)
            http_open, _ = check_tcp_port(validated_ip, 80, timeout_sec=1.5)
            if not https_open and not http_open:
                return TaskExecutionOutput(
                    succeeded=False,
                    summary=f"Thiết bị {validated_ip} không mở cổng quản trị Web (80/443).",
                    error_message="Web management ports 80 and 443 are closed.",
                )
            scheme = "https" if https_open else "http"
            url = f"{scheme}://{validated_ip}/"
            if not params.get("dry_run", False):
                webbrowser.open(url, new=2)
            return TaskExecutionOutput(
                succeeded=True,
                summary=f"Đã mở trang quản trị Web máy in tại {url}.",
                telemetry={"url": url},
            )

        if task_type == TaskType.RESTART_PRINT_SPOOLER:
            use_remote_agent = bool(params.get("use_remote_agent", False))
            if use_remote_agent:
                resp = self._agent_client.execute_remote_task(
                    target_ip=validated_ip,
                    task_type=TaskType.RESTART_PRINT_SPOOLER,
                    parameters=params,
                )
                ok = bool(resp.get("succeeded", False))
                return TaskExecutionOutput(
                    succeeded=ok,
                    summary=str(resp.get("summary") or "Đã gửi lệnh tới Remote Agent."),
                    error_message=resp.get("error_message"),
                    telemetry=resp,
                )

            ok, msg = self._win_adapter.restart_spooler_service()
            return TaskExecutionOutput(
                succeeded=ok,
                summary=msg,
                error_message=None if ok else msg,
            )

        if task_type == TaskType.CLEAR_STUCK_PRINT_JOBS:
            queue_name = str(params.get("queue_name") or "").strip()
            if not queue_name:
                q_status = self._win_adapter.inspect_queue_for_device(
                    validated_ip,
                    printer_name_hint=device.printer_info.printer_name
                    if device.printer_info
                    else device.hostname,
                )
                queue_name = q_status.matched_queue_name or ""
            if not queue_name:
                return TaskExecutionOutput(
                    succeeded=False,
                    summary=f"Không tìm thấy hàng đợi in Windows tương ứng với thiết bị {validated_ip}.",
                    error_message="No matching Windows print queue found.",
                )
            ok, msg, deleted_count = self._win_adapter.clear_stuck_print_jobs(queue_name)
            return TaskExecutionOutput(
                succeeded=ok,
                summary=msg,
                error_message=None if ok else msg,
                telemetry={"queue_name": queue_name, "deleted_jobs": deleted_count},
            )

        return TaskExecutionOutput(
            succeeded=False,
            summary=f"Loại tác vụ chưa được hỗ trợ: {task_type}",
            error_message="Unsupported task type",
        )
