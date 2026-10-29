"""Unit tests for DiagnosticService, RemoteTaskService, RBAC authorization, and HMAC anti-replay."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from lan_manager.application.services.audit_service import AuditService
from lan_manager.application.services.diagnostic_service import DiagnosticService
from lan_manager.application.services.remote_task_service import RemoteTaskService
from lan_manager.core.security import sign_agent_payload
from lan_manager.domain.enums.system_enums import (
    DeviceStatusEnum,
    DeviceType,
    DiagnosticSeverity,
    RoleType,
    TaskStatus,
    TaskType,
)
from lan_manager.domain.exceptions import PermissionDeniedError, TaskNotAllowedError
from lan_manager.infrastructure.database.repositories import DeviceRepository
from lan_manager.infrastructure.network.port_checker import PortProbeSummary
from lan_manager.infrastructure.network.snmp_client import SNMPDeviceProfile
from lan_manager.infrastructure.printer.windows_printer_adapter import (
    PrintQueueStatus,
    SpoolerStatus,
)
from lan_manager.infrastructure.remote.agent_client import AgentRequestVerifier
from lan_manager.infrastructure.remote.task_executor import (
    RemoteExecutionProvider,
    TaskExecutionOutput,
)
from tests.conftest import create_isolated_test_db_manager


class DummyExecutor(RemoteExecutionProvider):
    """Mock remote execution provider for unit testing RemoteTaskService."""

    def execute(self, device, task_type, parameters=None) -> TaskExecutionOutput:
        return TaskExecutionOutput(
            succeeded=True,
            summary=f"Executed {task_type.value} on {device.ip_address}",
            telemetry={"is_online": True, "latency_ms": 2, "open_ports": [9100]},
        )


class TestServicesRBACAndDiagnostics(unittest.TestCase):
    """Tests 5-step diagnostics, RBAC enforcement, task confirmation, post-verification, and agent security."""

    def setUp(self) -> None:
        self.config, self.db = create_isolated_test_db_manager()
        with self.db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            self.device, _ = dev_repo.upsert_scanned_device(
                ip_address="192.168.1.50",
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.PRINTER,
                hostname="PRN-FINANCE",
            )

    def tearDown(self) -> None:
        self.db.dispose()

    @patch("lan_manager.application.services.diagnostic_service.icmp_ping")
    @patch("lan_manager.application.services.diagnostic_service.probe_multiple_ports")
    def test_diagnostic_service_detects_stopped_spooler_and_snmp_alert(
        self, mock_probe: MagicMock, mock_ping: MagicMock
    ) -> None:
        mock_ping.return_value = (True, 2)
        mock_probe.return_value = PortProbeSummary(
            ip_address="192.168.1.50",
            open_ports=[9100, 631],
            best_latency_ms=2,
            supported_protocols=["RAW_9100", "IPP_631"],
        )

        mock_snmp = MagicMock()
        mock_snmp.query_device_profile.return_value = SNMPDeviceProfile(
            reachable=True,
            printer_status_text="idle",
            detected_alerts=["noPaper (Hết giấy)"],
        )

        mock_win = MagicMock()
        mock_win.check_spooler_service.return_value = SpoolerStatus(
            supported=True,
            is_running=False,
            state_name="STOPPED",
            detail="Dịch vụ Print Spooler đang dừng.",
        )
        mock_win.inspect_queue_for_device.return_value = PrintQueueStatus(
            matched_queue_name="HP Finance",
            total_jobs=2,
            stuck_jobs=1,
            detail="Có 1 lệnh in bị kẹt.",
        )

        diag_service = DiagnosticService(
            config=self.config,
            db_manager=self.db,
            snmp_client=mock_snmp,
            win_printer_adapter=mock_win,
        )
        tech_ctx = AuditService.create_default_session(role=RoleType.TECHNICIAN, username="tech01")
        report = diag_service.run_full_diagnostic(tech_ctx, self.device.id)

        self.assertEqual(report.overall_severity, DiagnosticSeverity.ERROR)
        self.assertEqual(len(report.steps), 5)
        self.assertIn(TaskType.RESTART_PRINT_SPOOLER, report.recommended_tasks)
        self.assertIn(TaskType.CLEAR_STUCK_PRINT_JOBS, report.recommended_tasks)

    def test_rbac_blocks_viewer_and_technician_from_high_privilege_tasks(self) -> None:
        mock_win = MagicMock()
        mock_win.check_spooler_service.return_value = SpoolerStatus(
            supported=True, is_running=True, state_name="RUNNING"
        )
        task_service = RemoteTaskService(
            config=self.config,
            db_manager=self.db,
            executor=DummyExecutor(),
            win_printer_adapter=mock_win,
        )

        viewer_ctx = AuditService.create_default_session(role=RoleType.VIEWER, username="viewer01")
        with self.assertRaises(PermissionDeniedError):
            task_service.execute_task(
                viewer_ctx,
                self.device.id,
                TaskType.RECHECK_CONNECTIVITY,
            )

        tech_ctx = AuditService.create_default_session(role=RoleType.TECHNICIAN, username="tech01")
        with self.assertRaises(PermissionDeniedError):
            task_service.execute_task(
                tech_ctx,
                self.device.id,
                TaskType.RESTART_PRINT_SPOOLER,
                confirmed_by_user=True,
            )

        # Operator has sufficient privileges for RESTART_PRINT_SPOOLER, but must confirm!
        operator_ctx = AuditService.create_default_session(role=RoleType.OPERATOR, username="op01")
        with self.assertRaises(TaskNotAllowedError):
            task_service.execute_task(
                operator_ctx,
                self.device.id,
                TaskType.RESTART_PRINT_SPOOLER,
                confirmed_by_user=False,
            )

        completed = task_service.execute_task(
            operator_ctx,
            self.device.id,
            TaskType.RESTART_PRINT_SPOOLER,
            confirmed_by_user=True,
        )
        self.assertEqual(completed.status, TaskStatus.SUCCEEDED)

    def test_reject_arbitrary_task_not_in_allowlist(self) -> None:
        task_service = RemoteTaskService(
            config=self.config,
            db_manager=self.db,
            executor=DummyExecutor(),
        )
        admin_ctx = AuditService.create_default_session(role=RoleType.ADMIN, username="admin")
        with self.assertRaises(TaskNotAllowedError):
            task_service.execute_task(admin_ctx, self.device.id, "RUN_ARBITRARY_SHELL_CMD")

    def test_remote_agent_hmac_and_anti_replay_protection(self) -> None:
        secret = "enterprise_agent_shared_secret_key_2026"
        verifier = AgentRequestVerifier(shared_secret=secret, max_skew_seconds=60)

        envelope = sign_agent_payload(
            shared_secret=secret,
            task_type=TaskType.RESTART_PRINT_SPOOLER.value,
            target_ip="192.168.1.50",
            parameters={"use_remote_agent": True},
        )
        verified_type, _params = verifier.validate_envelope(envelope)
        self.assertEqual(verified_type, TaskType.RESTART_PRINT_SPOOLER)

        # Replay of the exact same nonce must be rejected!
        from lan_manager.domain.exceptions import RemoteExecutionError

        with self.assertRaises(RemoteExecutionError):
            verifier.validate_envelope(envelope)

        # Shell command parameter injection must be rejected!
        bad_envelope = sign_agent_payload(
            shared_secret=secret,
            task_type=TaskType.RESTART_PRINT_SPOOLER.value,
            target_ip="192.168.1.50",
            parameters={"powershell": "Remove-Item -Recurse C:\\"},
        )
        with self.assertRaises(TaskNotAllowedError):
            verifier.validate_envelope(bad_envelope)


if __name__ == "__main__":
    unittest.main()
