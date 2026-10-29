"""Unit tests for UI navigation, immediate device selection, and auto diagnostic execution."""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication

from lan_manager.application.dto.schemas import FullDiagnosticReportDTO
from lan_manager.core.security import UserSessionContext
from lan_manager.domain.enums.system_enums import (
    DeviceStatusEnum,
    DeviceType,
    DiagnosticSeverity,
    RoleType,
)
from lan_manager.domain.models.entities import Device, DiagnosticResult, Printer
from lan_manager.ui.diagnostics_page import DiagnosticsPage
from lan_manager.ui.tasks_page import TasksPage


def _get_qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_diagnostics_page_immediate_selection_and_auto_run() -> None:
    _get_qapp()
    thread_pool = QThreadPool()

    test_id = uuid4()
    printer_info = Printer(printer_name="Xerox B210 WorkCentre")
    device_hint = Device(
        id=test_id,
        ip_address="192.168.1.55",
        hostname="xerox-prn",
        device_type=DeviceType.PRINTER,
        status=DeviceStatusEnum.ERROR,
        printer_info=printer_info,
    )

    mock_report = FullDiagnosticReportDTO(
        device=device_hint,
        saved_result=DiagnosticResult(device_id=test_id),
        overall_severity=DiagnosticSeverity.ERROR,
        probable_cause="Print Spooler is stopped",
        steps=[],
        recommended_tasks=[],
    )

    mock_dev_svc = MagicMock()
    mock_dev_svc.list_devices.return_value = ([device_hint], 1)
    mock_diag_svc = MagicMock()
    mock_diag_svc.run_full_diagnostic.return_value = mock_report
    user_ctx = UserSessionContext(
        user_id=uuid4(), username="admin", full_name="Administrator", role=RoleType.ADMIN
    )

    page = DiagnosticsPage(
        device_service=mock_dev_svc,
        diagnostic_service=mock_diag_svc,
        user_ctx_provider=lambda: user_ctx,
        thread_pool=thread_pool,
    )

    # Call select_and_diagnose
    page.select_and_diagnose(test_id, device_hint=device_hint, auto_run=True)

    # 1. Verification: Combo box must immediately contain the target device and be selected
    assert page.device_combo.count() >= 1
    assert page.device_combo.currentData() == test_id
    assert "192.168.1.55" in page.device_combo.currentText()
    assert "Xerox B210 WorkCentre" in page.device_combo.currentText()

    # 2. Wait for background thread to finish cleanly and process events
    thread_pool.waitForDone(2000)
    QApplication.processEvents()

    # 3. Verification: Results populated
    assert page._is_running is False
    assert page.btn_run_diag.isEnabled() is True
    assert "KẾT QUẢ: LỖI" in page.overall_badge.text()
    assert "Print Spooler is stopped" in page.lbl_probable_cause.text()


def test_diagnostics_page_populate_combo_preserves_selection() -> None:
    _get_qapp()
    thread_pool = QThreadPool()

    mock_dev_svc = MagicMock()
    mock_diag_svc = MagicMock()
    user_ctx = UserSessionContext(
        user_id=uuid4(), username="admin", full_name="Administrator", role=RoleType.ADMIN
    )

    page = DiagnosticsPage(
        device_service=mock_dev_svc,
        diagnostic_service=mock_diag_svc,
        user_ctx_provider=lambda: user_ctx,
        thread_pool=thread_pool,
    )

    target_id = uuid4()
    other_id = uuid4()

    dev1 = Device(id=other_id, ip_address="192.168.1.1", status=DeviceStatusEnum.ONLINE)
    dev2 = Device(id=target_id, ip_address="192.168.1.55", status=DeviceStatusEnum.ERROR)

    # Simulate populate combo with preselect_id
    page._populate_combo([dev1, dev2], preselect_id=target_id)

    assert page.device_combo.count() == 2
    assert page.device_combo.currentData() == target_id
    assert "192.168.1.55" in page.device_combo.currentText()


def test_tasks_page_immediate_selection_with_device_hint() -> None:
    _get_qapp()
    thread_pool = QThreadPool()

    mock_dev_svc = MagicMock()
    mock_dev_svc.list_devices.return_value = ([], 0)
    mock_task_svc = MagicMock()
    mock_task_svc.list_allowed_task_definitions.return_value = []
    mock_task_svc.list_recent_tasks.return_value = []
    user_ctx = UserSessionContext(
        user_id=uuid4(), username="admin", full_name="Administrator", role=RoleType.ADMIN
    )

    page = TasksPage(
        device_service=mock_dev_svc,
        task_service=mock_task_svc,
        user_ctx_provider=lambda: user_ctx,
        thread_pool=thread_pool,
    )

    test_id = uuid4()
    device_hint = Device(
        id=test_id,
        ip_address="192.168.1.52",
        hostname="brother-pc",
        device_type=DeviceType.PRINTER,
        status=DeviceStatusEnum.ERROR,
    )

    page.refresh_page_data(preselect_device_id=test_id, device_hint=device_hint)

    # Immediately visible without waiting for worker
    assert page.device_combo.count() >= 1
    assert page.device_combo.currentData() == test_id
    assert "192.168.1.52" in page.device_combo.currentText()
