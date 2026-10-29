"""Step-by-step printer & device Diagnostics page."""

from __future__ import annotations

from uuid import UUID

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.dto.schemas import FullDiagnosticReportDTO
from lan_manager.application.services.device_service import DeviceService
from lan_manager.application.services.diagnostic_service import DiagnosticService
from lan_manager.core.security import UserSessionContext
from lan_manager.domain.enums.system_enums import TaskType
from lan_manager.domain.models.entities import Device
from lan_manager.ui.components.status_badge import StatusBadge, colors_for_table_status
from lan_manager.ui.workers import ServiceWorker


class DiagnosticsPage(QWidget):
    """
    Executes the 5-step read-only diagnostic workflow and displays:
    - Step-by-step probe evidence (IP, Print Ports, SNMP, Windows Spooler, Print Queue).
    - Overall classification (NORMAL / WARNING / ERROR / UNKNOWN).
    - Probable root-cause summary.
    - Quick dispatch buttons to the controlled Remediation Tasks page.
    """

    dispatch_remediation_task = Signal(UUID, str)
    status_message = Signal(str)

    def __init__(
        self,
        device_service: DeviceService,
        diagnostic_service: DiagnosticService,
        user_ctx_provider: callable,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._device_service = device_service
        self._diagnostic_service = diagnostic_service
        self._get_user_ctx = user_ctx_provider
        self._thread_pool = thread_pool
        self._devices: list[Device] = []
        self._current_report: FullDiagnosticReportDTO | None = None
        self._is_running = False
        self._load_worker: ServiceWorker | None = None
        self._diag_worker: ServiceWorker | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        # Header
        header_row = QHBoxLayout()
        title_lbl = QLabel("Chẩn đoán sự cố Máy in & Thiết bị mạng (Read-Only)")
        title_lbl.setProperty("pageTitle", True)
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        self.btn_reload_devices = QPushButton("Tải lại danh sách thiết bị")
        self.btn_reload_devices.clicked.connect(self.load_device_choices)
        header_row.addWidget(self.btn_reload_devices)
        root.addLayout(header_row)

        # Target Selector Card
        selector_card = QFrame()
        selector_card.setProperty("card", True)
        sel_layout = QHBoxLayout(selector_card)
        sel_layout.setContentsMargins(14, 12, 14, 12)
        sel_layout.setSpacing(12)

        sel_layout.addWidget(QLabel("Chọn thiết bị / máy in cần chẩn đoán:"))
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(360)
        sel_layout.addWidget(self.device_combo, 1)

        self.btn_run_diag = QPushButton("Chạy quy trình Chẩn đoán 5 bước")
        self.btn_run_diag.setProperty("primary", True)
        self.btn_run_diag.clicked.connect(self.run_selected_diagnostic)
        sel_layout.addWidget(self.btn_run_diag)
        root.addWidget(selector_card)

        # Outcome Summary Card
        outcome_card = QFrame()
        outcome_card.setProperty("card", True)
        outcome_layout = QVBoxLayout(outcome_card)
        outcome_layout.setContentsMargins(16, 14, 16, 14)
        outcome_layout.setSpacing(8)

        top_outcome = QHBoxLayout()
        lbl_conclusion = QLabel("Kết luận chẩn đoán & Nguyên nhân dự kiến:")
        lbl_conclusion.setProperty("sectionTitle", True)
        top_outcome.addWidget(lbl_conclusion)
        top_outcome.addStretch()
        self.overall_badge = StatusBadge("CHƯA CHẠY CHẨN ĐOÁN", "UNKNOWN")
        top_outcome.addWidget(self.overall_badge)
        outcome_layout.addLayout(top_outcome)

        self.lbl_probable_cause = QLabel(
            "Hãy chọn một thiết bị và bấm 'Chạy quy trình Chẩn đoán 5 bước' để phân tích nguyên nhân."
        )
        self.lbl_probable_cause.setWordWrap(True)
        outcome_layout.addWidget(self.lbl_probable_cause)

        self.recommend_bar = QHBoxLayout()
        self.recommend_bar.setSpacing(8)
        outcome_layout.addLayout(self.recommend_bar)
        root.addWidget(outcome_card)

        # 5-Step Evidence Table
        steps_card = QFrame()
        steps_card.setProperty("card", True)
        steps_layout = QVBoxLayout(steps_card)
        lbl_steps = QLabel("Chi tiết 5 bước kiểm tra kỹ thuật")
        lbl_steps.setProperty("sectionTitle", True)
        steps_layout.addWidget(lbl_steps)

        self.steps_table = QTableWidget(0, 4)
        self.steps_table.setHorizontalHeaderLabels(
            ["Bước", "Hạng mục kiểm tra", " Đánh giá", "Chi tiết kỹ thuật & Bằng chứng"]
        )
        self.steps_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.steps_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.steps_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.steps_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.steps_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.steps_table.setAlternatingRowColors(True)
        steps_layout.addWidget(self.steps_table, 1)
        root.addWidget(steps_card, 1)

    def load_device_choices(self, preselect_id: UUID | None = None) -> None:
        worker = ServiceWorker(
            "Tải thiết bị cho chẩn đoán",
            self._device_service.list_devices,
            limit=500,
        )
        self._load_worker = worker
        worker.signals.result.connect(lambda res: self._populate_combo(res[0], preselect_id))
        self._thread_pool.start(worker)

    def select_and_diagnose(
        self,
        device_id: UUID,
        device_hint: Device | None = None,
        auto_run: bool = True,
    ) -> None:
        """
        Immediately displays the target device in the combobox and initiates 5-step diagnostic.
        Prevents empty combobox delay and auto-starts the workflow.
        """
        matched_idx = -1
        for i in range(self.device_combo.count()):
            val = self.device_combo.itemData(i)
            if val == device_id or str(val) == str(device_id):
                matched_idx = i
                break

        if matched_idx >= 0:
            self.device_combo.setCurrentIndex(matched_idx)
        else:
            # Immediate display without waiting for DB thread
            if device_hint is not None:
                prn = device_hint.printer_info
                name = (
                    prn.printer_name
                    if prn and prn.printer_name
                    else (device_hint.hostname or device_hint.model or device_hint.device_type.label_vi)
                )
                label = f"{device_hint.ip_address} — {name} [{device_hint.status.value}]"
            else:
                label = f"Thiết bị ({device_id})"
            self.device_combo.insertItem(0, label, device_id)
            self.device_combo.setCurrentIndex(0)

        # Execute diagnostic automatically
        if auto_run:
            self.run_selected_diagnostic()

        # In parallel, asynchronously load all devices without disrupting current selection
        self.load_device_choices(preselect_id=device_id)

    def _populate_combo(self, devices: list[Device], preselect_id: UUID | None = None) -> None:
        self._devices = devices
        current_id = preselect_id or self.device_combo.currentData()

        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        selected_idx = 0
        found_target = False

        for idx, dev in enumerate(devices):
            prn = dev.printer_info
            name = (
                prn.printer_name
                if prn and prn.printer_name
                else (dev.hostname or dev.model or dev.device_type.label_vi)
            )
            label = f"{dev.ip_address} — {name} [{dev.status.value}]"
            self.device_combo.addItem(label, dev.id)
            if current_id and (dev.id == current_id or str(dev.id) == str(current_id)):
                selected_idx = idx
                found_target = True

        if current_id and not found_target:
            self.device_combo.insertItem(0, f"Thiết bị ({current_id})", current_id)
            selected_idx = 0

        if self.device_combo.count() > 0:
            self.device_combo.setCurrentIndex(selected_idx)
        self.device_combo.blockSignals(False)

    def run_selected_diagnostic(self) -> None:
        if self._is_running:
            return

        dev_id = self.device_combo.currentData()
        if not dev_id:
            QMessageBox.information(
                self, "Chưa chọn thiết bị", "Vui lòng chọn một thiết bị trong danh sách."
            )
            return

        target_uuid = dev_id if isinstance(dev_id, UUID) else UUID(str(dev_id))

        user_ctx: UserSessionContext = self._get_user_ctx()
        self._is_running = True
        self.btn_run_diag.setEnabled(False)
        self.overall_badge.update_badge("ĐANG CHẨN ĐOÁN...", "RUNNING")
        self.lbl_probable_cause.setText("Hệ thống đang tiến hành kiểm tra 5 bước chuyên sâu...")
        self.steps_table.setRowCount(0)

        # Clear previous recommendation buttons
        while self.recommend_bar.count():
            child = self.recommend_bar.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        self.status_message.emit("Đang thực hiện quy trình chẩn đoán 5 bước...")

        worker = ServiceWorker(
            "Chẩn đoán 5 bước",
            self._diagnostic_service.run_full_diagnostic,
            user_ctx,
            target_uuid,
        )
        self._diag_worker = worker
        worker.signals.result.connect(self._on_diagnostic_finished)
        worker.signals.error.connect(self._on_diagnostic_error)
        worker.signals.finished_task.connect(self._on_diagnostic_completed)
        self._thread_pool.start(worker)

    def _on_diagnostic_completed(self) -> None:
        self._is_running = False
        self.btn_run_diag.setEnabled(True)

    def _on_diagnostic_finished(self, report: FullDiagnosticReportDTO) -> None:
        self._current_report = report
        self.overall_badge.update_badge(
            f"KẾT QUẢ: {report.overall_severity.label_vi.upper()}",
            report.overall_severity.value,
        )
        self.lbl_probable_cause.setText(str(report.probable_cause or ""))

        # Populate recommended task buttons
        while self.recommend_bar.count():
            child = self.recommend_bar.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if report.recommended_tasks:
            lbl_rec = QLabel("Đề xuất tác vụ xử lý:")
            lbl_rec.setStyleSheet("font-weight: 600; color: #1E40AF;")
            self.recommend_bar.addWidget(lbl_rec)

            for task_type in report.recommended_tasks:
                btn = QPushButton(f"Chuyển sang tác vụ: {task_type.value}")
                btn.clicked.connect(
                    lambda _checked=False, tt=task_type: self._trigger_recommended_task(tt)
                )
                self.recommend_bar.addWidget(btn)
            self.recommend_bar.addStretch()

        self.steps_table.setRowCount(len(report.steps))
        for r_idx, step in enumerate(report.steps):
            sev_item = QTableWidgetItem(step.severity.label_vi)
            bg, fg = colors_for_table_status(step.severity.value)
            sev_item.setBackground(bg)
            sev_item.setForeground(fg)

            self.steps_table.setItem(r_idx, 0, QTableWidgetItem(f"Bước {step.step_number}"))
            self.steps_table.setItem(r_idx, 1, QTableWidgetItem(step.title))
            self.steps_table.setItem(r_idx, 2, sev_item)
            self.steps_table.setItem(r_idx, 3, QTableWidgetItem(step.summary))

        self.status_message.emit(
            f"Hoàn tất chẩn đoán {report.device.ip_address}: {report.overall_severity.label_vi}"
        )

    def _trigger_recommended_task(self, task_type: TaskType) -> None:
        if self._current_report is not None:
            self.dispatch_remediation_task.emit(self._current_report.device.id, task_type.value)

    def _on_diagnostic_error(self, message: str, _detail: str) -> None:
        self._is_running = False
        self.btn_run_diag.setEnabled(True)
        self.overall_badge.update_badge("LỖI CHẨN ĐOÁN", "ERROR")
        self.lbl_probable_cause.setText(f"Gặp lỗi khi thực hiện chẩn đoán: {message}")
        QMessageBox.warning(self, "Lỗi khi chạy chẩn đoán", message)
