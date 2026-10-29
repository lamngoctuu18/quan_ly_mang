"""Controlled Remediation Tasks page with allowlist registry, confirmation dialog, and post-verification."""

from __future__ import annotations

from uuid import UUID

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
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

from lan_manager.application.dto.schemas import TaskDefinitionDTO
from lan_manager.application.services.device_service import DeviceService
from lan_manager.application.services.remote_task_service import RemoteTaskService
from lan_manager.core.security import UserSessionContext
from lan_manager.domain.models.entities import Device, RemoteTask
from lan_manager.ui.components.confirm_dialog import TaskConfirmationDialog
from lan_manager.ui.components.status_badge import StatusBadge, colors_for_table_status
from lan_manager.ui.workers import ServiceWorker


class TasksPage(QWidget):
    """
    Allows authorized operators to execute allowlisted remediation tasks,
    inspect task prerequisites/risk levels, confirm high-risk actions, and verify post-execution results.
    """

    status_message = Signal(str)

    def __init__(
        self,
        device_service: DeviceService,
        task_service: RemoteTaskService,
        user_ctx_provider: callable,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._device_service = device_service
        self._task_service = task_service
        self._get_user_ctx = user_ctx_provider
        self._thread_pool = thread_pool

        self._devices: list[Device] = []
        self._tasks_worker: ServiceWorker | None = None
        self._task_defs: list[TaskDefinitionDTO] = (
            self._task_service.list_allowed_task_definitions()
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        # Header
        header_row = QHBoxLayout()
        title_lbl = QLabel("Tác vụ quản trị & Sửa lỗi có kiểm soát (Allowlist Registry)")
        title_lbl.setProperty("pageTitle", True)
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        self.btn_refresh = QPushButton("Làm mới lịch sử tác vụ")
        self.btn_refresh.clicked.connect(self.refresh_page_data)
        header_row.addWidget(self.btn_refresh)
        root.addLayout(header_row)

        # Task Execution Form Card
        exec_card = QFrame()
        exec_card.setProperty("card", True)
        exec_layout = QVBoxLayout(exec_card)
        exec_layout.setContentsMargins(16, 14, 16, 14)
        exec_layout.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)

        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(360)
        form.addRow("Thiết bị / Máy tính đích:", self.device_combo)

        self.task_combo = QComboBox()
        for td in self._task_defs:
            self.task_combo.addItem(f"{td.title} [{td.task_type.value}]", td.task_type.value)
        self.task_combo.currentIndexChanged.connect(self._on_task_type_changed)
        form.addRow("Tác vụ trong Allowlist:", self.task_combo)

        self.lbl_task_desc = QLabel("")
        self.lbl_task_desc.setWordWrap(True)
        form.addRow("Mô tả nghiệp vụ:", self.lbl_task_desc)

        self.lbl_task_prereq = QLabel("")
        self.lbl_task_prereq.setWordWrap(True)
        form.addRow("Điều kiện tiên quyết:", self.lbl_task_prereq)

        meta_row = QHBoxLayout()
        self.badge_role = StatusBadge("", "UNKNOWN")
        self.badge_risk = StatusBadge("", "LOW")
        self.lbl_verify_desc = QLabel("")
        meta_row.addWidget(self.badge_role)
        meta_row.addWidget(self.badge_risk)
        meta_row.addWidget(self.lbl_verify_desc, 1)
        form.addRow("Yêu cầu & Hậu kiểm:", meta_row)

        self.chk_remote_agent = QCheckBox(
            "Gửi qua Authenticated Remote Agent (HTTPS + HMAC) thay vì thực thi cục bộ"
        )
        form.addRow("Chế độ thực thi:", self.chk_remote_agent)

        exec_layout.addLayout(form)

        action_bar = QHBoxLayout()
        action_bar.addStretch()
        self.btn_execute_task = QPushButton("Thực thi tác vụ đã chọn")
        self.btn_execute_task.setProperty("primary", True)
        self.btn_execute_task.clicked.connect(self.execute_selected_task)
        action_bar.addWidget(self.btn_execute_task)
        exec_layout.addLayout(action_bar)

        root.addWidget(exec_card)

        # Task Execution History Table
        hist_card = QFrame()
        hist_card.setProperty("card", True)
        hist_layout = QVBoxLayout(hist_card)
        lbl_hist = QLabel("Lịch sử thực thi và kết quả xác minh sau sửa lỗi")
        lbl_hist.setProperty("sectionTitle", True)
        hist_layout.addWidget(lbl_hist)

        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(
            [
                "Thời gian",
                "Thiết bị đích",
                "Loại tác vụ",
                "Mức rủi ro",
                "Người thực hiện",
                "Trạng thái & Kết quả hậu kiểm",
            ]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setAlternatingRowColors(True)
        hist_layout.addWidget(self.history_table, 1)
        root.addWidget(hist_card, 1)

        self._on_task_type_changed()

    def _on_task_type_changed(self) -> None:
        task_key = str(self.task_combo.currentData() or "")
        if not task_key:
            return
        td = self._task_service.get_task_definition(task_key)
        self.lbl_task_desc.setText(td.description)
        self.lbl_task_prereq.setText(td.prerequisite_desc)
        self.badge_role.update_badge(f"Quyền tối thiểu: {td.required_role.value}", "NORMAL")
        self.badge_risk.update_badge(f"Rủi ro: {td.risk_level.label_vi}", td.risk_level.value)
        self.lbl_verify_desc.setText(f"Hậu kiểm: {td.post_verify_desc}")

    def refresh_page_data(
        self,
        preselect_device_id: UUID | None = None,
        preselect_task_key: str | None = None,
        device_hint: Device | None = None,
    ) -> None:
        if preselect_task_key:
            idx = self.task_combo.findData(preselect_task_key)
            if idx >= 0:
                self.task_combo.setCurrentIndex(idx)

        if preselect_device_id:
            existing_idx = -1
            for i in range(self.device_combo.count()):
                val = self.device_combo.itemData(i)
                if val == preselect_device_id or str(val) == str(preselect_device_id):
                    existing_idx = i
                    break
            if existing_idx >= 0:
                self.device_combo.setCurrentIndex(existing_idx)
            elif device_hint is not None:
                label = f"{device_hint.ip_address} — {device_hint.hostname or device_hint.model or device_hint.device_type.label_vi}"
                self.device_combo.insertItem(0, label, device_hint.id)
                self.device_combo.setCurrentIndex(0)

        def _fetch_all() -> tuple[list[Device], list[RemoteTask]]:
            devices, _ = self._device_service.list_devices(limit=500)
            tasks = self._task_service.list_recent_tasks(limit=50)
            return devices, tasks

        worker = ServiceWorker("Tải dữ liệu tác vụ", _fetch_all)
        self._tasks_worker = worker
        worker.signals.result.connect(
            lambda res: self._populate_data(res[0], res[1], preselect_device_id)
        )
        self._thread_pool.start(worker)

    def _populate_data(
        self,
        devices: list[Device],
        tasks: list[RemoteTask],
        preselect_device_id: UUID | None = None,
    ) -> None:
        self._devices = devices
        dev_map = {d.id: d for d in devices}
        current_id = preselect_device_id or self.device_combo.currentData()

        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        sel_idx = 0
        found_target = False
        for idx, d in enumerate(devices):
            self.device_combo.addItem(
                f"{d.ip_address} — {d.hostname or d.model or d.device_type.label_vi}", d.id
            )
            if current_id and (d.id == current_id or str(d.id) == str(current_id)):
                sel_idx = idx
                found_target = True

        if current_id and not found_target:
            self.device_combo.insertItem(0, f"Thiết bị ({current_id})", current_id)
            sel_idx = 0

        if self.device_combo.count() > 0:
            self.device_combo.setCurrentIndex(sel_idx)
        self.device_combo.blockSignals(False)

        self.history_table.setRowCount(len(tasks))
        for r_idx, t in enumerate(tasks):
            ts_str = t.requested_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            target_dev = dev_map.get(t.target_device_id)
            dev_str = (
                f"{target_dev.ip_address} ({target_dev.hostname or '—'})"
                if target_dev
                else str(t.target_device_id)
            )
            risk_item = QTableWidgetItem(t.risk_level.label_vi)
            r_bg, r_fg = colors_for_table_status(t.risk_level.value)
            risk_item.setBackground(r_bg)
            risk_item.setForeground(r_fg)

            summary_txt = f"[{t.status.label_vi}] {t.result_summary or t.error_message or ''}"
            st_item = QTableWidgetItem(summary_txt)
            s_bg, s_fg = colors_for_table_status(t.status.value)
            st_item.setBackground(s_bg)
            st_item.setForeground(s_fg)

            self.history_table.setItem(r_idx, 0, QTableWidgetItem(ts_str))
            self.history_table.setItem(r_idx, 1, QTableWidgetItem(dev_str))
            self.history_table.setItem(r_idx, 2, QTableWidgetItem(t.task_type.value))
            self.history_table.setItem(r_idx, 3, risk_item)
            self.history_table.setItem(r_idx, 4, QTableWidgetItem(t.requested_by_username))
            self.history_table.setItem(r_idx, 5, st_item)

    def execute_selected_task(self) -> None:
        dev_id = self.device_combo.currentData()
        if not isinstance(dev_id, UUID):
            QMessageBox.information(self, "Chưa chọn thiết bị", "Vui lòng chọn thiết bị đích.")
            return

        selected_device = next((d for d in self._devices if d.id == dev_id), None)
        if selected_device is None:
            return

        task_key = str(self.task_combo.currentData() or "")
        task_def = self._task_service.get_task_definition(task_key)

        confirmed = True
        if task_def.requires_confirmation:
            dlg = TaskConfirmationDialog(selected_device, task_def, self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            confirmed = True

        user_ctx: UserSessionContext = self._get_user_ctx()
        params = {"use_remote_agent": self.chk_remote_agent.isChecked()}

        self.btn_execute_task.setEnabled(False)
        self.status_message.emit(
            f"Đang thực thi tác vụ {task_def.title} trên {selected_device.ip_address}..."
        )

        worker = ServiceWorker(
            f"Thực thi {task_def.task_type.value}",
            self._task_service.execute_task,
            user_ctx,
            dev_id,
            task_def.task_type,
            confirmed_by_user=confirmed,
            parameters=params,
        )
        worker.signals.result.connect(self._on_task_completed)
        worker.signals.error.connect(self._on_task_error)
        worker.signals.finished_task.connect(lambda: self.btn_execute_task.setEnabled(True))
        self._thread_pool.start(worker)

    def _on_task_completed(self, task_record: RemoteTask) -> None:
        msg = f"Tác vụ {task_record.task_type.value}: {task_record.status.label_vi}\n\n{task_record.result_summary or ''}"
        self.status_message.emit(
            f"Hoàn tất {task_record.task_type.value} ({task_record.status.value})"
        )
        QMessageBox.information(self, "Kết quả thực thi & Hậu kiểm", msg)
        self.refresh_page_data(preselect_device_id=task_record.target_device_id)

    def _on_task_error(self, message: str, _detail: str) -> None:
        QMessageBox.warning(self, "Không thể thực thi tác vụ", message)
        self.refresh_page_data()
