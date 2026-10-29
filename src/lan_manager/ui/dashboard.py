"""Enterprise Dashboard page displaying real-time PostgreSQL metrics and operational lists."""

from __future__ import annotations

from uuid import UUID

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.dto.schemas import DashboardSummaryDTO
from lan_manager.application.services.device_service import DeviceService
from lan_manager.ui.components.status_badge import StatusBadge, colors_for_table_status
from lan_manager.ui.workers import ServiceWorker


class KPICard(QFrame):
    """Single metric card for the Dashboard top row."""

    def __init__(self, title: str, initial_value: str = "0", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        self.title_lbl = QLabel(title)
        self.title_lbl.setProperty("kpiTitle", True)
        self.value_lbl = QLabel(initial_value)
        self.value_lbl.setProperty("kpiValue", True)

        layout.addWidget(self.title_lbl)
        layout.addWidget(self.value_lbl)

    def set_value(self, value: int | str) -> None:
        self.value_lbl.setText(str(value))


class DashboardPage(QWidget):
    """
    Displays real-time device & printer KPIs, recent diagnostic issues,
    printers needing inspection, and recent administrative tasks.
    """

    navigate_to_printer = Signal(UUID)
    status_message = Signal(str)

    def __init__(
        self,
        device_service: DeviceService,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._device_service = device_service
        self._thread_pool = thread_pool

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(16)

        # Header Row
        header_row = QHBoxLayout()
        title_lbl = QLabel("Tổng quan hệ thống (Dashboard)")
        title_lbl.setProperty("pageTitle", True)
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        self.db_banner_badge = StatusBadge("Đang kiểm tra DB...", "UNKNOWN")
        header_row.addWidget(self.db_banner_badge)

        self.refresh_btn = QPushButton("Làm mới dữ liệu")
        self.refresh_btn.setProperty("primary", True)
        self.refresh_btn.clicked.connect(self.refresh_dashboard)
        header_row.addWidget(self.refresh_btn)
        root.addLayout(header_row)

        # 5 KPI Cards
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self.card_total_devices = KPICard("TỔNG THIẾT BỊ QUẢN LÝ", "0")
        self.card_total_printers = KPICard("TỔNG SỐ MÁY IN", "0")
        self.card_online = KPICard("THIẾT BỊ ĐANG ONLINE", "0")
        self.card_offline = KPICard("THIẾT BỊ OFFLINE / LỖI", "0")
        self.card_open_issues = KPICard("SỰ CỐ ĐANG MỞ", "0")

        for card in (
            self.card_total_devices,
            self.card_total_printers,
            self.card_online,
            self.card_offline,
            self.card_open_issues,
        ):
            kpi_row.addWidget(card, 1)
        root.addLayout(kpi_row)

        # Notice label for empty / disconnected state
        self.notice_label = QLabel("")
        self.notice_label.setWordWrap(True)
        self.notice_label.setStyleSheet(
            "background-color: #EFF6FF; color: #1E40AF; border: 1px solid #BFDBFE; "
            "border-radius: 6px; padding: 10px;"
        )
        self.notice_label.setVisible(False)
        root.addWidget(self.notice_label)

        # Lower Grid: 3 Operational Tables
        grid = QGridLayout()
        grid.setSpacing(14)

        # 1. Recent Diagnostic Issues
        issues_card = QFrame()
        issues_card.setProperty("card", True)
        issues_layout = QVBoxLayout(issues_card)
        lbl_issues = QLabel("Danh sách sự cố chẩn đoán mới nhất")
        lbl_issues.setProperty("sectionTitle", True)
        issues_layout.addWidget(lbl_issues)

        self.issues_table = QTableWidget(0, 4)
        self.issues_table.setHorizontalHeaderLabels(
            ["Thời gian", "Thiết bị (IP)", "Mức độ", "Nguyên nhân dự kiến"]
        )
        self.issues_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.issues_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.issues_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.issues_table.setAlternatingRowColors(True)
        issues_layout.addWidget(self.issues_table)
        grid.addWidget(issues_card, 0, 0)

        # 2. Printers Needing Inspection
        printers_card = QFrame()
        printers_card.setProperty("card", True)
        printers_layout = QVBoxLayout(printers_card)
        lbl_printers = QLabel("Danh sách máy in cần kiểm tra")
        lbl_printers.setProperty("sectionTitle", True)
        printers_layout.addWidget(lbl_printers)

        self.printers_table = QTableWidget(0, 4)
        self.printers_table.setHorizontalHeaderLabels(
            ["Địa chỉ IP", "Tên máy in / Hostname", "Trạng thái", "Cập nhật gần nhất"]
        )
        self.printers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.printers_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.printers_table.setAlternatingRowColors(True)
        printers_layout.addWidget(self.printers_table)
        grid.addWidget(printers_card, 0, 1)

        # 3. Recent Remediation Tasks
        tasks_card = QFrame()
        tasks_card.setProperty("card", True)
        tasks_layout = QVBoxLayout(tasks_card)
        lbl_tasks = QLabel("Lịch sử tác vụ quản trị gần đây")
        lbl_tasks.setProperty("sectionTitle", True)
        tasks_layout.addWidget(lbl_tasks)

        self.tasks_table = QTableWidget(0, 5)
        self.tasks_table.setHorizontalHeaderLabels(
            ["Thời gian", "Thiết bị đích", "Loại tác vụ", "Người yêu cầu", "Trạng thái"]
        )
        self.tasks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tasks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tasks_table.setAlternatingRowColors(True)
        tasks_layout.addWidget(self.tasks_table)
        grid.addWidget(tasks_card, 1, 0, 1, 2)

        root.addLayout(grid, 1)

    def refresh_dashboard(self) -> None:
        self.refresh_btn.setEnabled(False)
        worker = ServiceWorker(
            "Tải số liệu Dashboard",
            self._device_service.get_dashboard_summary,
        )
        worker.signals.result.connect(self._on_summary_loaded)
        worker.signals.error.connect(self._on_summary_error)
        worker.signals.finished_task.connect(lambda: self.refresh_btn.setEnabled(True))
        self._thread_pool.start(worker)

    def _on_summary_loaded(self, summary: DashboardSummaryDTO) -> None:
        if not summary.db_connected:
            self.db_banner_badge.update_badge("Chưa kết nối PostgreSQL", "DISCONNECTED")
            self.notice_label.setText(
                f"Cơ sở dữ liệu hiện chưa kết nối ({summary.db_status_message}). "
                "Vui lòng kiểm tra cấu hình PostgreSQL trong mục 'Cài đặt' hoặc file .env."
            )
            self.notice_label.setVisible(True)
            return

        self.db_banner_badge.update_badge("PostgreSQL: Đã kết nối", "CONNECTED")
        self.card_total_devices.set_value(summary.total_devices)
        self.card_total_printers.set_value(summary.total_printers)
        self.card_online.set_value(summary.online_devices)
        self.card_offline.set_value(summary.offline_devices)
        self.card_open_issues.set_value(summary.open_issues_count)

        if summary.total_devices == 0:
            self.notice_label.setText(
                "Chưa có thiết bị nào trong cơ sở dữ liệu. Hãy chuyển sang mục 'Thiết bị mạng' "
                "để thực hiện quét khám phá dải mạng LAN được phép."
            )
            self.notice_label.setVisible(True)
        else:
            self.notice_label.setVisible(False)

        # Populate Recent Issues
        self.issues_table.setRowCount(len(summary.recent_issues))
        for row_idx, (diag, dev) in enumerate(summary.recent_issues):
            ts_str = diag.checked_at.astimezone().strftime("%Y-%m-%d %H:%M")
            dev_str = f"{dev.ip_address} ({dev.hostname or '—'})" if dev else str(diag.device_id)
            sev_item = QTableWidgetItem(diag.severity.label_vi)
            bg, fg = colors_for_table_status(diag.severity.value)
            sev_item.setBackground(bg)
            sev_item.setForeground(fg)

            self.issues_table.setItem(row_idx, 0, QTableWidgetItem(ts_str))
            self.issues_table.setItem(row_idx, 1, QTableWidgetItem(dev_str))
            self.issues_table.setItem(row_idx, 2, sev_item)
            self.issues_table.setItem(row_idx, 3, QTableWidgetItem(diag.probable_cause))

        # Populate Printers Needing Attention
        self.printers_table.setRowCount(len(summary.printers_needing_check))
        for row_idx, prn_dev in enumerate(summary.printers_needing_check):
            prn_name = (
                prn_dev.printer_info.printer_name
                if prn_dev.printer_info and prn_dev.printer_info.printer_name
                else (prn_dev.hostname or prn_dev.model or "Máy in chưa rõ tên")
            )
            st_item = QTableWidgetItem(prn_dev.status.label_vi)
            bg, fg = colors_for_table_status(prn_dev.status.value)
            st_item.setBackground(bg)
            st_item.setForeground(fg)
            seen_str = (
                prn_dev.last_seen_at.astimezone().strftime("%Y-%m-%d %H:%M")
                if prn_dev.last_seen_at
                else "Chưa kiểm tra"
            )
            self.printers_table.setItem(row_idx, 0, QTableWidgetItem(prn_dev.ip_address))
            self.printers_table.setItem(row_idx, 1, QTableWidgetItem(prn_name))
            self.printers_table.setItem(row_idx, 2, st_item)
            self.printers_table.setItem(row_idx, 3, QTableWidgetItem(seen_str))

        # Populate Recent Tasks
        self.tasks_table.setRowCount(len(summary.recent_tasks))
        for row_idx, (task, dev) in enumerate(summary.recent_tasks):
            ts_str = task.requested_at.astimezone().strftime("%Y-%m-%d %H:%M")
            dev_str = dev.ip_address if dev else str(task.target_device_id)
            st_item = QTableWidgetItem(task.status.label_vi)
            bg, fg = colors_for_table_status(task.status.value)
            st_item.setBackground(bg)
            st_item.setForeground(fg)

            self.tasks_table.setItem(row_idx, 0, QTableWidgetItem(ts_str))
            self.tasks_table.setItem(row_idx, 1, QTableWidgetItem(dev_str))
            self.tasks_table.setItem(row_idx, 2, QTableWidgetItem(task.task_type.value))
            self.tasks_table.setItem(row_idx, 3, QTableWidgetItem(task.requested_by_username))
            self.tasks_table.setItem(row_idx, 4, st_item)

    def _on_summary_error(self, message: str, _detail: str) -> None:
        self.db_banner_badge.update_badge("Lỗi kết nối DB", "ERROR")
        self.notice_label.setText(f"Không thể tải dữ liệu Dashboard: {message}")
        self.notice_label.setVisible(True)
