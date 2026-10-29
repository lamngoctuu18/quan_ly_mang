"""Printers management page featuring a 6-tab Printer Details inspector."""

from __future__ import annotations

from uuid import UUID

from PySide6.QtCore import Qt, QThreadPool, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.dto.schemas import PrinterFullDetailDTO
from lan_manager.application.services.monitoring_service import MonitoringService
from lan_manager.application.services.printer_service import PrinterService
from lan_manager.domain.models.entities import Device
from lan_manager.ui.components.status_badge import StatusBadge, colors_for_table_status
from lan_manager.ui.workers import ServiceWorker


class PrintersPage(QWidget):
    """
    Dedicated IP Printer Management Page.
    Left panel: Searchable printer list.
    Right panel: 6-Tab Printer Details (Tổng quan, Kết nối, Thông tin SNMP, Chẩn đoán, Tác vụ, Lịch sử).
    """

    open_diagnostics_for_device = Signal(UUID)
    open_tasks_for_device = Signal(UUID)
    status_message = Signal(str)

    def __init__(
        self,
        printer_service: PrinterService,
        monitoring_service: MonitoringService,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._printer_service = printer_service
        self._monitoring_service = monitoring_service
        self._thread_pool = thread_pool
        self._printers: list[Device] = []
        self._selected_device_id: UUID | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        # Page Header
        header_row = QHBoxLayout()
        title_lbl = QLabel("Quản lý chuyên sâu Máy in IP")
        title_lbl.setProperty("pageTitle", True)
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        self.btn_check_now = QPushButton("Kiểm tra máy in đang chọn")
        self.btn_check_now.setEnabled(False)
        self.btn_check_now.clicked.connect(self.check_selected_printer_now)
        header_row.addWidget(self.btn_check_now)

        self.btn_refresh_list = QPushButton("Làm mới danh sách")
        self.btn_refresh_list.setProperty("primary", True)
        self.btn_refresh_list.clicked.connect(self.load_printers)
        header_row.addWidget(self.btn_refresh_list)
        root.addLayout(header_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel: Printer List
        left_card = QFrame()
        left_card.setProperty("card", True)
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Tìm máy in (IP, Tên, Model, Serial)...")
        self.search_input.textChanged.connect(self._filter_printer_list)
        left_layout.addWidget(self.search_input)

        self.printer_list_widget = QListWidget()
        self.printer_list_widget.currentItemChanged.connect(self._on_printer_selected)
        left_layout.addWidget(self.printer_list_widget, 1)
        splitter.addWidget(left_card)

        # Right Panel: 6 Tabs
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        # Top Summary Banner for Selected Printer
        summary_frame = QFrame()
        summary_frame.setProperty("card", True)
        summary_bar = QHBoxLayout(summary_frame)
        summary_bar.setContentsMargins(14, 10, 14, 10)
        self.lbl_selected_title = QLabel("Chưa chọn máy in")
        self.lbl_selected_title.setProperty("sectionTitle", True)
        summary_bar.addWidget(self.lbl_selected_title)
        summary_bar.addStretch()
        self.badge_selected_status = StatusBadge("CHƯA CHỌN", "UNKNOWN")
        summary_bar.addWidget(self.badge_selected_status)
        right_layout.addWidget(summary_frame)

        self.tabs = QTabWidget()
        self._build_tab_overview()
        self._build_tab_connectivity()
        self._build_tab_snmp()
        self._build_tab_diagnostics()
        self._build_tab_tasks()
        self._build_tab_history()
        right_layout.addWidget(self.tabs, 1)

        splitter.addWidget(right_container)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        root.addWidget(splitter, 1)

    def _build_tab_overview(self) -> None:
        tab = QWidget()
        layout = QFormLayout(tab)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        self.lbl_ov_name = QLabel("—")
        self.lbl_ov_ip = QLabel("—")
        self.lbl_ov_mac = QLabel("—")
        self.lbl_ov_vendor = QLabel("—")
        self.lbl_ov_model = QLabel("—")
        self.lbl_ov_serial = QLabel("—")
        self.lbl_ov_firmware = QLabel("—")
        self.lbl_ov_location = QLabel("—")
        self.lbl_ov_last_seen = QLabel("—")

        layout.addRow("Tên máy in:", self.lbl_ov_name)
        layout.addRow("Địa chỉ IP:", self.lbl_ov_ip)
        layout.addRow("Địa chỉ MAC:", self.lbl_ov_mac)
        layout.addRow("Nhà sản xuất:", self.lbl_ov_vendor)
        layout.addRow("Model:", self.lbl_ov_model)
        layout.addRow("Số Serial (SNMP):", self.lbl_ov_serial)
        layout.addRow("Phiên bản Firmware:", self.lbl_ov_firmware)
        layout.addRow("Vị trí lắp đặt:", self.lbl_ov_location)
        layout.addRow("Cập nhật gần nhất:", self.lbl_ov_last_seen)

        self.tabs.addTab(tab, "1. Tổng quan")

    def _build_tab_connectivity(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        form = QFormLayout()
        self.lbl_conn_status = QLabel("—")
        self.lbl_conn_protocols = QLabel("—")
        self.lbl_conn_ports = QLabel("—")
        self.lbl_conn_latency = QLabel("—")
        form.addRow("Trạng thái hiện tại:", self.lbl_conn_status)
        form.addRow("Giao thức in hỗ trợ:", self.lbl_conn_protocols)
        form.addRow("Các cổng TCP đang mở:", self.lbl_conn_ports)
        form.addRow("Độ trễ phản hồi (Latency):", self.lbl_conn_latency)
        layout.addLayout(form)
        layout.addStretch()

        self.tabs.addTab(tab, "2. Kết nối")

    def _build_tab_snmp(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self.lbl_snmp_summary = QLabel("Chưa có dữ liệu SNMP.")
        self.lbl_snmp_summary.setWordWrap(True)
        layout.addWidget(self.lbl_snmp_summary)

        self.snmp_table = QTableWidget(0, 2)
        self.snmp_table.setHorizontalHeaderLabels(["Thuộc tính / OID", "Giá trị thu thập"])
        self.snmp_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.snmp_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.snmp_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.snmp_table, 1)

        self.tabs.addTab(tab, "3. Thông tin SNMP")

    def _build_tab_diagnostics(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Lịch sử chẩn đoán sự cố của máy in này:"))
        top_bar.addStretch()
        btn_go_diag = QPushButton("Mở trình Chẩn đoán 5 bước cho máy in này")
        btn_go_diag.setProperty("primary", True)
        btn_go_diag.clicked.connect(
            lambda: (
                self._selected_device_id
                and self.open_diagnostics_for_device.emit(self._selected_device_id)
            )
        )
        top_bar.addWidget(btn_go_diag)
        layout.addLayout(top_bar)

        self.diag_table = QTableWidget(0, 3)
        self.diag_table.setHorizontalHeaderLabels(["Thời điểm", "Mức độ", "Nguyên nhân dự kiến"])
        self.diag_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.diag_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.diag_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.diag_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.diag_table, 1)

        self.tabs.addTab(tab, "4. Chẩn đoán")

    def _build_tab_tasks(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Lịch sử tác vụ sửa lỗi trên máy in này:"))
        top_bar.addStretch()
        btn_go_tasks = QPushButton("Thực thi tác vụ sửa lỗi cho máy in này")
        btn_go_tasks.setProperty("primary", True)
        btn_go_tasks.clicked.connect(
            lambda: (
                self._selected_device_id
                and self.open_tasks_for_device.emit(self._selected_device_id)
            )
        )
        top_bar.addWidget(btn_go_tasks)
        layout.addLayout(top_bar)

        self.task_table = QTableWidget(0, 4)
        self.task_table.setHorizontalHeaderLabels(
            ["Thời gian", "Mã tác vụ", "Trạng thái", "Kết quả & Hậu kiểm"]
        )
        self.task_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.task_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.task_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.task_table, 1)

        self.tabs.addTab(tab, "5. Tác vụ")

    def _build_tab_history(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(
            ["Thời điểm kiểm tra", "Trạng thái", "Độ trễ (ms)", "Cổng mở", "Chi tiết"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.history_table, 1)

        self.tabs.addTab(tab, "6. Lịch sử")

    def load_printers(self, select_device_id: UUID | None = None) -> None:
        if select_device_id is not None:
            self._selected_device_id = select_device_id

        worker = ServiceWorker("Tải danh sách máy in", self._printer_service.list_printers)
        worker.signals.result.connect(self._on_printers_loaded)
        worker.signals.error.connect(lambda msg, _: QMessageBox.warning(self, "Lỗi", msg))
        self._thread_pool.start(worker)

    def select_printer_by_id(self, device_id: UUID) -> None:
        self._selected_device_id = device_id
        self.load_printers(select_device_id=device_id)

    def _on_printers_loaded(self, printers: list[Device]) -> None:
        self._printers = printers
        self._filter_printer_list()

    def _filter_printer_list(self) -> None:
        q = self.search_input.text().strip().lower()
        self.printer_list_widget.clear()
        selected_row = 0

        for dev in self._printers:
            prn_name = (
                dev.printer_info.printer_name
                if dev.printer_info and dev.printer_info.printer_name
                else (dev.hostname or dev.model or f"Máy in {dev.ip_address}")
            )
            if q and q not in f"{dev.ip_address} {prn_name} {dev.model or ''}".lower():
                continue

            item = QListWidgetItem(f"{dev.ip_address} — {prn_name} [{dev.status.value}]")
            item.setData(Qt.ItemDataRole.UserRole, dev.id)
            self.printer_list_widget.addItem(item)
            if self._selected_device_id and dev.id == self._selected_device_id:
                selected_row = self.printer_list_widget.count() - 1

        if self.printer_list_widget.count() > 0:
            self.printer_list_widget.setCurrentRow(selected_row)
        else:
            self.lbl_selected_title.setText("Chưa có máy in IP nào được phát hiện")
            self.badge_selected_status.update_badge("TRỐNG", "UNKNOWN")
            self.btn_check_now.setEnabled(False)

    def _on_printer_selected(
        self, current: QListWidgetItem | None, _previous: QListWidgetItem | None
    ) -> None:
        if current is None:
            return
        dev_id: UUID = current.data(Qt.ItemDataRole.UserRole)
        self._selected_device_id = dev_id
        self.btn_check_now.setEnabled(True)

        worker = ServiceWorker(
            "Tải chi tiết máy in",
            self._printer_service.get_printer_full_detail,
            dev_id,
        )
        worker.signals.result.connect(self._populate_detail_tabs)
        self._thread_pool.start(worker)

    def _populate_detail_tabs(self, detail: PrinterFullDetailDTO) -> None:
        dev = detail.device
        prn = dev.printer_info
        prn_name = (
            prn.printer_name if prn else (dev.hostname or dev.model or f"Printer {dev.ip_address}")
        )

        self.lbl_selected_title.setText(f"{prn_name} ({dev.ip_address})")
        self.badge_selected_status.update_badge(dev.status.label_vi, dev.status.value)

        # Tab 1: Overview
        self.lbl_ov_name.setText(prn_name)
        self.lbl_ov_ip.setText(dev.ip_address)
        self.lbl_ov_mac.setText(dev.mac_address or "Chưa thu thập")
        self.lbl_ov_vendor.setText(dev.manufacturer or "Chưa xác định")
        self.lbl_ov_model.setText(dev.model or "Chưa xác định")
        self.lbl_ov_serial.setText((prn.serial_number if prn else None) or "Không có")
        self.lbl_ov_firmware.setText((prn.firmware_version if prn else None) or "Không có")
        self.lbl_ov_location.setText(dev.location or "Chưa cập nhật")
        self.lbl_ov_last_seen.setText(
            dev.last_seen_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            if dev.last_seen_at
            else "Chưa kiểm tra"
        )

        # Tab 2: Connectivity
        meta = prn.metadata if prn else {}
        open_ports = meta.get("open_ports", [])
        latency = meta.get("latency_ms")
        protocols = prn.supported_protocols if prn else []

        self.lbl_conn_status.setText(dev.status.label_vi)
        self.lbl_conn_protocols.setText(", ".join(protocols) if protocols else "Chưa xác định")
        self.lbl_conn_ports.setText(
            ", ".join(str(p) for p in open_ports) if open_ports else "Không có"
        )
        self.lbl_conn_latency.setText(f"{latency} ms" if latency is not None else "—")

        # Tab 3: SNMP
        snmp_enabled = bool(prn and prn.snmp_enabled)
        self.lbl_snmp_summary.setText(
            f"Trạng thái SNMP: {'Đã kích hoạt & phản hồi' if snmp_enabled else 'Không phản hồi hoặc đã tắt trên máy in'}"
        )
        snmp_rows: list[tuple[str, str]] = []
        if prn and prn.metadata:
            for key in (
                "snmp_sys_descr",
                "snmp_printer_status",
                "snmp_page_count",
                "snmp_console_display",
                "snmp_alerts",
            ):
                if key in prn.metadata and prn.metadata[key] is not None:
                    snmp_rows.append((key, str(prn.metadata[key])))
            raw_oids = prn.metadata.get("snmp_raw_oids", {})
            if isinstance(raw_oids, dict):
                for oid_k, oid_v in raw_oids.items():
                    snmp_rows.append((f"OID {oid_k}", str(oid_v)))

        self.snmp_table.setRowCount(len(snmp_rows))
        for r_idx, (k_str, v_str) in enumerate(snmp_rows):
            self.snmp_table.setItem(r_idx, 0, QTableWidgetItem(k_str))
            self.snmp_table.setItem(r_idx, 1, QTableWidgetItem(v_str))

        # Tab 4: Diagnostics
        self.diag_table.setRowCount(len(detail.diagnostics))
        for r_idx, diag in enumerate(detail.diagnostics):
            ts_str = diag.checked_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            sev_item = QTableWidgetItem(diag.severity.label_vi)
            bg, fg = colors_for_table_status(diag.severity.value)
            sev_item.setBackground(bg)
            sev_item.setForeground(fg)
            self.diag_table.setItem(r_idx, 0, QTableWidgetItem(ts_str))
            self.diag_table.setItem(r_idx, 1, sev_item)
            self.diag_table.setItem(r_idx, 2, QTableWidgetItem(diag.probable_cause))

        # Tab 5: Tasks
        self.task_table.setRowCount(len(detail.tasks))
        for r_idx, task in enumerate(detail.tasks):
            ts_str = task.requested_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            st_item = QTableWidgetItem(task.status.label_vi)
            bg, fg = colors_for_table_status(task.status.value)
            st_item.setBackground(bg)
            st_item.setForeground(fg)
            self.task_table.setItem(r_idx, 0, QTableWidgetItem(ts_str))
            self.task_table.setItem(r_idx, 1, QTableWidgetItem(task.task_type.value))
            self.task_table.setItem(r_idx, 2, st_item)
            self.task_table.setItem(
                r_idx, 3, QTableWidgetItem(task.result_summary or task.error_message or "")
            )

        # Tab 6: History
        self.history_table.setRowCount(len(detail.status_history))
        for r_idx, h in enumerate(detail.status_history):
            ts_str = h.checked_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            st_item = QTableWidgetItem(h.status.label_vi)
            bg, fg = colors_for_table_status(h.status.value)
            st_item.setBackground(bg)
            st_item.setForeground(fg)
            self.history_table.setItem(r_idx, 0, QTableWidgetItem(ts_str))
            self.history_table.setItem(r_idx, 1, st_item)
            self.history_table.setItem(r_idx, 2, QTableWidgetItem(str(h.latency_ms or "—")))
            self.history_table.setItem(
                r_idx, 3, QTableWidgetItem(", ".join(str(p) for p in h.open_ports) or "—")
            )
            self.history_table.setItem(r_idx, 4, QTableWidgetItem(h.status_detail or ""))

    def check_selected_printer_now(self) -> None:
        if self._selected_device_id is None:
            return
        self.btn_check_now.setEnabled(False)
        worker = ServiceWorker(
            "Kiểm tra trạng thái máy in",
            self._monitoring_service.check_device_now,
            self._selected_device_id,
        )
        worker.signals.result.connect(
            lambda dev: (
                self.status_message.emit(
                    f"Đã cập nhật trạng thái máy in {dev.ip_address}: {dev.status.label_vi}"
                ),
                self.load_printers(select_device_id=dev.id),
            )
        )
        worker.signals.error.connect(lambda msg, _: QMessageBox.warning(self, "Lỗi kiểm tra", msg))
        worker.signals.finished_task.connect(lambda: self.btn_check_now.setEnabled(True))
        self._thread_pool.start(worker)
