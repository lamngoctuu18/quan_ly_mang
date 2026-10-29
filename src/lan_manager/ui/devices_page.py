"""Network Devices discovery and inventory page using Qt Model/View."""

from __future__ import annotations

from uuid import UUID

from PySide6.QtCore import QModelIndex, QThreadPool, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.dto.schemas import ScanSummaryDTO
from lan_manager.application.services.device_service import DeviceService
from lan_manager.application.services.monitoring_service import MonitoringService
from lan_manager.application.services.scan_service import ScanService
from lan_manager.core.config import AppConfig
from lan_manager.core.security import UserSessionContext
from lan_manager.domain.enums.system_enums import DeviceStatusEnum, DeviceType
from lan_manager.domain.models.entities import Device
from lan_manager.ui.components.device_table_model import (
    DeviceSortFilterProxyModel,
    DeviceTableModel,
)
from lan_manager.ui.workers import ServiceWorker


class DeviceEditDialog(QDialog):
    """Dialog to view and edit device administrative metadata (hostname, type, vendor, location)."""

    def __init__(self, device: Device, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Chi tiết & Cập nhật thiết bị — {device.ip_address}")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        form = QFormLayout()
        form.addRow("Địa chỉ IP:", QLabel(device.ip_address))
        form.addRow("Địa chỉ MAC:", QLabel(device.mac_address or "Chưa thu thập"))

        self.hostname_edit = QLineEdit(device.hostname or "")
        form.addRow("Hostname:", self.hostname_edit)

        self.type_combo = QComboBox()
        for dt in DeviceType:
            self.type_combo.addItem(dt.label_vi, dt.value)
        idx = self.type_combo.findData(device.device_type.value)
        if idx >= 0:
            self.type_combo.setCurrentIndex(idx)
        form.addRow("Loại thiết bị:", self.type_combo)

        self.vendor_edit = QLineEdit(device.manufacturer or "")
        form.addRow("Nhà sản xuất:", self.vendor_edit)

        self.model_edit = QLineEdit(device.model or "")
        form.addRow("Model:", self.model_edit)

        self.location_edit = QLineEdit(device.location or "")
        form.addRow("Vị trí (Phòng/Tầng):", self.location_edit)

        layout.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Đóng")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Lưu thay đổi")
        save_btn.setProperty("primary", True)
        save_btn.clicked.connect(self.accept)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        layout.addLayout(btn_row)


class DevicesPage(QWidget):
    """
    Network device management page:
    - Controlled CIDR LAN scan bar with progress & cancellation.
    - Search, device type filter, status filter, multi-selection, sorting, and pagination.
    """

    inspect_device_requested = Signal(UUID)
    diagnose_device_requested = Signal(UUID)
    scan_progress_changed = Signal(int, int, str)
    scan_state_changed = Signal(bool, str)

    PAGE_SIZE = 25

    def __init__(
        self,
        config: AppConfig,
        scan_service: ScanService,
        device_service: DeviceService,
        monitoring_service: MonitoringService,
        user_ctx_provider: callable,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._scan_service = scan_service
        self._device_service = device_service
        self._monitoring_service = monitoring_service
        self._get_user_ctx = user_ctx_provider
        self._thread_pool = thread_pool

        self._active_scan_worker: ServiceWorker | None = None
        self._all_loaded_devices: list[Device] = []
        self._current_page = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        # Page Header
        top_row = QHBoxLayout()
        title_lbl = QLabel("Quản lý thiết bị mạng & Quét khám phá LAN")
        title_lbl.setProperty("pageTitle", True)
        top_row.addWidget(title_lbl)
        top_row.addStretch()

        self.btn_recheck_selected = QPushButton("Kiểm tra kết nối mục đã chọn")
        self.btn_recheck_selected.clicked.connect(self._recheck_selected_devices)
        top_row.addWidget(self.btn_recheck_selected)

        self.btn_refresh = QPushButton("Tải lại danh sách")
        self.btn_refresh.clicked.connect(self.load_devices)
        top_row.addWidget(self.btn_refresh)
        root.addLayout(top_row)

        # Scan Control Panel
        scan_card = QFrame()
        scan_card.setProperty("card", True)
        scan_layout = QHBoxLayout(scan_card)
        scan_layout.setContentsMargins(14, 12, 14, 12)
        scan_layout.setSpacing(10)

        scan_layout.addWidget(QLabel("Dải IP / CIDR được phép:"))
        self.cidr_input = QComboBox()
        self.cidr_input.setEditable(True)
        self.cidr_input.setMinimumWidth(220)
        default_examples = ["127.0.0.1/32", "192.168.1.0/24", "192.168.10.0/24", "10.0.0.0/24"]
        for subnet in default_examples + self._config.allowed_scan_subnets:
            if self.cidr_input.findText(subnet) < 0:
                self.cidr_input.addItem(subnet)
        scan_layout.addWidget(self.cidr_input)

        self.snmp_checkbox = QCheckBox("Thu thập SNMP (MIB-II / Printer-MIB)")
        self.snmp_checkbox.setChecked(self._config.snmp_enabled_by_default)
        scan_layout.addWidget(self.snmp_checkbox)

        self.btn_start_scan = QPushButton("Bắt đầu quét LAN")
        self.btn_start_scan.setProperty("primary", True)
        self.btn_start_scan.clicked.connect(self.start_lan_scan)
        scan_layout.addWidget(self.btn_start_scan)

        self.btn_cancel_scan = QPushButton("Dừng quét")
        self.btn_cancel_scan.setProperty("danger", True)
        self.btn_cancel_scan.setEnabled(False)
        self.btn_cancel_scan.clicked.connect(self.cancel_lan_scan)
        scan_layout.addWidget(self.btn_cancel_scan)

        scan_layout.addStretch()
        self.scan_summary_lbl = QLabel(
            f"Giới hạn tối đa: {self._config.max_scan_hosts} IP/lần, {self._config.max_concurrent_probes} luồng"
        )
        scan_layout.addWidget(self.scan_summary_lbl)
        root.addWidget(scan_card)

        # Filter & Search Toolbar
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Tìm kiếm theo IP, Hostname, MAC, Nhà sản xuất, Model..."
        )
        self.search_input.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.search_input, 2)

        filter_row.addWidget(QLabel("Loại thiết bị:"))
        self.type_filter = QComboBox()
        self.type_filter.addItem("Tất cả loại thiết bị", "")
        for dt in DeviceType:
            self.type_filter.addItem(dt.label_vi, dt.value)
        self.type_filter.currentIndexChanged.connect(self._apply_filters)
        filter_row.addWidget(self.type_filter)

        filter_row.addWidget(QLabel("Trạng thái:"))
        self.status_filter = QComboBox()
        self.status_filter.addItem("Tất cả trạng thái", "")
        for st in DeviceStatusEnum:
            self.status_filter.addItem(st.label_vi, st.value)
        self.status_filter.currentIndexChanged.connect(self._apply_filters)
        filter_row.addWidget(self.status_filter)

        btn_select_all = QPushButton("Chọn tất cả")
        btn_select_all.clicked.connect(lambda: self.table_model.select_all(True))
        filter_row.addWidget(btn_select_all)

        btn_unselect_all = QPushButton("Bỏ chọn")
        btn_unselect_all.clicked.connect(lambda: self.table_model.select_all(False))
        filter_row.addWidget(btn_unselect_all)

        root.addLayout(filter_row)

        # Device TableView (Qt Model/View)
        self.table_model = DeviceTableModel()
        self.proxy_model = DeviceSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.table_model)

        self.table_view = QTableView()
        self.table_view.setModel(self.proxy_model)
        self.table_view.setSortingEnabled(True)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.verticalHeader().setVisible(False)
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(
            DeviceTableModel.COL_SELECT, QHeaderView.ResizeMode.ResizeToContents
        )
        header.setSectionResizeMode(DeviceTableModel.COL_VENDOR, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(
            DeviceTableModel.COL_ACTION, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table_view.clicked.connect(self._on_table_clicked)
        self.table_view.doubleClicked.connect(self._on_table_double_clicked)
        root.addWidget(self.table_view, 1)

        # Pagination Footer
        footer_row = QHBoxLayout()
        self.lbl_pagination_info = QLabel("Hiển thị 0 thiết bị")
        footer_row.addWidget(self.lbl_pagination_info)
        footer_row.addStretch()

        self.btn_prev_page = QPushButton("< Trang trước")
        self.btn_prev_page.clicked.connect(self._prev_page)
        footer_row.addWidget(self.btn_prev_page)

        self.lbl_page_num = QLabel("Trang 1 / 1")
        footer_row.addWidget(self.lbl_page_num)

        self.btn_next_page = QPushButton("Trang sau >")
        self.btn_next_page.clicked.connect(self._next_page)
        footer_row.addWidget(self.btn_next_page)
        root.addLayout(footer_row)

    def load_devices(self) -> None:
        self.btn_refresh.setEnabled(False)
        worker = ServiceWorker(
            "Tải danh sách thiết bị",
            self._device_service.list_devices,
            limit=1000,
        )
        worker.signals.result.connect(self._on_devices_loaded)
        worker.signals.error.connect(self._on_error)
        worker.signals.finished_task.connect(lambda: self.btn_refresh.setEnabled(True))
        self._thread_pool.start(worker)

    def _on_devices_loaded(self, result: tuple[list[Device], int]) -> None:
        devices, _ = result
        self._all_loaded_devices = devices
        self._current_page = 0
        self._refresh_current_page()

    def _apply_filters(self) -> None:
        self._current_page = 0
        self._refresh_current_page()

    def _refresh_current_page(self) -> None:
        search_q = self.search_input.text().strip().lower()
        type_val = str(self.type_filter.currentData() or "")
        status_val = str(self.status_filter.currentData() or "")

        filtered: list[Device] = []
        for dev in self._all_loaded_devices:
            if type_val and dev.device_type.value != type_val:
                continue
            if status_val and dev.status.value != status_val:
                continue
            if search_q:
                haystack = " ".join(
                    filter(
                        None,
                        [
                            dev.ip_address,
                            dev.hostname,
                            dev.mac_address,
                            dev.manufacturer,
                            dev.model,
                            dev.location,
                        ],
                    )
                ).lower()
                if search_q not in haystack:
                    continue
            filtered.append(dev)

        total = len(filtered)
        total_pages = max(1, (total + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self._current_page = max(0, min(self._current_page, total_pages - 1))

        start = self._current_page * self.PAGE_SIZE
        end = start + self.PAGE_SIZE
        page_items = filtered[start:end]

        self.table_model.set_devices(page_items)
        self.lbl_pagination_info.setText(
            f"Hiển thị {len(page_items)} / {total} thiết bị phù hợp (Tổng DB: {len(self._all_loaded_devices)})"
        )
        self.lbl_page_num.setText(f"Trang {self._current_page + 1} / {total_pages}")
        self.btn_prev_page.setEnabled(self._current_page > 0)
        self.btn_next_page.setEnabled(self._current_page + 1 < total_pages)

    def _prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self._refresh_current_page()

    def _next_page(self) -> None:
        self._current_page += 1
        self._refresh_current_page()

    def start_lan_scan(self) -> None:
        target_cidr = self.cidr_input.currentText().strip()
        user_ctx: UserSessionContext = self._get_user_ctx()
        enable_snmp = self.snmp_checkbox.isChecked()

        self.btn_start_scan.setEnabled(False)
        self.btn_cancel_scan.setEnabled(True)
        self.scan_state_changed.emit(True, f"Đang quét dải {target_cidr}...")

        worker = ServiceWorker(
            f"Quét mạng {target_cidr}",
            self._scan_service.scan_and_persist,
            user_ctx,
            target_cidr,
            enable_snmp=enable_snmp,
            supports_cancel=True,
            supports_progress=True,
        )
        self._active_scan_worker = worker
        worker.signals.progress.connect(self.scan_progress_changed.emit)
        worker.signals.result.connect(self._on_scan_finished)
        worker.signals.error.connect(self._on_scan_error)
        worker.signals.finished_task.connect(self._reset_scan_buttons)
        self._thread_pool.start(worker)

    def cancel_lan_scan(self) -> None:
        if self._active_scan_worker is not None:
            self._active_scan_worker.request_cancel()
            self.scan_summary_lbl.setText("Đang dừng tác vụ quét mạng...")

    def _reset_scan_buttons(self) -> None:
        self.btn_start_scan.setEnabled(True)
        self.btn_cancel_scan.setEnabled(False)
        self._active_scan_worker = None

    def _on_scan_finished(self, summary: ScanSummaryDTO) -> None:
        status_txt = "Đã hủy quét" if summary.cancelled else "Hoàn tất quét"
        msg = (
            f"{status_txt} {summary.target_cidr} trong {summary.duration_sec}s: "
            f"{summary.alive_count}/{summary.total_hosts_probed} IP phản hồi "
            f"(Mới: {summary.new_devices_count}, Cập nhật: {summary.updated_devices_count}, "
            f"Máy in: {summary.printers_found})."
        )
        self.scan_summary_lbl.setText(msg)
        self.scan_state_changed.emit(False, msg)
        self.load_devices()

    def _on_scan_error(self, message: str, _detail: str) -> None:
        self.scan_state_changed.emit(False, f"Lỗi quét mạng: {message}")
        QMessageBox.warning(self, "Không thể thực hiện quét mạng", message)

    def _on_table_clicked(self, proxy_index: QModelIndex) -> None:
        if not proxy_index.isValid():
            return
        if proxy_index.column() == DeviceTableModel.COL_ACTION:
            src_idx = self.proxy_model.mapToSource(proxy_index)
            dev = self.table_model.get_device_at(src_idx.row())
            if dev is not None:
                self._open_device_detail_or_edit(dev)

    def _on_table_double_clicked(self, proxy_index: QModelIndex) -> None:
        if not proxy_index.isValid():
            return
        src_idx = self.proxy_model.mapToSource(proxy_index)
        dev = self.table_model.get_device_at(src_idx.row())
        if dev is not None:
            self._open_device_detail_or_edit(dev)

    def _open_device_detail_or_edit(self, device: Device) -> None:
        if device.device_type == DeviceType.PRINTER:
            self.inspect_device_requested.emit(device.id)
            return

        dlg = DeviceEditDialog(device, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            user_ctx: UserSessionContext = self._get_user_ctx()
            new_type = DeviceType(str(dlg.type_combo.currentData()))
            worker = ServiceWorker(
                "Cập nhật thiết bị",
                self._device_service.update_device_details,
                user_ctx,
                device.id,
                hostname=dlg.hostname_edit.text().strip() or None,
                device_type=new_type,
                manufacturer=dlg.vendor_edit.text().strip() or None,
                model=dlg.model_edit.text().strip() or None,
                location=dlg.location_edit.text().strip() or None,
            )
            worker.signals.result.connect(lambda _: self.load_devices())
            worker.signals.error.connect(self._on_error)
            self._thread_pool.start(worker)

    def _recheck_selected_devices(self) -> None:
        selected = self.table_model.get_selected_devices()
        if not selected:
            QMessageBox.information(
                self,
                "Chưa chọn thiết bị",
                "Vui lòng tích chọn ít nhất một thiết bị trong bảng để kiểm tra lại kết nối.",
            )
            return

        def _batch_check() -> int:
            for dev in selected:
                self._monitoring_service.check_device_now(dev.id)
            return len(selected)

        self.btn_recheck_selected.setEnabled(False)
        worker = ServiceWorker("Kiểm tra kết nối thiết bị", _batch_check)
        worker.signals.result.connect(
            lambda count: (
                self.scan_state_changed.emit(False, f"Đã kiểm tra lại {count} thiết bị."),
                self.load_devices(),
            )
        )
        worker.signals.error.connect(self._on_error)
        worker.signals.finished_task.connect(lambda: self.btn_recheck_selected.setEnabled(True))
        self._thread_pool.start(worker)

    def _on_error(self, message: str, _detail: str) -> None:
        QMessageBox.warning(self, "Thông báo lỗi", message)
