"""Enterprise Main Window with collapsible sidebar, live DB header, 7 pages, and task status bar."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from PySide6.QtCore import QThreadPool
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.services import (
    AuditService,
    DeviceService,
    DiagnosticService,
    MonitoringService,
    PrinterService,
    RemoteTaskService,
    ScanService,
)
from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.security import UserSessionContext
from lan_manager.domain.enums.system_enums import RoleType
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.ui.components.status_badge import StatusBadge
from lan_manager.ui.dashboard import DashboardPage
from lan_manager.ui.devices_page import DevicesPage
from lan_manager.ui.diagnostics_page import DiagnosticsPage
from lan_manager.ui.logs_page import LogsPage
from lan_manager.ui.printers_page import PrintersPage
from lan_manager.ui.settings_page import SettingsPage
from lan_manager.ui.tasks_page import TasksPage


class MainWindow(QMainWindow):
    """Primary desktop window for LAN Printer Manager."""

    NAV_ITEMS = (
        ("01. Dashboard", "01"),
        ("02. Thiết bị mạng", "02"),
        ("03. Máy in", "03"),
        ("04. Chẩn đoán sự cố", "04"),
        ("05. Tác vụ từ xa", "05"),
        ("06. Nhật ký hoạt động", "06"),
        ("07. Cài đặt", "07"),
    )

    def __init__(
        self,
        config: AppConfig | None = None,
        db_manager: DatabaseManager | None = None,
        initial_user_ctx: UserSessionContext | None = None,
    ) -> None:
        super().__init__()
        self._config = config or get_config()
        self._db_manager = db_manager or get_db_manager(self._config)
        self._user_ctx = initial_user_ctx or AuditService.create_default_session(
            role=RoleType.ADMIN, username="admin"
        )
        self._sidebar_collapsed = False

        self.thread_pool = QThreadPool(self)
        self.thread_pool.setMaxThreadCount(8)

        # Initialize Application Services
        self.audit_service = AuditService(self._db_manager)
        self.device_service = DeviceService(self._db_manager)
        self.printer_service = PrinterService(self._db_manager)
        self.monitoring_service = MonitoringService(self._config, self._db_manager)
        self.scan_service = ScanService(self._config, self._db_manager)
        self.diagnostic_service = DiagnosticService(self._config, self._db_manager)
        self.task_service = RemoteTaskService(self._config, self._db_manager)

        self.setWindowTitle(f"{self._config.app_name} — Hệ thống Quản trị Máy in & Thiết bị LAN")
        self.resize(1360, 840)
        self.setMinimumSize(1080, 680)

        self._load_stylesheet()
        self._build_ui()
        self._wire_signals()

        # NOTE: All DB-dependent startup work is deferred to deferred_startup()
        # called via QTimer.singleShot(0) AFTER the window is shown on screen.
        # This ensures the UI appears instantly without waiting for PostgreSQL.

    def deferred_startup(self) -> None:
        """Run after the window is visible — performs non-blocking DB checks and data loading."""
        self.settings_page.test_db_connection()
        self.dashboard_page.refresh_dashboard()
        self.diagnostics_page.load_device_choices()
        self.tasks_page.refresh_page_data()

    def _load_stylesheet(self) -> None:
        qss_path = Path(__file__).resolve().parent / "styles" / "enterprise_theme.qss"
        if qss_path.exists():
            self.setStyleSheet(qss_path.read_text(encoding="utf-8"))

    def get_current_user_context(self) -> UserSessionContext:
        return self._user_ctx

    def _build_ui(self) -> None:
        central = QWidget()
        root_v = QVBoxLayout(central)
        root_v.setContentsMargins(0, 0, 0, 0)
        root_v.setSpacing(0)

        # 1. Top Header Bar
        header_frame = QFrame()
        header_frame.setObjectName("TopHeaderBar")
        header_frame.setFixedHeight(56)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(16, 8, 20, 8)
        header_layout.setSpacing(14)

        self.btn_toggle_sidebar = QPushButton("Thu gọn menu")
        self.btn_toggle_sidebar.clicked.connect(self.toggle_sidebar)
        header_layout.addWidget(self.btn_toggle_sidebar)

        title_lbl = QLabel("LAN PRINTER MANAGER")
        title_lbl.setObjectName("HeaderTitleLabel")
        header_layout.addWidget(title_lbl)

        header_layout.addStretch()

        self.header_db_badge = StatusBadge("DB: Đang kiểm tra...", "UNKNOWN")
        header_layout.addWidget(self.header_db_badge)

        btn_quick_db = QPushButton("Kiểm tra DB")
        btn_quick_db.clicked.connect(lambda: self.settings_page.test_db_connection())
        header_layout.addWidget(btn_quick_db)

        self.header_user_lbl = QLabel(self._format_user_header())
        self.header_user_lbl.setObjectName("HeaderUserLabel")
        header_layout.addWidget(self.header_user_lbl)

        root_v.addWidget(header_frame)

        # 2. Body Area (Left Sidebar + Stacked Content)
        body_h = QHBoxLayout()
        body_h.setContentsMargins(0, 0, 0, 0)
        body_h.setSpacing(0)

        self.sidebar_frame = QFrame()
        self.sidebar_frame.setObjectName("SidebarContainer")
        self.sidebar_frame.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(self.sidebar_frame)
        sidebar_layout.setContentsMargins(10, 16, 10, 16)
        sidebar_layout.setSpacing(6)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: list[QPushButton] = []

        for idx, (full_label, _short_label) in enumerate(self.NAV_ITEMS):
            btn = QPushButton(full_label)
            btn.setProperty("navButton", True)
            btn.setCheckable(True)
            if idx == 0:
                btn.setChecked(True)
            self.nav_group.addButton(btn, idx)
            self.nav_buttons.append(btn)
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()
        body_h.addWidget(self.sidebar_frame)

        # Stacked Pages
        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage(self.device_service, self.thread_pool, self)
        self.devices_page = DevicesPage(
            self._config,
            self.scan_service,
            self.device_service,
            self.monitoring_service,
            self.get_current_user_context,
            self.thread_pool,
            self,
        )
        self.printers_page = PrintersPage(
            self.printer_service,
            self.monitoring_service,
            self.thread_pool,
            self,
        )
        self.diagnostics_page = DiagnosticsPage(
            self.device_service,
            self.diagnostic_service,
            self.get_current_user_context,
            self.thread_pool,
            self,
        )
        self.tasks_page = TasksPage(
            self.device_service,
            self.task_service,
            self.get_current_user_context,
            self.thread_pool,
            self,
        )
        self.logs_page = LogsPage(self.audit_service, self.thread_pool, self)
        self.settings_page = SettingsPage(
            self._config,
            self._db_manager,
            self.audit_service,
            self._user_ctx,
            self.thread_pool,
            self,
        )

        for page in (
            self.dashboard_page,
            self.devices_page,
            self.printers_page,
            self.diagnostics_page,
            self.tasks_page,
            self.logs_page,
            self.settings_page,
        ):
            self.stack.addWidget(page)

        body_h.addWidget(self.stack, 1)
        root_v.addLayout(body_h, 1)
        self.setCentralWidget(central)

        # 3. Bottom Status Bar
        status_bar = QStatusBar()
        self.lbl_status_task = QLabel("Sẵn sàng.")
        status_bar.addWidget(self.lbl_status_task, 1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(240)
        self.progress_bar.setVisible(False)
        status_bar.addPermanentWidget(self.progress_bar)
        self.setStatusBar(status_bar)

    def _wire_signals(self) -> None:
        self.nav_group.idClicked.connect(self.switch_to_page)

        self.devices_page.inspect_device_requested.connect(self._open_printer_detail)
        self.devices_page.scan_progress_changed.connect(self._on_scan_progress)
        self.devices_page.scan_state_changed.connect(self._on_scan_state_changed)

        self.printers_page.open_diagnostics_for_device.connect(self._open_diagnostics_for_device)
        self.printers_page.open_tasks_for_device.connect(self._open_tasks_for_device)
        self.printers_page.status_message.connect(self.lbl_status_task.setText)

        self.diagnostics_page.dispatch_remediation_task.connect(
            self._open_tasks_for_device_with_type
        )
        self.diagnostics_page.status_message.connect(self.lbl_status_task.setText)

        self.tasks_page.status_message.connect(self.lbl_status_task.setText)

        self.settings_page.session_changed.connect(self._on_session_changed)
        self.settings_page.db_status_updated.connect(self._on_db_status_updated)

    def _format_user_header(self) -> str:
        return f"Tài khoản: {self._user_ctx.username} ({self._user_ctx.role.value})"

    def toggle_sidebar(self) -> None:
        self._sidebar_collapsed = not self._sidebar_collapsed
        if self._sidebar_collapsed:
            self.sidebar_frame.setFixedWidth(64)
            self.btn_toggle_sidebar.setText("Mở rộng menu")
            for idx, btn in enumerate(self.nav_buttons):
                btn.setText(self.NAV_ITEMS[idx][1])
        else:
            self.sidebar_frame.setFixedWidth(220)
            self.btn_toggle_sidebar.setText("Thu gọn menu")
            for idx, btn in enumerate(self.nav_buttons):
                btn.setText(self.NAV_ITEMS[idx][0])

    def switch_to_page(self, index: int) -> None:
        if not (0 <= index < self.stack.count()):
            return
        self.stack.setCurrentIndex(index)
        if index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)

        if index == 0:
            self.dashboard_page.refresh_dashboard()
        elif index == 1:
            self.devices_page.load_devices()
        elif index == 2:
            self.printers_page.load_printers()
        elif index == 3:
            if self.diagnostics_page.device_combo.count() == 0:
                self.diagnostics_page.load_device_choices()
        elif index == 4:
            if self.tasks_page.device_combo.count() == 0:
                self.tasks_page.refresh_page_data()
        elif index == 5:
            self.logs_page.load_logs()

    def _open_printer_detail(self, device_id: UUID) -> None:
        self.stack.setCurrentIndex(2)
        self.nav_buttons[2].setChecked(True)
        self.printers_page.select_printer_by_id(device_id)

    def _open_diagnostics_for_device(self, device_id: UUID) -> None:
        self.stack.setCurrentIndex(3)
        self.nav_buttons[3].setChecked(True)
        dev = next(
            (
                d
                for d in self.printers_page._printers
                if d.id == device_id or str(d.id) == str(device_id)
            ),
            None,
        )
        if dev is None:
            dev = next(
                (
                    d
                    for d in self.devices_page._all_loaded_devices
                    if d.id == device_id or str(d.id) == str(device_id)
                ),
                None,
            )
        self.diagnostics_page.select_and_diagnose(device_id, device_hint=dev, auto_run=True)

    def _open_tasks_for_device(self, device_id: UUID) -> None:
        self.stack.setCurrentIndex(4)
        self.nav_buttons[4].setChecked(True)
        dev = next(
            (
                d
                for d in self.printers_page._printers
                if d.id == device_id or str(d.id) == str(device_id)
            ),
            None,
        )
        if dev is None:
            dev = next(
                (
                    d
                    for d in self.devices_page._all_loaded_devices
                    if d.id == device_id or str(d.id) == str(device_id)
                ),
                None,
            )
        self.tasks_page.refresh_page_data(preselect_device_id=device_id, device_hint=dev)

    def _open_tasks_for_device_with_type(self, device_id: UUID, task_key: str) -> None:
        self.stack.setCurrentIndex(4)
        self.nav_buttons[4].setChecked(True)
        dev = next(
            (
                d
                for d in self.printers_page._printers
                if d.id == device_id or str(d.id) == str(device_id)
            ),
            None,
        )
        if dev is None:
            dev = next(
                (
                    d
                    for d in self.devices_page._all_loaded_devices
                    if d.id == device_id or str(d.id) == str(device_id)
                ),
                None,
            )
        self.tasks_page.refresh_page_data(
            preselect_device_id=device_id, preselect_task_key=task_key, device_hint=dev
        )

    def _on_scan_progress(self, current: int, total: int, detail: str) -> None:
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(max(1, total))
        self.progress_bar.setValue(current)
        self.lbl_status_task.setText(f"Đang quét mạng: {current}/{total} IP — {detail}")

    def _on_scan_state_changed(self, is_running: bool, message: str) -> None:
        self.progress_bar.setVisible(is_running)
        self.lbl_status_task.setText(message)

    def _on_session_changed(self, new_ctx: UserSessionContext) -> None:
        self._user_ctx = new_ctx
        self.header_user_lbl.setText(self._format_user_header())
        self.lbl_status_task.setText(
            f"Đã chuyển phiên làm việc sang {new_ctx.username} ({new_ctx.role.label_vi})."
        )

    def _on_db_status_updated(self, ok: bool, msg: str) -> None:
        if ok:
            self.header_db_badge.update_badge("PostgreSQL: Đã kết nối", "CONNECTED")
        else:
            self.header_db_badge.update_badge("PostgreSQL: Mất kết nối", "DISCONNECTED")
        self.lbl_status_task.setText(msg)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.devices_page.cancel_lan_scan()
        self.thread_pool.waitForDone(2000)
        super().closeEvent(event)
