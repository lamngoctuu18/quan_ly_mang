"""System Settings, PostgreSQL Connection Tester, and RBAC Session Management page."""

from __future__ import annotations

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.services.audit_service import AuditService
from lan_manager.core.config import AppConfig
from lan_manager.core.security import UserSessionContext
from lan_manager.domain.enums.system_enums import RoleType
from lan_manager.infrastructure.database.base import Base
from lan_manager.infrastructure.database.connection import DatabaseManager
from lan_manager.ui.components.status_badge import StatusBadge
from lan_manager.ui.workers import ServiceWorker


class SettingsPage(QWidget):
    """
    Allows administrators to:
    - Verify PostgreSQL connectivity & initialize schema tables safely.
    - Authenticate with a database user account or switch RBAC operator session role.
    - Inspect and update allowed CIDR scan subnets at runtime.
    """

    session_changed = Signal(object)
    db_status_updated = Signal(bool, str)

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
        audit_service: AuditService,
        current_user_ctx: UserSessionContext,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._db_manager = db_manager
        self._audit_service = audit_service
        self._user_ctx = current_user_ctx
        self._thread_pool = thread_pool

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(16)

        title_lbl = QLabel("Cài đặt hệ thống, Cơ sở dữ liệu & Phân quyền RBAC")
        title_lbl.setProperty("pageTitle", True)
        root.addWidget(title_lbl)

        # 1. PostgreSQL Connection Card
        db_card = QFrame()
        db_card.setProperty("card", True)
        db_layout = QVBoxLayout(db_card)
        db_layout.setContentsMargins(16, 14, 16, 14)
        db_layout.setSpacing(10)

        lbl_db = QLabel("1. Trạng thái kết nối PostgreSQL")
        lbl_db.setProperty("sectionTitle", True)
        db_layout.addWidget(lbl_db)

        db_form = QFormLayout()
        db_form.addRow(
            "URI kết nối (Đã ẩn mật khẩu):",
            QLabel(self._config.get_database_url(hide_password=True)),
        )
        self.db_status_badge = StatusBadge("CHƯA KIỂM TRA", "UNKNOWN")
        db_form.addRow("Trạng thái hiện tại:", self.db_status_badge)
        db_layout.addLayout(db_form)

        db_btn_row = QHBoxLayout()
        self.btn_test_db = QPushButton("Kiểm tra kết nối PostgreSQL")
        self.btn_test_db.setProperty("primary", True)
        self.btn_test_db.clicked.connect(self.test_db_connection)
        db_btn_row.addWidget(self.btn_test_db)

        self.btn_sync_schema = QPushButton("Đồng bộ bảng dữ liệu (Create Tables if Missing)")
        self.btn_sync_schema.clicked.connect(self.sync_database_schema)
        db_btn_row.addWidget(self.btn_sync_schema)
        db_btn_row.addStretch()
        db_layout.addLayout(db_btn_row)
        root.addWidget(db_card)

        # 2. Authentication & RBAC Session Card
        auth_card = QFrame()
        auth_card.setProperty("card", True)
        auth_layout = QVBoxLayout(auth_card)
        auth_layout.setContentsMargins(16, 14, 16, 14)
        auth_layout.setSpacing(10)

        lbl_auth = QLabel("2. Phiên làm việc & Phân quyền người vận hành (Least Privilege RBAC)")
        lbl_auth.setProperty("sectionTitle", True)
        auth_layout.addWidget(lbl_auth)

        auth_form = QFormLayout()
        self.lbl_current_session = QLabel(
            f"{self._user_ctx.username} — {self._user_ctx.role.label_vi}"
        )
        auth_form.addRow("Phiên hiện tại:", self.lbl_current_session)

        self.login_user_edit = QLineEdit(self._user_ctx.username)
        auth_form.addRow("Tên đăng nhập DB:", self.login_user_edit)

        self.login_pass_edit = QLineEdit()
        self.login_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_pass_edit.setPlaceholderText("Nhập mật khẩu tài khoản trong bảng users...")
        auth_form.addRow("Mật khẩu:", self.login_pass_edit)

        self.role_switch_combo = QComboBox()
        for r in RoleType:
            self.role_switch_combo.addItem(r.label_vi, r)
        idx = self.role_switch_combo.findData(self._user_ctx.role)
        if idx >= 0:
            self.role_switch_combo.setCurrentIndex(idx)
        auth_form.addRow("Hoặc chuyển vai trò kiểm thử RBAC:", self.role_switch_combo)
        auth_layout.addLayout(auth_form)

        auth_btn_row = QHBoxLayout()
        btn_db_login = QPushButton("Đăng nhập qua PostgreSQL")
        btn_db_login.setProperty("primary", True)
        btn_db_login.clicked.connect(self._login_with_db)
        auth_btn_row.addWidget(btn_db_login)

        btn_switch_role = QPushButton("Áp dụng vai trò phiên hiện tại")
        btn_switch_role.clicked.connect(self._apply_role_switch)
        auth_btn_row.addWidget(btn_switch_role)
        auth_btn_row.addStretch()
        auth_layout.addLayout(auth_btn_row)
        root.addWidget(auth_card)

        # 3. Network & SNMP Policy Card
        net_card = QFrame()
        net_card.setProperty("card", True)
        net_layout = QVBoxLayout(net_card)
        net_layout.setContentsMargins(16, 14, 16, 14)
        net_layout.setSpacing(10)

        lbl_net = QLabel("3. Chính sách giới hạn quét mạng LAN & SNMP")
        lbl_net.setProperty("sectionTitle", True)
        net_layout.addWidget(lbl_net)

        net_form = QFormLayout()
        self.subnets_edit = QLineEdit(", ".join(self._config.allowed_scan_subnets))
        net_form.addRow("Danh sách CIDR được phép quét:", self.subnets_edit)
        net_form.addRow("Giới hạn số host mỗi lần quét:", QLabel(str(self._config.max_scan_hosts)))
        net_form.addRow("Số luồng thăm dò tối đa:", QLabel(str(self._config.max_concurrent_probes)))
        net_form.addRow(
            "Giới hạn tốc độ (Rate limit):",
            QLabel(f"{self._config.scan_rate_limit_per_sec} IP/giây"),
        )
        net_form.addRow(
            "Cổng SNMP & Timeout:",
            QLabel(f"UDP {self._config.snmp_port} ({self._config.snmp_timeout_sec}s)"),
        )
        net_layout.addLayout(net_form)

        btn_save_subnets = QPushButton("Cập nhật danh sách dải CIDR cho phép")
        btn_save_subnets.clicked.connect(self._update_allowed_subnets)
        net_layout.addWidget(btn_save_subnets)

        root.addWidget(net_card)
        root.addStretch()

    def test_db_connection(self) -> None:
        self.btn_test_db.setEnabled(False)
        worker = ServiceWorker("Kiểm tra kết nối DB", self._db_manager.check_connection)
        worker.signals.result.connect(self._on_db_checked)
        worker.signals.finished_task.connect(lambda: self.btn_test_db.setEnabled(True))
        self._thread_pool.start(worker)

    def _on_db_checked(self, result: tuple[bool, str]) -> None:
        ok, msg = result
        self.db_status_badge.update_badge(msg, "CONNECTED" if ok else "DISCONNECTED")
        self.db_status_updated.emit(ok, msg)

    def sync_database_schema(self) -> None:
        def _create_tables() -> str:
            ok, msg = self._db_manager.check_connection()
            if not ok:
                raise RuntimeError(msg)
            engine = self._db_manager.get_engine()
            Base.metadata.create_all(bind=engine)
            return "Đã khởi tạo và đồng bộ đầy đủ các bảng PostgreSQL."

        worker = ServiceWorker("Đồng bộ schema PostgreSQL", _create_tables)
        worker.signals.result.connect(
            lambda msg: (
                QMessageBox.information(self, "Thành công", msg),
                self.test_db_connection(),
            )
        )
        worker.signals.error.connect(
            lambda err, _: QMessageBox.warning(self, "Không thể đồng bộ bảng", err)
        )
        self._thread_pool.start(worker)

    def _login_with_db(self) -> None:
        username = self.login_user_edit.text().strip()
        password = self.login_pass_edit.text()
        try:
            new_ctx = self._audit_service.authenticate_user(username, password)
            self._user_ctx = new_ctx
            self.lbl_current_session.setText(f"{new_ctx.username} — {new_ctx.role.label_vi}")
            self.login_pass_edit.clear()
            self.session_changed.emit(new_ctx)
            QMessageBox.information(
                self,
                "Đăng nhập thành công",
                f"Đã xác thực tài khoản {new_ctx.username} ({new_ctx.role.label_vi}).",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Đăng nhập thất bại", str(exc))

    def _apply_role_switch(self) -> None:
        role: RoleType = self.role_switch_combo.currentData()
        username = self.login_user_edit.text().strip() or "operator"
        new_ctx = AuditService.create_default_session(role=role, username=username)
        self._user_ctx = new_ctx
        self.lbl_current_session.setText(f"{new_ctx.username} — {new_ctx.role.label_vi}")
        self.session_changed.emit(new_ctx)

    def _update_allowed_subnets(self) -> None:
        raw = self.subnets_edit.text()
        subnets = [s.strip() for s in raw.split(",") if s.strip()]
        try:
            validated = AppConfig.validate_subnets(subnets)
            self._config.allowed_scan_subnets = validated
            QMessageBox.information(
                self,
                "Đã cập nhật",
                f"Danh sách dải mạng cho phép quét hiện tại: {', '.join(validated)}",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Dải mạng không hợp lệ", str(exc))
