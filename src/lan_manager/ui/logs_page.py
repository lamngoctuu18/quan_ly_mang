"""Audit Logs inspection page displaying immutable administrative records from PostgreSQL."""

from __future__ import annotations

import json

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.services.audit_service import AuditService
from lan_manager.domain.enums.system_enums import AuditResult
from lan_manager.domain.models.entities import AuditLog
from lan_manager.ui.components.status_badge import colors_for_table_status
from lan_manager.ui.workers import ServiceWorker


class LogsPage(QWidget):
    """
    Searchable, filterable viewer for the immutable PostgreSQL audit_logs table.
    Displays sanitized JSON metadata without exposing sensitive credentials.
    """

    def __init__(
        self,
        audit_service: AuditService,
        thread_pool: QThreadPool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._audit_service = audit_service
        self._thread_pool = thread_pool
        self._logs: list[AuditLog] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        # Header
        header_row = QHBoxLayout()
        title_lbl = QLabel("Nhật ký hoạt động quản trị (Immutable Audit Logs)")
        title_lbl.setProperty("pageTitle", True)
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        self.btn_refresh = QPushButton("Làm mới nhật ký")
        self.btn_refresh.setProperty("primary", True)
        self.btn_refresh.clicked.connect(self.load_logs)
        header_row.addWidget(self.btn_refresh)
        root.addLayout(header_row)

        # Filter Row
        filter_card = QFrame()
        filter_card.setProperty("card", True)
        filter_row = QHBoxLayout(filter_card)
        filter_row.setContentsMargins(14, 10, 14, 10)
        filter_row.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Tìm theo người thao tác, hành động, đối tượng...")
        self.search_input.returnPressed.connect(self.load_logs)
        filter_row.addWidget(self.search_input, 2)

        filter_row.addWidget(QLabel("Kết quả:"))
        self.result_combo = QComboBox()
        self.result_combo.addItem("Tất cả kết quả", None)
        for res in AuditResult:
            self.result_combo.addItem(res.value, res)
        self.result_combo.currentIndexChanged.connect(self.load_logs)
        filter_row.addWidget(self.result_combo)

        btn_search = QPushButton("Lọc")
        btn_search.clicked.connect(self.load_logs)
        filter_row.addWidget(btn_search)
        root.addWidget(filter_card)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Audit Table
        self.logs_table = QTableWidget(0, 6)
        self.logs_table.setHorizontalHeaderLabels(
            ["ID", "Thời gian", "Tài khoản", "Hành động", "Đối tượng", "Kết quả"]
        )
        self.logs_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.logs_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.logs_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self.logs_table)

        # Metadata JSON Inspector
        meta_card = QFrame()
        meta_card.setProperty("card", True)
        meta_layout = QVBoxLayout(meta_card)
        lbl_meta = QLabel("Chi tiết Metadata an toàn (Đã lọc bỏ thông tin nhạy cảm)")
        lbl_meta.setProperty("sectionTitle", True)
        meta_layout.addWidget(lbl_meta)

        self.meta_viewer = QPlainTextEdit()
        self.meta_viewer.setReadOnly(True)
        meta_layout.addWidget(self.meta_viewer, 1)
        splitter.addWidget(meta_card)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

    def load_logs(self) -> None:
        search_q = self.search_input.text().strip() or None
        res_filter = self.result_combo.currentData()

        worker = ServiceWorker(
            "Tải nhật ký kiểm toán",
            self._audit_service.list_audit_logs,
            search_query=search_q,
            result_filter=res_filter,
            limit=200,
        )
        worker.signals.result.connect(self._on_logs_loaded)
        self._thread_pool.start(worker)

    def _on_logs_loaded(self, data: tuple[list[AuditLog], int]) -> None:
        logs, _ = data
        self._logs = logs
        self.logs_table.setRowCount(len(logs))
        for r_idx, entry in enumerate(logs):
            ts_str = entry.created_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            res_item = QTableWidgetItem(entry.result.value)
            bg, fg = colors_for_table_status(entry.result.value)
            res_item.setBackground(bg)
            res_item.setForeground(fg)

            self.logs_table.setItem(r_idx, 0, QTableWidgetItem(str(entry.id or "")))
            self.logs_table.setItem(r_idx, 1, QTableWidgetItem(ts_str))
            self.logs_table.setItem(r_idx, 2, QTableWidgetItem(entry.username))
            self.logs_table.setItem(r_idx, 3, QTableWidgetItem(entry.action))
            self.logs_table.setItem(
                r_idx, 4, QTableWidgetItem(f"{entry.target_type}: {entry.target_id}")
            )
            self.logs_table.setItem(r_idx, 5, res_item)

        if logs:
            self.logs_table.selectRow(0)
        else:
            self.meta_viewer.setPlainText("{}")

    def _on_row_selected(self, current_row: int, _col: int, _prev_row: int, _prev_col: int) -> None:
        if 0 <= current_row < len(self._logs):
            entry = self._logs[current_row]
            formatted = json.dumps(entry.safe_metadata, indent=2, ensure_ascii=False)
            self.meta_viewer.setPlainText(formatted)
