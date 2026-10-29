"""Confirmation dialog for medium/high-risk administrative remediation tasks."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from lan_manager.application.dto.schemas import TaskDefinitionDTO
from lan_manager.domain.models.entities import Device
from lan_manager.ui.components.status_badge import StatusBadge


class TaskConfirmationDialog(QDialog):
    """
    Prompts the operator to review task details, prerequisites, risk level,
    and explicitly confirm before executing an administrative remediation task.
    """

    def __init__(
        self,
        device: Device,
        task_def: TaskDefinitionDTO,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Xác nhận thực thi tác vụ quản trị")
        self.setMinimumWidth(520)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header_lbl = QLabel("Xác nhận thao tác quản trị hệ thống")
        header_lbl.setProperty("sectionTitle", True)
        layout.addWidget(header_lbl)

        info_card = QFrame()
        info_card.setProperty("card", True)
        form = QFormLayout(info_card)
        form.setContentsMargins(14, 14, 14, 14)
        form.setSpacing(10)

        target_text = f"{device.ip_address} ({device.hostname or 'Không có hostname'})"
        form.addRow("Thiết bị đích:", QLabel(target_text))
        form.addRow("Tên tác vụ:", QLabel(f"{task_def.title} [{task_def.task_type.value}]"))

        desc_lbl = QLabel(task_def.description)
        desc_lbl.setWordWrap(True)
        form.addRow("Mô tả:", desc_lbl)

        prereq_lbl = QLabel(task_def.prerequisite_desc)
        prereq_lbl.setWordWrap(True)
        form.addRow("Điều kiện tiên quyết:", prereq_lbl)

        form.addRow("Quyền yêu cầu:", QLabel(task_def.required_role.label_vi))

        risk_badge = StatusBadge(
            text=f"Mức rủi ro: {task_def.risk_level.label_vi}",
            status_key=task_def.risk_level.value,
        )
        form.addRow("Đánh giá rủi ro:", risk_badge)

        verify_lbl = QLabel(task_def.post_verify_desc)
        verify_lbl.setWordWrap(True)
        form.addRow("Kiểm tra sau thực thi:", verify_lbl)

        layout.addWidget(info_card)

        self.ack_checkbox = QCheckBox(
            "Tôi đã kiểm tra điều kiện tiên quyết và xác nhận thực thi tác vụ này trên thiết bị đích."
        )
        layout.addWidget(self.ack_checkbox)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Hủy bỏ")
        cancel_btn.clicked.connect(self.reject)

        self.confirm_btn = QPushButton("Xác nhận & Thực thi")
        self.confirm_btn.setProperty("primary", True)
        self.confirm_btn.setEnabled(False)
        self.confirm_btn.clicked.connect(self.accept)

        self.ack_checkbox.toggled.connect(self.confirm_btn.setEnabled)

        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self.confirm_btn)
        layout.addLayout(btn_row)
