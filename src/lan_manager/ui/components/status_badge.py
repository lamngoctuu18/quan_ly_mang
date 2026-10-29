"""Consistent semantic status badge widget for devices, diagnostics, and remote tasks."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QLabel, QWidget


def style_for_status(status_key: str) -> tuple[str, str, str]:
    """
    Return (background_hex, text_hex, border_hex) for a given status or severity string.
    Ensures enterprise-wide visual consistency.
    """
    key = (status_key or "UNKNOWN").upper()
    if key in {"ONLINE", "NORMAL", "SUCCEEDED", "SUCCESS", "CONNECTED"}:
        return "#DCFCE7", "#15803D", "#86EFAC"
    if key in {"WARNING", "RUNNING", "PENDING", "MEDIUM"}:
        return "#FEF3C7", "#B45309", "#FDE68A"
    if key in {
        "OFFLINE",
        "ERROR",
        "FAILED",
        "DENIED",
        "VERIFICATION_FAILED",
        "DISCONNECTED",
        "HIGH",
    }:
        return "#FEE2E2", "#B91C1C", "#FCA5A5"
    return "#F1F5F9", "#475569", "#CBD5E1"


def colors_for_table_status(status_key: str) -> tuple[QColor, QColor]:
    """Return (background QColor, foreground QColor) for QAbstractTableModel cells."""
    bg, fg, _ = style_for_status(status_key)
    return QColor(bg), QColor(fg)


class StatusBadge(QLabel):
    """Pill-style status badge used across headers, cards, and detail panels."""

    def __init__(
        self, text: str = "UNKNOWN", status_key: str = "UNKNOWN", parent: QWidget | None = None
    ) -> None:
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.update_badge(text, status_key)

    def update_badge(self, text: str, status_key: str) -> None:
        bg, fg, border = style_for_status(status_key)
        self.setText(text)
        self.setStyleSheet(
            f"QLabel {{"
            f"  background-color: {bg};"
            f"  color: {fg};"
            f"  border: 1px solid {border};"
            f"  border-radius: 4px;"
            f"  padding: 3px 8px;"
            f"  font-weight: 600;"
            f"  font-size: 11px;"
            f"}}"
        )
