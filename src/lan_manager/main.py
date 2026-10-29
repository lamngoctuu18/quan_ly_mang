"""Application entrypoint for LAN Printer Manager."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure 'src' directory is on sys.path even when executed directly without 'pip install -e .'
_SRC_DIR = str(Path(__file__).resolve().parents[1])
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

try:
    from PySide6.QtWidgets import QApplication
except ModuleNotFoundError as exc:
    sys.stderr.write(
        "\n[LỖI THIẾU THƯ VIỆN GIAO DIỆN] Chưa cài đặt PySide6 trong môi trường Python hiện tại.\n"
        "Vui lòng chạy lệnh sau để cài đặt đầy đủ thư viện trước khi mở ứng dụng:\n\n"
        "    pip install -r requirements.txt\n\n"
    )
    raise SystemExit(1) from exc

from PySide6.QtCore import QTimer

from lan_manager.core.config import get_config
from lan_manager.core.logging_config import get_logger, setup_logging
from lan_manager.infrastructure.database.connection import get_db_manager
from lan_manager.ui.main_window import MainWindow


def main() -> int:
    """Initialize configuration, logging, database manager, and launch the PySide6 desktop UI."""
    config = get_config()
    setup_logging(config)
    logger = get_logger("main")

    logger.info("Khởi động ứng dụng %s (Môi trường: %s)", config.app_name, config.app_env)
    db_manager = get_db_manager(config)

    app = QApplication(sys.argv)
    app.setApplicationName(config.app_name)

    # Directly show the main window with zero splash overhead
    window = MainWindow(config=config, db_manager=db_manager)
    window.show()

    # Defer background database loading until AFTER the window is visible
    QTimer.singleShot(50, window.deferred_startup)

    exit_code = app.exec()
    db_manager.dispose()
    logger.info("Ứng dụng %s đã đóng (mã thoát: %d).", config.app_name, exit_code)
    return int(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
