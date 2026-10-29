"""Integration tests for PostgreSQL connection health checks and UI state transitions."""

from __future__ import annotations

import os
import unittest

from lan_manager.core.config import AppConfig
from lan_manager.domain.enums.system_enums import DeviceStatusEnum, DeviceType
from lan_manager.domain.models.entities import Device
from lan_manager.infrastructure.database.base import Base
from lan_manager.infrastructure.database.connection import DatabaseManager
from lan_manager.infrastructure.database.repositories import DeviceRepository


class TestPostgresConnectionAndIntegration(unittest.TestCase):
    """
    Tests PostgreSQL connection handling:
    - Verifies non-blocking behavior when PostgreSQL is unreachable (e.g. wrong port).
    - Runs live PostgreSQL persistence tests if TEST_DATABASE_URL is configured and reachable.
    """

    def test_unreachable_postgres_fails_fast_without_hanging(self) -> None:
        bad_config = AppConfig(
            db_host="127.0.0.1",
            db_port=59999,  # Unused port
            db_name="nonexistent_db",
            db_user="no_user",
            db_password="no_password",
            db_connect_timeout=1,
        )
        mgr = DatabaseManager(config=bad_config)
        try:
            ok, msg = mgr.check_connection()
            self.assertFalse(ok)
            self.assertIn("Không thể kết nối DB", msg)
        finally:
            mgr.dispose()

    def test_ui_components_and_main_window_states(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication

        from lan_manager.ui.components.device_table_model import (
            DeviceSortFilterProxyModel,
            DeviceTableModel,
        )
        from lan_manager.ui.components.status_badge import StatusBadge, style_for_status

        app = QApplication.instance() or QApplication([])

        # Verify status badge semantic color tokens for RUNNING, SUCCEEDED, FAILED
        bg_run, _, _ = style_for_status("RUNNING")
        bg_ok, _, _ = style_for_status("SUCCEEDED")
        bg_err, _, _ = style_for_status("FAILED")
        self.assertNotEqual(bg_run, bg_ok)
        self.assertNotEqual(bg_ok, bg_err)

        badge = StatusBadge("ĐANG CHẠY", "RUNNING")
        self.assertEqual(badge.text(), "ĐANG CHẠY")
        badge.update_badge("THÀNH CÔNG", "SUCCEEDED")
        self.assertEqual(badge.text(), "THÀNH CÔNG")

        # Verify DeviceTableModel & numerical IP sorting in proxy model
        d1 = Device(
            ip_address="192.168.1.10",
            hostname="PRN-10",
            device_type=DeviceType.PRINTER,
            status=DeviceStatusEnum.ONLINE,
        )
        d2 = Device(
            ip_address="192.168.1.2",
            hostname="PRN-02",
            device_type=DeviceType.PRINTER,
            status=DeviceStatusEnum.OFFLINE,
        )
        model = DeviceTableModel([d1, d2])
        proxy = DeviceSortFilterProxyModel()
        proxy.setSourceModel(model)
        proxy.sort(DeviceTableModel.COL_IP, Qt.SortOrder.AscendingOrder)

        first_ip = proxy.data(proxy.index(0, DeviceTableModel.COL_IP))
        second_ip = proxy.data(proxy.index(1, DeviceTableModel.COL_IP))
        self.assertEqual(first_ip, "192.168.1.2")
        self.assertEqual(second_ip, "192.168.1.10")
        self.assertIsNotNone(app)

    def test_postgres_test_database_roundtrip_if_available(self) -> None:
        test_db_url = os.getenv("TEST_DATABASE_URL", "").strip()
        if not test_db_url or "CHANGE_ME" in test_db_url:
            return

        mgr = DatabaseManager(db_url_override=test_db_url)
        try:
            ok, _ = mgr.check_connection()
            if not ok:
                return
            engine = mgr.get_engine()
            Base.metadata.create_all(bind=engine)
            with mgr.session_scope() as session:
                repo = DeviceRepository(session)
                dev, _ = repo.upsert_scanned_device(
                    ip_address="192.168.100.10",
                    status=DeviceStatusEnum.ONLINE,
                    device_type=DeviceType.PRINTER,
                    hostname="INTEGRATION-TEST-PRN",
                )
                self.assertEqual(dev.ip_address, "192.168.100.10")
        finally:
            mgr.dispose()


if __name__ == "__main__":
    unittest.main()
