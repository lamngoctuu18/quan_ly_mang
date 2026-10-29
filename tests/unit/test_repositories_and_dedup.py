"""Unit tests for repositories, DHCP MAC/IP deduplication, transactions, and audit log sanitization."""

from __future__ import annotations

import unittest

from lan_manager.domain.enums.system_enums import AuditResult, DeviceStatusEnum, DeviceType
from lan_manager.infrastructure.database.repositories import (
    AuditRepository,
    DeviceRepository,
    PrinterRepository,
)
from tests.conftest import create_isolated_test_db_manager


class TestRepositoriesAndDeduplication(unittest.TestCase):
    """Verifies MAC/IP deduplication rules, transactional rollback, and audit secret scrubbing."""

    def setUp(self) -> None:
        self.config, self.db = create_isolated_test_db_manager()

    def tearDown(self) -> None:
        self.db.dispose()

    def test_upsert_same_ip_does_not_create_duplicate(self) -> None:
        with self.db.session_scope() as session:
            repo = DeviceRepository(session)
            dev1, created1 = repo.upsert_scanned_device(
                ip_address="192.168.1.50",
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.PRINTER,
                hostname="PRN-FLOOR1",
                mac_address="00-1b-78-aa-bb-cc",
            )
            self.assertTrue(created1)
            self.assertEqual(dev1.mac_address, "00:1B:78:AA:BB:CC")

        with self.db.session_scope() as session:
            repo = DeviceRepository(session)
            dev2, created2 = repo.upsert_scanned_device(
                ip_address="192.168.1.50",
                status=DeviceStatusEnum.WARNING,
                device_type=DeviceType.PRINTER,
                model="HP LaserJet M404dn",
            )
            self.assertFalse(created2)
            self.assertEqual(dev1.id, dev2.id)
            self.assertEqual(dev2.hostname, "PRN-FLOOR1")
            self.assertEqual(dev2.model, "HP LaserJet M404dn")
            self.assertEqual(dev2.status, DeviceStatusEnum.WARNING)

            all_devs, total = repo.list_devices()
            self.assertEqual(total, 1)
            self.assertEqual(len(all_devs), 1)

    def test_dhcp_ip_change_deduplicates_by_mac_address(self) -> None:
        """When a printer with a known MAC gets a new DHCP IP, update the existing record rather than duplicating."""
        with self.db.session_scope() as session:
            repo = DeviceRepository(session)
            original, created = repo.upsert_scanned_device(
                ip_address="192.168.1.50",
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.PRINTER,
                hostname="PRN-ACC-01",
                mac_address="00:80:77:11:22:33",
            )
            self.assertTrue(created)

        with self.db.session_scope() as session:
            repo = DeviceRepository(session)
            moved, created_after_move = repo.upsert_scanned_device(
                ip_address="192.168.1.88",
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.PRINTER,
                hostname="PRN-ACC-01",
                mac_address="00:80:77:11:22:33",
            )
            self.assertFalse(created_after_move)
            self.assertEqual(original.id, moved.id)
            self.assertEqual(moved.ip_address, "192.168.1.88")

            _, total = repo.list_devices()
            self.assertEqual(total, 1)

    def test_transaction_rolls_back_on_exception(self) -> None:
        try:
            with self.db.session_scope() as session:
                repo = DeviceRepository(session)
                repo.upsert_scanned_device(
                    ip_address="192.168.1.99",
                    status=DeviceStatusEnum.ONLINE,
                )
                raise RuntimeError("Simulated error mid-transaction")
        except RuntimeError:
            pass

        with self.db.session_scope() as session:
            repo = DeviceRepository(session)
            self.assertIsNone(repo.get_by_ip("192.168.1.99"))

    def test_audit_log_redacts_sensitive_credentials(self) -> None:
        with self.db.session_scope() as session:
            audit_repo = AuditRepository(session)
            log_entry = audit_repo.append(
                action="UPDATE_CONFIG",
                target_type="SYSTEM",
                target_id="settings",
                result=AuditResult.SUCCESS,
                username="admin",
                metadata={
                    "db_password": "SuperSecretPassword123",
                    "remote_shared_secret": "my_secret_key",
                    "snmp_community": "private_comm",
                    "allowed_subnet": "192.168.1.0/24",
                },
            )
            self.assertEqual(log_entry.safe_metadata["db_password"], "***REDACTED***")
            self.assertEqual(log_entry.safe_metadata["remote_shared_secret"], "***REDACTED***")
            self.assertEqual(log_entry.safe_metadata["snmp_community"], "***REDACTED***")
            self.assertEqual(log_entry.safe_metadata["allowed_subnet"], "192.168.1.0/24")

    def test_printer_repository_profile_attach(self) -> None:
        with self.db.session_scope() as session:
            dev_repo = DeviceRepository(session)
            prn_repo = PrinterRepository(session)
            dev, _ = dev_repo.upsert_scanned_device(
                ip_address="192.168.1.70",
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.PRINTER,
            )
            prn_repo.upsert_printer(
                device_id=dev.id,
                printer_name="Canon LBP2900",
                serial_number="SN-998877",
                supported_protocols=["RAW_9100"],
                snmp_enabled=True,
                metadata={"snmp_page_count": 1250},
            )

        with self.db.session_scope() as session:
            prn_repo = PrinterRepository(session)
            printers = prn_repo.list_printer_devices(search_query="LBP2900")
            self.assertEqual(len(printers), 1)
            self.assertIsNotNone(printers[0].printer_info)
            assert printers[0].printer_info is not None
            self.assertEqual(printers[0].printer_info.serial_number, "SN-998877")


if __name__ == "__main__":
    unittest.main()
