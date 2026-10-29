"""Unit tests for SNMPv2c ASN.1 BER encoding/decoding, ScanService persistence, User Authentication, and UI status styles."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from lan_manager.application.services.audit_service import AuditService
from lan_manager.application.services.device_service import DeviceService
from lan_manager.application.services.scan_service import ScanService
from lan_manager.domain.enums.system_enums import (
    DeviceStatusEnum,
    DeviceType,
    RoleType,
)
from lan_manager.domain.exceptions import AuthenticationError
from lan_manager.infrastructure.database.repositories import UserRepository
from lan_manager.infrastructure.network.scanner import DiscoveredHostInfo
from lan_manager.infrastructure.network.snmp_client import (
    HR_DEVICE_PRINTER_OID,
    OID_SYS_DESCR,
    SNMPDeviceProfile,
    _build_snmpv2c_get_packet,
    _encode_integer,
    _encode_oid,
    _encode_tlv,
    _parse_snmpv2c_response,
)
from tests.conftest import create_isolated_test_db_manager


class TestSNMPScanServiceAndAuth(unittest.TestCase):
    """Tests SNMP packet codec, ScanService end-to-end persistence, user auth, and dashboard counts."""

    def setUp(self) -> None:
        self.config, self.db = create_isolated_test_db_manager()

    def tearDown(self) -> None:
        self.db.dispose()

    def test_snmpv2c_packet_encode_and_response_decode(self) -> None:
        req_pkt = _build_snmpv2c_get_packet("public", [OID_SYS_DESCR], request_id=12345)
        self.assertTrue(req_pkt.startswith(b"\x30"))

        # Construct a valid ASN.1 BER GetResponse-PDU (0xA2) packet
        varbind = _encode_tlv(
            0x30,
            _encode_oid(OID_SYS_DESCR) + _encode_tlv(0x04, b"HP LaserJet Pro M404dn"),
        )
        varbind_list = _encode_tlv(0x30, varbind)
        pdu = _encode_tlv(
            0xA2,
            _encode_integer(12345) + _encode_integer(0) + _encode_integer(0) + varbind_list,
        )
        resp_pkt = _encode_tlv(
            0x30,
            _encode_integer(1) + _encode_tlv(0x04, b"public") + pdu,
        )

        parsed = _parse_snmpv2c_response(resp_pkt)
        self.assertIn(OID_SYS_DESCR, parsed)
        self.assertEqual(parsed[OID_SYS_DESCR], b"HP LaserJet Pro M404dn")

    def test_scan_service_persists_devices_printers_and_dashboard_kpis(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan_cidr.return_value = [
            DiscoveredHostInfo(
                ip_address="192.168.1.10",
                is_alive=True,
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.WORKSTATION,
                hostname="PC-HR-01",
                mac_address="00:14:22:AA:BB:CC",
                manufacturer="Dell Inc.",
                open_ports=[445, 135],
                supported_protocols=["SMB_445", "RPC_135"],
                classification_reason="Windows SMB/RPC",
            ),
            DiscoveredHostInfo(
                ip_address="192.168.1.50",
                is_alive=True,
                status=DeviceStatusEnum.ONLINE,
                device_type=DeviceType.PRINTER,
                hostname="PRN-HR-LASER",
                mac_address="00:1B:78:12:34:56",
                manufacturer="HP Inc.",
                model="HP LaserJet M404dn",
                open_ports=[9100, 631, 80],
                supported_protocols=["RAW_9100", "IPP_631", "HTTP_80"],
                snmp_profile=SNMPDeviceProfile(
                    reachable=True,
                    hr_device_type=HR_DEVICE_PRINTER_OID,
                    printer_name="HP LaserJet M404dn",
                    serial_number="VNB3K11223",
                    page_count=4320,
                ),
                classification_reason="Verified SNMP Printer-MIB",
            ),
        ]

        scan_service = ScanService(
            config=self.config,
            db_manager=self.db,
            scanner=mock_scanner,
        )
        tech_ctx = AuditService.create_default_session(role=RoleType.TECHNICIAN, username="tech01")
        summary = scan_service.scan_and_persist(tech_ctx, "192.168.1.0/28")

        self.assertEqual(summary.alive_count, 2)
        self.assertEqual(summary.new_devices_count, 2)
        self.assertEqual(summary.printers_found, 1)

        device_service = DeviceService(self.db)
        dashboard = device_service.get_dashboard_summary()
        self.assertEqual(dashboard.total_devices, 2)
        self.assertEqual(dashboard.total_printers, 1)
        self.assertEqual(dashboard.online_devices, 2)
        self.assertEqual(dashboard.offline_devices, 0)

    def test_user_authentication_and_audit_trail(self) -> None:
        with self.db.session_scope() as session:
            user_repo = UserRepository(session)
            user_repo.create_user(
                username="operator01",
                plain_password="StrongPassword!2026",
                role_type=RoleType.OPERATOR,
                full_name="Nguyen Van A",
            )

        audit_service = AuditService(self.db)
        ctx = audit_service.authenticate_user("operator01", "StrongPassword!2026")
        self.assertEqual(ctx.username, "operator01")
        self.assertEqual(ctx.role, RoleType.OPERATOR)

        with self.assertRaises(AuthenticationError):
            audit_service.authenticate_user("operator01", "WrongPassword")

        logs, total = audit_service.list_audit_logs(search_query="operator01")
        self.assertGreaterEqual(total, 2)


if __name__ == "__main__":
    unittest.main()
