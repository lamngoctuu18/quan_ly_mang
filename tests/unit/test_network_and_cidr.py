"""Unit tests for CIDR validation, TCP port checking, timeout handling, and evidence-based classification."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from lan_manager.core.config import AppConfig
from lan_manager.domain.enums.system_enums import DeviceStatusEnum, DeviceType
from lan_manager.domain.exceptions import SubnetNotAllowedError
from lan_manager.infrastructure.network.port_checker import (
    PortProbeSummary,
    check_tcp_port,
    probe_multiple_ports,
)
from lan_manager.infrastructure.network.scanner import classify_discovered_host
from lan_manager.infrastructure.network.snmp_client import (
    HR_DEVICE_PRINTER_OID,
    SNMPDeviceProfile,
    decode_printer_error_bits,
)


class TestNetworkAndCIDR(unittest.TestCase):
    """Tests CIDR validation, TCP port probing, timeouts, and printer classification rules."""

    def setUp(self) -> None:
        self.config = AppConfig(
            allowed_scan_subnets=["192.168.1.0/24", "10.10.0.0/16"],
            max_scan_hosts=256,
        )

    def test_valid_cidr_within_allowed_subnets(self) -> None:
        hosts = self.config.validate_scan_target("192.168.1.0/28")
        self.assertEqual(len(hosts), 14)
        self.assertEqual(str(hosts[0]), "192.168.1.1")

    def test_reject_public_internet_ip_scan(self) -> None:
        with self.assertRaises(SubnetNotAllowedError):
            self.config.validate_scan_target("8.8.8.0/24")

    def test_reject_subnet_not_in_allowlist(self) -> None:
        with self.assertRaises(SubnetNotAllowedError):
            self.config.validate_scan_target("192.168.99.0/24")

    def test_reject_subnet_exceeding_max_scan_hosts(self) -> None:
        with self.assertRaises(SubnetNotAllowedError):
            self.config.validate_scan_target("10.10.0.0/16")

    @patch("lan_manager.infrastructure.network.port_checker.socket.create_connection")
    def test_check_tcp_port_open_and_timeout(self, mock_conn: MagicMock) -> None:
        mock_conn.return_value.__enter__.return_value = MagicMock()
        is_open, latency = check_tcp_port("192.168.1.50", 9100, timeout_sec=0.5)
        self.assertTrue(is_open)
        self.assertIsNotNone(latency)

        mock_conn.side_effect = TimeoutError("timed out")
        is_open_timeout, latency_timeout = check_tcp_port("192.168.1.50", 9100, timeout_sec=0.5)
        self.assertFalse(is_open_timeout)
        self.assertIsNone(latency_timeout)

    @patch("lan_manager.infrastructure.network.port_checker.check_tcp_port")
    def test_probe_multiple_ports_maps_protocols(self, mock_check: MagicMock) -> None:
        def side_effect(_ip: str, port: int, timeout_sec: float = 1.0) -> tuple[bool, int | None]:
            if port in (9100, 631):
                return True, 3
            return False, None

        mock_check.side_effect = side_effect
        summary = probe_multiple_ports("192.168.1.50", ports=(9100, 631, 515, 445))
        self.assertEqual(summary.open_ports, [9100, 631])
        self.assertIn("RAW_9100", summary.supported_protocols)
        self.assertIn("IPP_631", summary.supported_protocols)
        self.assertEqual(summary.best_latency_ms, 3)

    def test_port_9100_alone_never_classifies_as_printer(self) -> None:
        """
        CRITICAL REQUIREMENT: Do not claim an IP is a printer solely because TCP 9100 is open.
        Without SNMP or vendor OUI verification, it must be classified as UNKNOWN.
        """
        port_summary = PortProbeSummary(
            ip_address="192.168.1.200",
            open_ports=[9100],
            best_latency_ms=4,
            supported_protocols=["RAW_9100"],
        )
        snmp_profile = SNMPDeviceProfile(reachable=False)
        dev_type, status, _reason = classify_discovered_host(
            port_summary=port_summary,
            snmp_profile=snmp_profile,
            mac_vendor=None,
            hostname=None,
        )
        self.assertEqual(dev_type, DeviceType.UNKNOWN)
        self.assertEqual(status, DeviceStatusEnum.WARNING)

    def test_snmp_verified_printer_classification(self) -> None:
        port_summary = PortProbeSummary(
            ip_address="192.168.1.55",
            open_ports=[9100, 80],
            best_latency_ms=2,
            supported_protocols=["RAW_9100", "HTTP_80"],
        )
        snmp_profile = SNMPDeviceProfile(
            reachable=True,
            sys_descr="HP ETHERNET MULTI-ENVIRONMENT",
            hr_device_type=HR_DEVICE_PRINTER_OID,
            printer_name="HP LaserJet Enterprise M608",
            serial_number="CNB1234567",
        )
        dev_type, status, _reason = classify_discovered_host(
            port_summary=port_summary,
            snmp_profile=snmp_profile,
        )
        self.assertEqual(dev_type, DeviceType.PRINTER)
        self.assertEqual(status, DeviceStatusEnum.ONLINE)

    def test_decode_printer_error_bitmask(self) -> None:
        # 0x40 = noPaper, 0x04 = jammed -> 0x44
        alerts = decode_printer_error_bits(b"\x44\x00")
        self.assertEqual(len(alerts), 2)
        self.assertTrue(any("noPaper" in a for a in alerts))
        self.assertTrue(any("jammed" in a for a in alerts))


if __name__ == "__main__":
    unittest.main()
