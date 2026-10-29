"""Controlled LAN scanner with rate limiting, concurrency bounds, cancellation, and evidence-based classification."""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.domain.enums.system_enums import DeviceStatusEnum, DeviceType
from lan_manager.infrastructure.network.port_checker import (
    DEFAULT_DISCOVERY_PORTS,
    PRINTER_PORTS,
    WORKSTATION_PORTS,
    PortProbeSummary,
    icmp_ping,
    lookup_arp_mac,
    lookup_vendor_by_mac,
    probe_multiple_ports,
    resolve_reverse_dns,
)
from lan_manager.infrastructure.network.snmp_client import SNMPClient, SNMPDeviceProfile

logger = get_logger(__name__)

_PRINTER_VENDORS = {
    "HP Inc.",
    "Canon Inc.",
    "Brother Industries",
    "Seiko Epson",
    "Ricoh Company",
    "Kyocera Document Solutions",
    "Fuji Xerox",
    "Konica Minolta",
    "Zebra Technologies",
    "Lexmark",
}


@dataclass
class DiscoveredHostInfo:
    """Comprehensive discovery result for a single scanned IP address."""

    ip_address: str
    is_alive: bool = False
    status: DeviceStatusEnum = DeviceStatusEnum.OFFLINE
    device_type: DeviceType = DeviceType.UNKNOWN
    hostname: str | None = None
    mac_address: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    location: str | None = None
    latency_ms: int | None = None
    open_ports: list[int] = field(default_factory=list)
    supported_protocols: list[str] = field(default_factory=list)
    snmp_profile: SNMPDeviceProfile = field(default_factory=SNMPDeviceProfile)
    classification_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def classify_discovered_host(
    port_summary: PortProbeSummary,
    snmp_profile: SNMPDeviceProfile,
    mac_vendor: str | None = None,
    hostname: str | None = None,
) -> tuple[DeviceType, DeviceStatusEnum, str]:
    """
    Evidence-based device classification.
    CRITICAL RULE: Never assert a device is a PRINTER solely because TCP port 9100 is open.
    Positive verification requires SNMP Printer-MIB / hrDevicePrinter, verified printer OUI/vendor
    combined with print protocols, or IPP/SNMP identity.
    """
    open_ports = set(port_summary.open_ports)
    has_print_ports = bool(open_ports.intersection(PRINTER_PORTS.keys()))
    has_workstation_ports = bool(open_ports.intersection(WORKSTATION_PORTS.keys()))

    # 1. Verified via SNMP Printer-MIB / Host-Resources-MIB
    if snmp_profile.is_verified_printer:
        if snmp_profile.detected_alerts:
            # Check if critical error (offline/noPaper/noToner/jammed/doorOpen) vs warning
            critical_keywords = ("Hết giấy", "Hết mực", "Kẹt giấy", "Offline", "Nắp máy")
            is_error = any(
                any(k in alert for k in critical_keywords) for alert in snmp_profile.detected_alerts
            )
            status = DeviceStatusEnum.ERROR if is_error else DeviceStatusEnum.WARNING
        else:
            status = DeviceStatusEnum.ONLINE
        return (
            DeviceType.PRINTER,
            status,
            "Xác minh qua SNMP Printer-MIB / Host-Resources-MIB",
        )

    # 2. Both Windows SMB/RPC ports AND print service ports open -> Print Server
    if has_workstation_ports and has_print_ports:
        return (
            DeviceType.PRINT_SERVER,
            DeviceStatusEnum.ONLINE,
            "Phát hiện cổng dịch vụ Windows (135/445) kết hợp cổng dịch vụ in",
        )

    # 3. Print port open + verified printer MAC OUI or IPP (631) + printer hostname prefix
    hostname_upper = (hostname or "").upper()
    has_printer_hostname = any(
        hostname_upper.startswith(prefix)
        for prefix in ("NPI", "PRN", "BRN", "BRW", "SEC", "CANON", "EPSON", "KM", "RNP")
    )
    if has_print_ports and (
        mac_vendor in _PRINTER_VENDORS or (631 in open_ports and has_printer_hostname)
    ):
        return (
            DeviceType.PRINTER,
            DeviceStatusEnum.ONLINE,
            f"Xác minh qua cổng in kết hợp định danh hãng ({mac_vendor or hostname})",
        )

    # 4. Only TCP 9100 / 515 open WITHOUT SNMP, OUI, or IPP verification -> UNKNOWN (do not guess PRINTER)
    if has_print_ports and not snmp_profile.reachable:
        return (
            DeviceType.UNKNOWN,
            DeviceStatusEnum.WARNING,
            "Mở cổng dịch vụ in (9100/515/631) nhưng chưa xác minh được qua SNMP hoặc OUI hãng",
        )

    # 5. Windows Workstation
    if has_workstation_ports:
        return (
            DeviceType.WORKSTATION,
            DeviceStatusEnum.ONLINE,
            "Phản hồi cổng dịch vụ Windows (SMB 445 / RPC 135)",
        )

    # 6. SNMP reachable non-printer network device (switch, router, gateway)
    if snmp_profile.reachable:
        return (
            DeviceType.NETWORK_DEVICE,
            DeviceStatusEnum.ONLINE,
            "Phản hồi SNMP MIB-II (Thiết bị mạng)",
        )

    return (
        DeviceType.UNKNOWN,
        DeviceStatusEnum.ONLINE,
        "Phản hồi kết nối mạng nhưng chưa đủ tín hiệu phân loại chuyên biệt",
    )


class ControlledNetworkScanner:
    """
    Executes bounded, cancellable, rate-limited LAN discovery across authorized CIDR ranges.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        snmp_client: SNMPClient | None = None,
    ) -> None:
        self._config = config or get_config()
        self._snmp_client = snmp_client or SNMPClient(
            community=self._config.snmp_community,
            port=self._config.snmp_port,
            timeout_sec=self._config.snmp_timeout_sec,
            retries=self._config.snmp_retries,
        )
        self._rate_lock = threading.Lock()
        self._last_probe_time = 0.0

    def _throttle(self) -> None:
        """Token-interval rate limiter to avoid flooding the LAN switch."""
        min_interval = 1.0 / max(1, self._config.scan_rate_limit_per_sec)
        with self._rate_lock:
            now = time.perf_counter()
            wait_sec = min_interval - (now - self._last_probe_time)
            if wait_sec > 0:
                time.sleep(wait_sec)
            self._last_probe_time = time.perf_counter()

    def inspect_single_host(
        self,
        ip_address: str,
        enable_snmp: bool | None = None,
        cancel_event: threading.Event | None = None,
    ) -> DiscoveredHostInfo:
        """
        Probe a single IP address using ICMP, TCP ports, ARP table, Reverse DNS, and SNMP.
        Safe against individual host errors or timeouts.
        """
        validated_ip = str(ipaddress.ip_address(str(ip_address).strip()))
        if cancel_event and cancel_event.is_set():
            return DiscoveredHostInfo(ip_address=validated_ip, is_alive=False)

        self._throttle()

        try:
            ping_ok, ping_latency = icmp_ping(validated_ip, timeout_ms=self._config.icmp_timeout_ms)
            if cancel_event and cancel_event.is_set():
                return DiscoveredHostInfo(ip_address=validated_ip, is_alive=False)

            port_summary = probe_multiple_ports(
                validated_ip,
                ports=DEFAULT_DISCOVERY_PORTS,
                timeout_sec=self._config.tcp_probe_timeout_sec,
            )

            # Do NOT treat ping failure as offline if any TCP port responded
            is_alive = ping_ok or len(port_summary.open_ports) > 0

            snmp_enabled = (
                enable_snmp if enable_snmp is not None else self._config.snmp_enabled_by_default
            )
            snmp_profile = SNMPDeviceProfile(reachable=False)
            if snmp_enabled and (is_alive or not ping_ok):
                # Only query SNMP if host showed life or if we want to check UDP 161 on alive hosts
                if is_alive:
                    snmp_profile = self._snmp_client.query_device_profile(validated_ip)

            if not is_alive and not snmp_profile.reachable:
                return DiscoveredHostInfo(
                    ip_address=validated_ip,
                    is_alive=False,
                    status=DeviceStatusEnum.OFFLINE,
                )

            mac_address = lookup_arp_mac(validated_ip)
            mac_vendor = lookup_vendor_by_mac(mac_address)
            dns_hostname = resolve_reverse_dns(validated_ip)
            effective_hostname = dns_hostname or snmp_profile.sys_name

            snmp_vendor, snmp_model = snmp_profile.infer_manufacturer_and_model()
            manufacturer = snmp_vendor or mac_vendor
            model = snmp_model

            device_type, status, reason = classify_discovered_host(
                port_summary=port_summary,
                snmp_profile=snmp_profile,
                mac_vendor=manufacturer,
                hostname=effective_hostname,
            )

            best_latency = port_summary.best_latency_ms or ping_latency
            metadata: dict[str, Any] = {
                "classification_reason": reason,
                "open_ports": port_summary.open_ports,
                "ping_responded": ping_ok,
                "latency_ms": best_latency,
                "snmp_reachable": snmp_profile.reachable,
            }
            if snmp_profile.reachable:
                metadata["snmp_sys_descr"] = snmp_profile.sys_descr
                metadata["snmp_printer_status"] = snmp_profile.printer_status_text
                metadata["snmp_alerts"] = snmp_profile.detected_alerts
                metadata["snmp_page_count"] = snmp_profile.page_count
                metadata["snmp_console_display"] = snmp_profile.console_display
                metadata["snmp_raw_oids"] = snmp_profile.raw_oids

            return DiscoveredHostInfo(
                ip_address=validated_ip,
                is_alive=True,
                status=status,
                device_type=device_type,
                hostname=effective_hostname,
                mac_address=mac_address,
                manufacturer=manufacturer,
                model=model,
                location=snmp_profile.sys_location,
                latency_ms=best_latency,
                open_ports=port_summary.open_ports,
                supported_protocols=port_summary.supported_protocols,
                snmp_profile=snmp_profile,
                classification_reason=reason,
                metadata=metadata,
            )
        except Exception as exc:
            logger.warning(
                "Lỗi khi kiểm tra thiết bị %s: %s",
                validated_ip,
                exc,
                extra={"device_ip": validated_ip, "error_code": "HOST_PROBE_ERROR"},
            )
            return DiscoveredHostInfo(
                ip_address=validated_ip,
                is_alive=False,
                status=DeviceStatusEnum.UNKNOWN,
                classification_reason=f"Lỗi thăm dò: {exc.__class__.__name__}",
            )

    def scan_cidr(
        self,
        target_cidr: str,
        enable_snmp: bool | None = None,
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[int, int, DiscoveredHostInfo | None], None] | None = None,
    ) -> list[DiscoveredHostInfo]:
        """
        Validate CIDR against ALLOWED_SCAN_SUBNETS and scan all hosts concurrently
        using a bounded ThreadPoolExecutor.
        Returns only hosts that responded (is_alive=True).
        """
        hosts = self._config.validate_scan_target(target_cidr)
        total = len(hosts)
        discovered_alive: list[DiscoveredHostInfo] = []
        completed_count = 0

        max_workers = min(self._config.max_concurrent_probes, max(1, total))
        logger.info(
            "Bắt đầu quét dải %s (%d địa chỉ, tối đa %d luồng)",
            target_cidr,
            total,
            max_workers,
            extra={"task_type": "LAN_SCAN"},
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(
                    self.inspect_single_host,
                    str(ip),
                    enable_snmp,
                    cancel_event,
                ): str(ip)
                for ip in hosts
            }

            for future in as_completed(future_to_ip):
                if cancel_event and cancel_event.is_set():
                    for pending in future_to_ip:
                        pending.cancel()
                    logger.info("Tác vụ quét mạng %s đã được hủy bởi người dùng.", target_cidr)
                    break

                completed_count += 1
                host_result: DiscoveredHostInfo | None = None
                try:
                    host_result = future.result()
                    if host_result.is_alive:
                        discovered_alive.append(host_result)
                except Exception as exc:
                    ip_str = future_to_ip[future]
                    logger.warning(
                        "Bỏ qua lỗi khi xử lý kết quả IP %s: %s",
                        ip_str,
                        exc,
                        extra={"device_ip": ip_str, "error_code": "SCAN_FUTURE_ERROR"},
                    )

                if progress_callback is not None:
                    progress_callback(completed_count, total, host_result)

        discovered_alive.sort(key=lambda item: ipaddress.ip_address(item.ip_address))
        return discovered_alive
