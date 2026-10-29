"""Safe TCP port probing, ICMP ping, ARP MAC lookup, and reverse DNS utilities."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field

from lan_manager.domain.models.entities import normalize_mac_address

# Standard enterprise ports to inspect during discovery & printer checks
PRINTER_PORTS: dict[int, str] = {
    9100: "RAW_9100",
    631: "IPP_631",
    515: "LPD_515",
}

WORKSTATION_PORTS: dict[int, str] = {
    445: "SMB_445",
    135: "RPC_135",
}

WEB_ADMIN_PORTS: dict[int, str] = {
    80: "HTTP_80",
    443: "HTTPS_443",
}

DEFAULT_DISCOVERY_PORTS: tuple[int, ...] = (9100, 631, 515, 445, 135, 80, 443)

# Common IEEE OUI prefixes for enterprise printer and hardware manufacturers
_KNOWN_OUI_VENDORS: dict[str, str] = {
    "00:1B:78": "HP Inc.",
    "3C:D9:2B": "HP Inc.",
    "B4:B5:2F": "HP Inc.",
    "64:51:06": "HP Inc.",
    "00:00:85": "Canon Inc.",
    "18:0C:AC": "Canon Inc.",
    "F8:0D:60": "Canon Inc.",
    "00:80:77": "Brother Industries",
    "30:05:5C": "Brother Industries",
    "00:1B:A9": "Brother Industries",
    "00:00:48": "Seiko Epson",
    "64:EB:8C": "Seiko Epson",
    "00:26:73": "Ricoh Company",
    "00:00:74": "Ricoh Company",
    "00:17:C8": "Kyocera Document Solutions",
    "00:C0:EE": "Kyocera Document Solutions",
    "00:00:AA": "Fuji Xerox",
    "00:07:4D": "Zebra Technologies",
    "00:14:22": "Dell Inc.",
    "F8:B1:56": "Dell Inc.",
}

_ARP_MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})")


@dataclass
class PortProbeSummary:
    """Aggregated TCP port probe results for a single IP."""

    ip_address: str
    open_ports: list[int] = field(default_factory=list)
    best_latency_ms: int | None = None
    supported_protocols: list[str] = field(default_factory=list)


def _validate_ip_str(ip_address: str) -> str:
    """Strictly validate an IP string before passing to socket or subprocess."""
    return str(ipaddress.ip_address(str(ip_address).strip()))


def check_tcp_port(ip_address: str, port: int, timeout_sec: float = 1.5) -> tuple[bool, int | None]:
    """
    Attempt a TCP handshake to (ip_address, port).
    Returns (is_open, latency_ms).
    """
    validated_ip = _validate_ip_str(ip_address)
    if not (1 <= int(port) <= 65535):
        raise ValueError(f"Cổng TCP không hợp lệ: {port}")

    start = time.perf_counter()
    try:
        with socket.create_connection((validated_ip, int(port)), timeout=timeout_sec):
            elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
            return True, elapsed_ms
    except (TimeoutError, OSError):
        return False, None


def probe_multiple_ports(
    ip_address: str,
    ports: tuple[int, ...] = DEFAULT_DISCOVERY_PORTS,
    timeout_sec: float = 1.2,
) -> PortProbeSummary:
    """Check a list of TCP ports sequentially on a single host and collect supported protocols."""
    validated_ip = _validate_ip_str(ip_address)
    open_ports: list[int] = []
    protocols: list[str] = []
    latencies: list[int] = []

    for port in ports:
        is_open, latency = check_tcp_port(validated_ip, port, timeout_sec=timeout_sec)
        if is_open:
            open_ports.append(port)
            if latency is not None:
                latencies.append(latency)
            if port in PRINTER_PORTS:
                protocols.append(PRINTER_PORTS[port])
            elif port in WORKSTATION_PORTS:
                protocols.append(WORKSTATION_PORTS[port])
            elif port in WEB_ADMIN_PORTS:
                protocols.append(WEB_ADMIN_PORTS[port])

    best_latency = min(latencies) if latencies else None
    return PortProbeSummary(
        ip_address=validated_ip,
        open_ports=open_ports,
        best_latency_ms=best_latency,
        supported_protocols=protocols,
    )


def icmp_ping(ip_address: str, timeout_ms: int = 1000) -> tuple[bool, int | None]:
    """
    Execute an OS ICMP echo request safely using subprocess with separated argument list (shell=False).
    Note: ICMP failure alone does NOT prove a host is offline because firewalls may block echo requests.
    """
    validated_ip = _validate_ip_str(ip_address)
    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(max(200, int(timeout_ms))), validated_ip]
    else:
        timeout_sec = max(1, int(timeout_ms // 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), validated_ip]

    start = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=max(2.0, (timeout_ms / 1000.0) + 1.5),
            check=False,
        )
        elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
        if completed.returncode == 0:
            # Extract exact RTT if present in ping output (e.g., "time=2ms" or "time<1ms")
            match = re.search(r"time[=<](\d+)\s*ms", completed.stdout, re.IGNORECASE)
            rtt = int(match.group(1)) if match else elapsed_ms
            return True, max(1, rtt)
        return False, None
    except (subprocess.TimeoutExpired, OSError):
        return False, None


def lookup_arp_mac(ip_address: str) -> str | None:
    """
    Read the local OS ARP cache for a validated IP address using subprocess with shell=False.
    Returns normalized 'AA:BB:CC:DD:EE:FF' or None.
    """
    validated_ip = _validate_ip_str(ip_address)
    is_windows = platform.system().lower().startswith("win")
    cmd = ["arp", "-a", validated_ip] if is_windows else ["arp", "-n", validated_ip]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=2.0,
            check=False,
        )
        if completed.returncode != 0 or not completed.stdout:
            return None

        for line in completed.stdout.splitlines():
            if validated_ip in line:
                match = _ARP_MAC_REGEX.search(line)
                if match:
                    return normalize_mac_address(match.group(1))
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None


def resolve_reverse_dns(ip_address: str) -> str | None:
    """Resolve hostname for an IP via reverse DNS lookup."""
    validated_ip = _validate_ip_str(ip_address)
    try:
        hostname, _, _ = socket.gethostbyaddr(validated_ip)
        return hostname.strip() if hostname else None
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return None


def lookup_vendor_by_mac(mac_address: str | None) -> str | None:
    """Return hardware manufacturer from normalized MAC OUI prefix if known."""
    norm = normalize_mac_address(mac_address)
    if not norm:
        return None
    prefix = norm[:8]
    return _KNOWN_OUI_VENDORS.get(prefix)
