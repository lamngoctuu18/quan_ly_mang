"""Read-only SNMP client for MIB-II and RFC 3805 Printer-MIB telemetry."""

from __future__ import annotations

import ipaddress
import secrets
import socket
from dataclasses import dataclass, field
from typing import Any

from lan_manager.core.logging_config import get_logger

logger = get_logger(__name__)

# Standard MIB-II & Host-Resources-MIB & Printer-MIB (RFC 3805) OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_HR_DEVICE_TYPE = "1.3.6.1.2.1.25.3.2.1.2.1"
OID_HR_DEVICE_DESCR = "1.3.6.1.2.1.25.3.2.1.3.1"
OID_HR_PRINTER_STATUS = "1.3.6.1.2.1.25.3.5.1.1.1"
OID_HR_PRINTER_ERROR_STATE = "1.3.6.1.2.1.25.3.5.1.2.1"
OID_PRT_GENERAL_PRINTER_NAME = "1.3.6.1.2.1.43.5.1.1.16.1"
OID_PRT_GENERAL_SERIAL_NUMBER = "1.3.6.1.2.1.43.5.1.1.17.1"
OID_PRT_MARKER_LIFE_COUNT = "1.3.6.1.2.1.43.10.2.1.4.1.1"
OID_PRT_CONSOLE_DISPLAY_TEXT = "1.3.6.1.2.1.43.16.5.1.2.1.1"

HR_DEVICE_PRINTER_OID = "1.3.6.1.2.1.25.3.1.5"

PRINTER_STATUS_MAP: dict[int, str] = {
    1: "other",
    2: "unknown",
    3: "idle",
    4: "printing",
    5: "warmup",
}

# RFC 3805 / Host-Resources-MIB hrPrinterDetectedErrorState bit positions (MSB first in first 2 octets)
_ERROR_STATE_BITS: list[tuple[int, int, str]] = [
    (0, 0x80, "lowPaper (Sắp hết giấy)"),
    (0, 0x40, "noPaper (Hết giấy)"),
    (0, 0x20, "lowToner (Sắp hết mực)"),
    (0, 0x10, "noToner (Hết mực)"),
    (0, 0x08, "doorOpen (Nắp máy đang mở)"),
    (0, 0x04, "jammed (Kẹt giấy)"),
    (0, 0x02, "offline (Máy in đang Offline)"),
    (0, 0x01, "serviceRequested (Yêu cầu bảo trì)"),
]

_KNOWN_PRINTER_KEYWORDS = (
    "laserjet",
    "jetdirect",
    "officejet",
    "pagewide",
    "designjet",
    "canon",
    "imageclass",
    "imagerunner",
    "brother",
    "hl-",
    "mfc-",
    "dcp-",
    "epson",
    "ricoh",
    "aficio",
    "kyocera",
    "ecosys",
    "taskalfa",
    "xerox",
    "versalink",
    "workcentre",
    "konica",
    "bizhub",
    "zebra",
    "zpl",
    "lexmark",
    "printer",
)


@dataclass
class SNMPDeviceProfile:
    """Structured SNMP telemetry retrieved from a network device."""

    reachable: bool = False
    sys_descr: str | None = None
    sys_object_id: str | None = None
    sys_name: str | None = None
    sys_location: str | None = None
    hr_device_type: str | None = None
    hr_device_descr: str | None = None
    printer_name: str | None = None
    serial_number: str | None = None
    firmware_version: str | None = None
    printer_status_text: str | None = None
    page_count: int | None = None
    console_display: str | None = None
    detected_alerts: list[str] = field(default_factory=list)
    raw_oids: dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified_printer(self) -> bool:
        """Determine if SNMP responses positively prove the device is a printer."""
        if not self.reachable:
            return False
        if self.hr_device_type and HR_DEVICE_PRINTER_OID in self.hr_device_type:
            return True
        if self.printer_name or self.serial_number or self.page_count is not None:
            return True
        combined_text = " ".join(
            filter(None, [self.sys_descr, self.hr_device_descr, self.console_display])
        ).lower()
        return any(keyword in combined_text for keyword in _KNOWN_PRINTER_KEYWORDS)

    def infer_manufacturer_and_model(self) -> tuple[str | None, str | None]:
        """Extract manufacturer and model from SNMP descriptions if available."""
        source = self.hr_device_descr or self.printer_name or self.sys_descr
        if not source:
            return None, None
        lower = source.lower()
        manufacturer: str | None = None
        if any(k in lower for k in ("hp", "hewlett-packard", "laserjet", "jetdirect", "officejet")):
            manufacturer = "HP Inc."
        elif "canon" in lower:
            manufacturer = "Canon Inc."
        elif "brother" in lower:
            manufacturer = "Brother Industries"
        elif "epson" in lower:
            manufacturer = "Seiko Epson"
        elif "ricoh" in lower:
            manufacturer = "Ricoh Company"
        elif "kyocera" in lower:
            manufacturer = "Kyocera Document Solutions"
        elif "xerox" in lower:
            manufacturer = "Fuji Xerox"
        elif "konica" in lower or "bizhub" in lower:
            manufacturer = "Konica Minolta"
        elif "zebra" in lower:
            manufacturer = "Zebra Technologies"
        elif "lexmark" in lower:
            manufacturer = "Lexmark"

        model = (self.hr_device_descr or self.printer_name or source.split(";")[0]).strip()[:120]
        return manufacturer, model


def decode_printer_error_bits(raw_bytes: bytes | str | None) -> list[str]:
    """Decode RFC 3805 hrPrinterDetectedErrorState bitmask into human-readable alerts."""
    if not raw_bytes:
        return []
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("latin1", errors="ignore")
    alerts: list[str] = []
    for byte_idx, mask, description in _ERROR_STATE_BITS:
        if len(raw_bytes) > byte_idx and (raw_bytes[byte_idx] & mask):
            alerts.append(description)
    return alerts


# ==============================================================================
# Minimal ASN.1 BER SNMPv2c GET Encoder/Decoder (Standard Library UDP Socket)
# Ensures read-only SNMP GET works reliably with zero external runtime fragility
# ==============================================================================


def _encode_ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    octets: list[int] = []
    temp = length
    while temp > 0:
        octets.insert(0, temp & 0xFF)
        temp >>= 8
    return bytes([0x80 | len(octets), *octets])


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_ber_length(len(value)) + value


def _encode_integer(value: int) -> bytes:
    if value == 0:
        return _encode_tlv(0x02, b"\x00")
    octets: list[int] = []
    temp = value
    while temp > 0:
        octets.insert(0, temp & 0xFF)
        temp >>= 8
    if octets[0] & 0x80:
        octets.insert(0, 0x00)
    return _encode_tlv(0x02, bytes(octets))


def _encode_oid(oid_str: str) -> bytes:
    parts = [int(p) for p in oid_str.strip(".").split(".") if p]
    if len(parts) < 2:
        raise ValueError(f"OID không hợp lệ: {oid_str}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for sub_id in parts[2:]:
        if sub_id == 0:
            body.append(0)
        else:
            stack: list[int] = []
            val = sub_id
            while val > 0:
                stack.insert(0, val & 0x7F)
                val >>= 7
            for i in range(len(stack) - 1):
                body.append(stack[i] | 0x80)
            body.append(stack[-1])
    return _encode_tlv(0x06, bytes(body))


def _build_snmpv2c_get_packet(community: str, oids: list[str], request_id: int) -> bytes:
    varbinds = b""
    for oid in oids:
        varbind = _encode_oid(oid) + _encode_tlv(0x05, b"")  # NULL value
        varbinds += _encode_tlv(0x30, varbind)
    varbind_list = _encode_tlv(0x30, varbinds)

    pdu_body = (
        _encode_integer(request_id)
        + _encode_integer(0)  # error-status = 0
        + _encode_integer(0)  # error-index = 0
        + varbind_list
    )
    get_pdu = _encode_tlv(0xA0, pdu_body)  # GetRequest-PDU (0xA0)

    message_body = (
        _encode_integer(1)  # SNMPv2c version = 1
        + _encode_tlv(0x04, community.encode("utf-8"))
        + get_pdu
    )
    return _encode_tlv(0x30, message_body)


def _decode_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_octets = first & 0x7F
    length = 0
    for _ in range(num_octets):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    oids = [first // 40, first % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            oids.append(val)
            val = 0
    return ".".join(str(x) for x in oids)


def _parse_snmpv2c_response(data: bytes) -> dict[str, Any]:
    """Parse an ASN.1 BER SNMPv2c GetResponse packet into {oid: value}."""
    results: dict[str, Any] = {}
    if not data or data[0] != 0x30:
        return results
    _, idx = _decode_ber_length(data, 1)

    # Skip version (0x02)
    if data[idx] != 0x02:
        return results
    v_len, idx = _decode_ber_length(data, idx + 1)
    idx += v_len

    # Skip community (0x04)
    if data[idx] != 0x04:
        return results
    c_len, idx = _decode_ber_length(data, idx + 1)
    idx += c_len

    # Expect GetResponse-PDU (0xA2)
    if data[idx] != 0xA2:
        return results
    _, idx = _decode_ber_length(data, idx + 1)

    # Skip request-id, error-status, error-index
    for field_idx in range(3):
        if data[idx] != 0x02:
            return results
        i_len, idx = _decode_ber_length(data, idx + 1)
        val_bytes = data[idx : idx + i_len]
        if field_idx == 1 and int.from_bytes(val_bytes, "big", signed=True) != 0:
            # Non-zero error-status
            return results
        idx += i_len

    # VarBindList (0x30)
    if data[idx] != 0x30:
        return results
    vbl_len, idx = _decode_ber_length(data, idx + 1)
    end_vbl = idx + vbl_len

    while idx < end_vbl:
        if data[idx] != 0x30:
            break
        vb_len, idx = _decode_ber_length(data, idx + 1)
        vb_end = idx + vb_len

        if data[idx] != 0x06:
            idx = vb_end
            continue
        oid_len, idx = _decode_ber_length(data, idx + 1)
        oid_str = _decode_oid(data[idx : idx + oid_len])
        idx += oid_len

        val_tag = data[idx]
        val_len, idx = _decode_ber_length(data, idx + 1)
        val_raw = data[idx : idx + val_len]
        idx = vb_end

        # Ignore noSuchObject (0x80), noSuchInstance (0x81), endOfMibView (0x82), NULL (0x05)
        if val_tag in (0x05, 0x80, 0x81, 0x82):
            continue
        if val_tag == 0x04:  # OCTET STRING
            results[oid_str] = val_raw
        elif val_tag in (0x02, 0x41, 0x42, 0x43):  # INTEGER / Counter32 / Gauge32 / TimeTicks
            results[oid_str] = int.from_bytes(val_raw, "big", signed=(val_tag == 0x02))
        elif val_tag == 0x06:  # OBJECT IDENTIFIER
            results[oid_str] = _decode_oid(val_raw)
    return results


class SNMPClient:
    """
    Read-only SNMP client for querying device identity and printer status.
    Never sends SNMP SET or configuration modification commands.
    """

    def __init__(
        self,
        community: str = "public",
        port: int = 161,
        timeout_sec: float = 1.5,
        retries: int = 1,
    ) -> None:
        self._community = community
        self._port = port
        self._timeout_sec = timeout_sec
        self._retries = max(0, retries)

    def get_oids(self, ip_address: str, oids: list[str]) -> dict[str, Any]:
        """Query a batch of OIDs over UDP 161 using SNMPv2c GET."""
        validated_ip = str(ipaddress.ip_address(str(ip_address).strip()))
        req_id = secrets.randbelow(900000) + 10000
        packet = _build_snmpv2c_get_packet(self._community, oids, req_id)

        attempts = 1 + self._retries
        for _ in range(attempts):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self._timeout_sec)
                    sock.sendto(packet, (validated_ip, self._port))
                    resp_data, _ = sock.recvfrom(8192)
                    parsed = _parse_snmpv2c_response(resp_data)
                    if parsed:
                        return parsed
            except (TimeoutError, OSError):
                continue
        return {}

    @staticmethod
    def _decode_text(val: Any) -> str | None:
        if val is None:
            return None
        if isinstance(val, bytes):
            cleaned = val.replace(b"\x00", b"").strip()
            if not cleaned:
                return None
            return cleaned.decode("utf-8", errors="replace")
        text = str(val).strip()
        return text if text else None

    def query_device_profile(self, ip_address: str) -> SNMPDeviceProfile:
        """
        Query MIB-II and Printer-MIB OIDs on a target IP and return a structured SNMPDeviceProfile.
        """
        identity_oids = [
            OID_SYS_DESCR,
            OID_SYS_OBJECT_ID,
            OID_SYS_NAME,
            OID_SYS_LOCATION,
            OID_HR_DEVICE_TYPE,
            OID_HR_DEVICE_DESCR,
        ]
        raw_identity = self.get_oids(ip_address, identity_oids)
        if not raw_identity:
            return SNMPDeviceProfile(reachable=False)

        printer_oids = [
            OID_HR_PRINTER_STATUS,
            OID_HR_PRINTER_ERROR_STATE,
            OID_PRT_GENERAL_PRINTER_NAME,
            OID_PRT_GENERAL_SERIAL_NUMBER,
            OID_PRT_MARKER_LIFE_COUNT,
            OID_PRT_CONSOLE_DISPLAY_TEXT,
        ]
        raw_printer = self.get_oids(ip_address, printer_oids)
        combined = {**raw_identity, **raw_printer}

        status_code = combined.get(OID_HR_PRINTER_STATUS)
        printer_status_text = (
            PRINTER_STATUS_MAP.get(int(status_code), "unknown")
            if isinstance(status_code, int)
            else None
        )

        error_bytes = combined.get(OID_HR_PRINTER_ERROR_STATE)
        alerts = decode_printer_error_bits(error_bytes if isinstance(error_bytes, bytes) else None)

        page_count_val = combined.get(OID_PRT_MARKER_LIFE_COUNT)
        page_count = (
            int(page_count_val) if isinstance(page_count_val, int) and page_count_val >= 0 else None
        )

        serializable_raw: dict[str, Any] = {}
        for k, v in combined.items():
            if isinstance(v, bytes):
                serializable_raw[k] = (
                    v.decode("utf-8", errors="replace").replace("\x00", "").strip()
                )
            else:
                serializable_raw[k] = v

        return SNMPDeviceProfile(
            reachable=True,
            sys_descr=self._decode_text(combined.get(OID_SYS_DESCR)),
            sys_object_id=self._decode_text(combined.get(OID_SYS_OBJECT_ID)),
            sys_name=self._decode_text(combined.get(OID_SYS_NAME)),
            sys_location=self._decode_text(combined.get(OID_SYS_LOCATION)),
            hr_device_type=self._decode_text(combined.get(OID_HR_DEVICE_TYPE)),
            hr_device_descr=self._decode_text(combined.get(OID_HR_DEVICE_DESCR)),
            printer_name=self._decode_text(combined.get(OID_PRT_GENERAL_PRINTER_NAME)),
            serial_number=self._decode_text(combined.get(OID_PRT_GENERAL_SERIAL_NUMBER)),
            printer_status_text=printer_status_text,
            page_count=page_count,
            console_display=self._decode_text(combined.get(OID_PRT_CONSOLE_DISPLAY_TEXT)),
            detected_alerts=alerts,
            raw_oids=serializable_raw,
        )
