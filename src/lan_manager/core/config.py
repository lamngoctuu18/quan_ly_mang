"""Centralized configuration management backed by environment variables and Pydantic validation."""

from __future__ import annotations

import importlib.util
import ipaddress
import os
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

from lan_manager.domain.exceptions import ConfigurationError, SubnetNotAllowedError

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"


def _parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class AppConfig(BaseModel):
    """Validated application configuration loaded from environment variables."""

    # General application settings
    app_env: str = Field(default="development")
    app_name: str = Field(default="LAN Printer Manager")
    log_level: str = Field(default="INFO")
    log_max_bytes: int = Field(default=5 * 1024 * 1024, ge=1024 * 100)
    log_backup_count: int = Field(default=5, ge=1, le=50)

    # PostgreSQL database configuration
    db_host: str = Field(default="127.0.0.1")
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = Field(default="lan_printer_manager")
    db_user: str = Field(default="lan_manager_app")
    db_password: str = Field(default="")
    db_connect_timeout: int = Field(default=3, ge=1, le=60)
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=10, ge=0, le=100)
    database_url_override: str | None = Field(default=None)

    # Controlled LAN Discovery configuration
    allowed_scan_subnets: list[str] = Field(
        default_factory=lambda: [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ]
    )
    max_scan_hosts: int = Field(default=1024, ge=1, le=4096)
    max_concurrent_probes: int = Field(default=32, ge=1, le=128)
    scan_rate_limit_per_sec: int = Field(default=64, ge=1, le=500)
    tcp_probe_timeout_sec: float = Field(default=1.5, ge=0.2, le=10.0)
    icmp_timeout_ms: int = Field(default=1000, ge=200, le=10000)

    # SNMP Read-only configuration
    snmp_enabled_by_default: bool = Field(default=True)
    snmp_community: str = Field(default="public")
    snmp_port: int = Field(default=161, ge=1, le=65535)
    snmp_timeout_sec: float = Field(default=1.5, ge=0.2, le=10.0)
    snmp_retries: int = Field(default=1, ge=0, le=5)

    # Remote execution configuration
    remote_agent_port: int = Field(default=8443, ge=1, le=65535)
    remote_agent_timeout_sec: float = Field(default=10.0, ge=1.0, le=120.0)
    remote_agent_shared_secret: str = Field(default="")
    remote_agent_verify_tls: bool = Field(default=True)

    @field_validator("allowed_scan_subnets")
    @classmethod
    def validate_subnets(cls, subnets: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in subnets:
            item = raw.strip()
            if not item:
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ConfigurationError(f"Dải mạng cấu hình không hợp lệ '{item}': {exc}") from exc
            if not (net.is_private or net.is_loopback):
                raise ConfigurationError(
                    f"Chỉ cho phép cấu hình dải mạng nội bộ (RFC1918), từ chối dải public: {net}"
                )
            normalized.append(str(net))
        if not normalized:
            raise ConfigurationError(
                "Phải có ít nhất một dải mạng được phép quét (ALLOWED_SCAN_SUBNETS)."
            )
        return normalized

    @classmethod
    def from_env(cls, env_file: Path | str | None = None) -> AppConfig:
        """Load configuration from .env file and OS environment variables."""
        target_env = Path(env_file) if env_file else PROJECT_ROOT / ".env"
        if target_env.exists():
            load_dotenv(dotenv_path=target_env, override=False)

        raw_subnets = os.getenv(
            "ALLOWED_SCAN_SUBNETS", "192.168.1.0/24,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
        )
        subnets_list = [s.strip() for s in raw_subnets.split(",") if s.strip()]

        return cls(
            app_env=os.getenv("APP_ENV", "development"),
            app_name=os.getenv("APP_NAME", "LAN Printer Manager"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_max_bytes=int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024))),
            log_backup_count=int(os.getenv("LOG_BACKUP_COUNT", "5")),
            db_host=os.getenv("DB_HOST", "127.0.0.1"),
            db_port=int(os.getenv("DB_PORT", "5432")),
            db_name=os.getenv("DB_NAME", "lan_printer_manager"),
            db_user=os.getenv("DB_USER", "lan_manager_app"),
            db_password=os.getenv("DB_PASSWORD", ""),
            db_connect_timeout=int(os.getenv("DB_CONNECT_TIMEOUT", "5")),
            db_pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
            db_max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            database_url_override=os.getenv("DATABASE_URL"),
            allowed_scan_subnets=subnets_list,
            max_scan_hosts=int(os.getenv("MAX_SCAN_HOSTS", "1024")),
            max_concurrent_probes=int(os.getenv("MAX_CONCURRENT_PROBES", "32")),
            scan_rate_limit_per_sec=int(os.getenv("SCAN_RATE_LIMIT_PER_SEC", "64")),
            tcp_probe_timeout_sec=float(os.getenv("TCP_PROBE_TIMEOUT_SEC", "1.5")),
            icmp_timeout_ms=int(os.getenv("ICMP_TIMEOUT_MS", "1000")),
            snmp_enabled_by_default=_parse_bool(os.getenv("SNMP_ENABLED_BY_DEFAULT"), True),
            snmp_community=os.getenv("SNMP_COMMUNITY", "public"),
            snmp_port=int(os.getenv("SNMP_PORT", "161")),
            snmp_timeout_sec=float(os.getenv("SNMP_TIMEOUT_SEC", "1.5")),
            snmp_retries=int(os.getenv("SNMP_RETRIES", "1")),
            remote_agent_port=int(os.getenv("REMOTE_AGENT_PORT", "8443")),
            remote_agent_timeout_sec=float(os.getenv("REMOTE_AGENT_TIMEOUT_SEC", "10.0")),
            remote_agent_shared_secret=os.getenv("REMOTE_AGENT_SHARED_SECRET", ""),
            remote_agent_verify_tls=_parse_bool(os.getenv("REMOTE_AGENT_VERIFY_TLS"), True),
        )

    @staticmethod
    def _preferred_pg_driver() -> str:
        """Select psycopg (v3) by default, falling back to psycopg2 only if psycopg v3 is missing."""
        if importlib.util.find_spec("psycopg") is not None:
            return "postgresql+psycopg"
        if importlib.util.find_spec("psycopg2") is not None:
            return "postgresql+psycopg2"
        return "postgresql+psycopg"

    def get_database_url(self, hide_password: bool = False) -> str:
        """Build SQLAlchemy PostgreSQL connection URI safely."""
        if self.database_url_override:
            if hide_password and "@" in self.database_url_override:
                prefix, suffix = self.database_url_override.split("@", 1)
                if ":" in prefix.split("//", 1)[-1]:
                    scheme_user = prefix.rsplit(":", 1)[0]
                    return f"{scheme_user}:***@{suffix}"
            return self.database_url_override

        driver = self._preferred_pg_driver()
        encoded_user = quote_plus(self.db_user)
        encoded_password = "***" if hide_password else quote_plus(self.db_password)
        return f"{driver}://{encoded_user}:{encoded_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    def validate_scan_target(self, target_cidr: str) -> list[ipaddress.IPv4Address]:
        """
        Validate that a requested IP or CIDR subnet is syntactically valid, private/LAN only,
        within the administrator-approved ALLOWED_SCAN_SUBNETS, and within MAX_SCAN_HOSTS.
        """
        cleaned = target_cidr.strip()
        if not cleaned:
            raise SubnetNotAllowedError("Dải IP quét không được để trống.")

        try:
            network = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise SubnetNotAllowedError(
                f"Định dạng IP/CIDR không hợp lệ '{cleaned}': {exc}"
            ) from exc

        if not isinstance(network, ipaddress.IPv4Network):
            raise SubnetNotAllowedError("Hiện chỉ hỗ trợ quét dải mạng IPv4 nội bộ.")

        if network.is_multicast or network.is_reserved or network.is_unspecified:
            raise SubnetNotAllowedError(f"Không được phép quét dải địa chỉ đặc biệt: {network}")

        if not network.is_private and not network.is_loopback:
            raise SubnetNotAllowedError(
                f"Từ chối quét dải IP ngoài mạng LAN (Internet/Public IP): {network}"
            )

        allowed_networks = [
            ipaddress.ip_network(subnet, strict=False) for subnet in self.allowed_scan_subnets
        ]
        is_permitted = any(
            isinstance(allowed, ipaddress.IPv4Network) and network.subnet_of(allowed)
            for allowed in allowed_networks
        )
        if not is_permitted:
            allowed_str = ", ".join(self.allowed_scan_subnets)
            raise SubnetNotAllowedError(
                f"Dải mạng {network} không nằm trong danh sách cho phép ({allowed_str})."
            )

        hosts = (
            [ip for ip in network.hosts()]
            if network.num_addresses > 1
            else [network.network_address]
        )
        if len(hosts) > self.max_scan_hosts:
            raise SubnetNotAllowedError(
                f"Số lượng địa chỉ cần quét ({len(hosts)}) vượt quá giới hạn an toàn "
                f"({self.max_scan_hosts} hosts/lần). Vui lòng thu hẹp prefix CIDR (ví dụ /24)."
            )
        return hosts


_config_instance: AppConfig | None = None


def get_config(reload: bool = False) -> AppConfig:
    """Return singleton AppConfig instance."""
    global _config_instance
    if _config_instance is None or reload:
        _config_instance = AppConfig.from_env()
    return _config_instance
