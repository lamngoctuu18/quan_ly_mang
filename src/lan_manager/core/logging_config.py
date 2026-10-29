"""Unified application logging with log rotation and secret scrubbing."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from lan_manager.core.config import LOGS_DIR, AppConfig

_SENSITIVE_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|token|authorization|snmp_community)\s*[:=]\s*(['\"]?)([^'\",\s]+)\2"
)


class ContextualSecretScrubFilter(logging.Filter):
    """Filter that injects structured defaults and scrubs credentials from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "device_ip"):
            record.device_ip = "-"
        if not hasattr(record, "task_type"):
            record.task_type = "-"
        if not hasattr(record, "error_code"):
            record.error_code = "-"

        msg = record.getMessage()
        if _SENSITIVE_PATTERNS.search(msg):
            record.msg = _SENSITIVE_PATTERNS.sub(r"\1=***REDACTED***", msg)
            record.args = ()
        return True


def setup_logging(config: AppConfig, log_dir: Path | None = None) -> logging.Logger:
    """Configure rotating file and console logging for the application."""
    target_dir = log_dir or LOGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    log_file = target_dir / "lan_printer_manager.log"

    root_logger = logging.getLogger("lan_manager")
    level = getattr(logging, config.log_level.upper(), logging.INFO)
    root_logger.setLevel(level)

    if root_logger.handlers:
        return root_logger

    log_format = (
        "%(asctime)s | %(levelname)-8s | %(name)s | "
        "device=%(device_ip)s | task=%(task_type)s | err=%(error_code)s | %(message)s"
    )
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    scrub_filter = ContextualSecretScrubFilter()

    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(scrub_filter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(scrub_filter)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger.propagate = False
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the 'lan_manager' hierarchy."""
    if name.startswith("lan_manager"):
        return logging.getLogger(name)
    return logging.getLogger(f"lan_manager.{name}")
