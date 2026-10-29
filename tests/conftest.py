"""Shared test fixtures and isolated test database factory."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lan_manager.core.config import AppConfig
from lan_manager.infrastructure.database.base import Base
from lan_manager.infrastructure.database.connection import DatabaseManager


def create_isolated_test_db_manager() -> tuple[AppConfig, DatabaseManager]:
    """
    Create an isolated in-memory database manager for unit testing repository,
    deduplication, and service logic without requiring a live production PostgreSQL server
    or a physical printer.
    """
    config = AppConfig(
        app_env="testing",
        allowed_scan_subnets=["192.168.1.0/24", "10.0.0.0/24", "127.0.0.1/32"],
        max_scan_hosts=256,
        max_concurrent_probes=8,
        scan_rate_limit_per_sec=500,
        remote_agent_shared_secret="test_shared_secret_32_bytes_minimum_key",
    )
    db_manager = DatabaseManager(config=config, db_url_override="sqlite+pysqlite:///:memory:")
    engine = db_manager.get_engine()
    Base.metadata.create_all(bind=engine)
    return config, db_manager
