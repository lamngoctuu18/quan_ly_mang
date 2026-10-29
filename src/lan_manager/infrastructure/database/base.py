"""SQLAlchemy 2.0 Declarative Base and PostgreSQL native type adapters."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String, TypeDecorator
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class IPAddressType(TypeDecorator[str]):
    """
    SQLAlchemy type that maps to PostgreSQL native INET type while validating
    and normalizing IPv4/IPv6 addresses as strings in Python.
    """

    impl = String(45)
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(INET())
        return dialect.type_descriptor(String(45))

    def process_bind_param(
        self, value: str | ipaddress.IPv4Address | None, dialect: Dialect
    ) -> str | None:
        if value is None:
            return None
        validated = ipaddress.ip_address(str(value).strip())
        return str(validated)

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(str(value).strip()))


JSONVariant = JSON().with_variant(JSONB(), "postgresql")
TZDateTime = DateTime(timezone=True)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy 2.0 ORM models."""
