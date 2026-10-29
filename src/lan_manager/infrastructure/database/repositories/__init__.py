"""Repository pattern implementations for PostgreSQL persistence."""

from lan_manager.infrastructure.database.repositories.audit_repository import AuditRepository
from lan_manager.infrastructure.database.repositories.device_repository import DeviceRepository
from lan_manager.infrastructure.database.repositories.diagnostic_repository import (
    DiagnosticRepository,
)
from lan_manager.infrastructure.database.repositories.printer_repository import PrinterRepository
from lan_manager.infrastructure.database.repositories.task_repository import TaskRepository
from lan_manager.infrastructure.database.repositories.user_repository import UserRepository

__all__ = [
    "AuditRepository",
    "DeviceRepository",
    "DiagnosticRepository",
    "PrinterRepository",
    "TaskRepository",
    "UserRepository",
]
