"""Domain and application exceptions with structured error codes."""

from __future__ import annotations


class DomainError(Exception):
    """Base exception for all LAN Printer Manager domain errors."""

    error_code: str = "DOMAIN_ERROR"

    def __init__(self, message: str, error_code: str | None = None) -> None:
        super().__init__(message)
        if error_code:
            self.error_code = error_code


class ConfigurationError(DomainError):
    """Raised when environment or application configuration is invalid."""

    error_code = "CONFIGURATION_ERROR"


class PermissionDeniedError(DomainError):
    """Raised when the current user lacks the required RBAC role for an operation."""

    error_code = "PERMISSION_DENIED"


class AuthenticationError(DomainError):
    """Raised when user authentication fails."""

    error_code = "AUTHENTICATION_FAILED"


class SubnetNotAllowedError(DomainError):
    """Raised when a scan target is outside administrator-approved LAN subnets or limits."""

    error_code = "SUBNET_NOT_ALLOWED"


class DatabaseUnavailableError(DomainError):
    """Raised when PostgreSQL cannot be reached or a transaction fails due to connectivity."""

    error_code = "DATABASE_UNAVAILABLE"


class DeviceNotFoundError(DomainError):
    """Raised when a requested device or printer does not exist."""

    error_code = "DEVICE_NOT_FOUND"


class TaskNotAllowedError(DomainError):
    """Raised when a requested remediation task is not in the allowlist or prerequisites fail."""

    error_code = "TASK_NOT_ALLOWED"


class RemoteExecutionError(DomainError):
    """Raised when a remote or local administrative task fails or times out."""

    error_code = "REMOTE_EXECUTION_ERROR"
