"""Core domain enumerations for devices, printers, diagnostics, tasks, and RBAC."""

from __future__ import annotations

from enum import StrEnum


class DeviceType(StrEnum):
    """Classification of discovered LAN devices."""

    PRINTER = "PRINTER"
    WORKSTATION = "WORKSTATION"
    PRINT_SERVER = "PRINT_SERVER"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    UNKNOWN = "UNKNOWN"

    @property
    def label_vi(self) -> str:
        labels = {
            DeviceType.PRINTER: "Máy in IP",
            DeviceType.WORKSTATION: "Máy tính (Workstation)",
            DeviceType.PRINT_SERVER: "Máy chủ in (Print Server)",
            DeviceType.NETWORK_DEVICE: "Thiết bị mạng",
            DeviceType.UNKNOWN: "Chưa xác định",
        }
        return labels.get(self, self.value)


class DeviceStatusEnum(StrEnum):
    """Operational and connectivity state of a device."""

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"
    UNCHECKED = "UNCHECKED"

    @property
    def label_vi(self) -> str:
        labels = {
            DeviceStatusEnum.ONLINE: "Đang kết nối (Online)",
            DeviceStatusEnum.OFFLINE: "Mất kết nối (Offline)",
            DeviceStatusEnum.WARNING: "Cảnh báo (Warning)",
            DeviceStatusEnum.ERROR: "Lỗi thiết bị (Error)",
            DeviceStatusEnum.UNKNOWN: "Không xác định",
            DeviceStatusEnum.UNCHECKED: "Chưa kiểm tra",
        }
        return labels.get(self, self.value)


class DiagnosticCheckType(StrEnum):
    """Types of diagnostic inspections."""

    FULL_DIAGNOSTIC = "FULL_DIAGNOSTIC"
    CONNECTIVITY = "CONNECTIVITY"
    PORT = "PORT"
    SNMP = "SNMP"
    SPOOLER = "SPOOLER"
    QUEUE = "QUEUE"


class DiagnosticSeverity(StrEnum):
    """Result classification for a diagnostic run."""

    NORMAL = "NORMAL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    @property
    def label_vi(self) -> str:
        labels = {
            DiagnosticSeverity.NORMAL: "Bình thường",
            DiagnosticSeverity.WARNING: "Cảnh báo",
            DiagnosticSeverity.ERROR: "Lỗi",
            DiagnosticSeverity.UNKNOWN: "Chưa xác định",
        }
        return labels.get(self, self.value)


class TaskType(StrEnum):
    """Allowlisted administrative remediation task types."""

    RECHECK_CONNECTIVITY = "RECHECK_CONNECTIVITY"
    REFRESH_SNMP_STATUS = "REFRESH_SNMP_STATUS"
    OPEN_WEB_ADMIN = "OPEN_WEB_ADMIN"
    RESTART_PRINT_SPOOLER = "RESTART_PRINT_SPOOLER"
    CLEAR_STUCK_PRINT_JOBS = "CLEAR_STUCK_PRINT_JOBS"


class TaskStatus(StrEnum):
    """Execution lifecycle state of a remediation task."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"

    @property
    def label_vi(self) -> str:
        labels = {
            TaskStatus.PENDING: "Đang chờ",
            TaskStatus.RUNNING: "Đang thực thi",
            TaskStatus.SUCCEEDED: "Thành công (Đã xác minh)",
            TaskStatus.FAILED: "Thất bại",
            TaskStatus.CANCELLED: "Đã hủy",
            TaskStatus.VERIFICATION_FAILED: "Hậu kiểm chưa đạt",
        }
        return labels.get(self, self.value)


class RiskLevel(StrEnum):
    """Risk classification for remediation tasks."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def label_vi(self) -> str:
        labels = {
            RiskLevel.LOW: "Thấp",
            RiskLevel.MEDIUM: "Trung bình",
            RiskLevel.HIGH: "Cao",
        }
        return labels.get(self, self.value)


class RoleType(StrEnum):
    """Role-Based Access Control (RBAC) levels."""

    VIEWER = "VIEWER"
    TECHNICIAN = "TECHNICIAN"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"

    @property
    def label_vi(self) -> str:
        labels = {
            RoleType.VIEWER: "Người xem (Viewer)",
            RoleType.TECHNICIAN: "Kỹ thuật viên chẩn đoán (Technician)",
            RoleType.OPERATOR: "Kỹ thuật viên vận hành & sửa lỗi (Operator)",
            RoleType.ADMIN: "Quản trị viên hệ thống (Admin)",
        }
        return labels.get(self, self.value)


class AuditResult(StrEnum):
    """Outcome recorded in audit logs."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
