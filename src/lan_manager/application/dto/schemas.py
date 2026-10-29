"""Structured DTOs returned by application services to the presentation layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lan_manager.domain.enums.system_enums import (
    DiagnosticSeverity,
    RiskLevel,
    RoleType,
    TaskType,
)
from lan_manager.domain.models.entities import (
    Device,
    DeviceStatusRecord,
    DiagnosticResult,
    RemoteTask,
)


@dataclass
class ScanSummaryDTO:
    """Summary of a completed or cancelled LAN scan operation."""

    target_cidr: str
    total_hosts_probed: int
    alive_count: int
    new_devices_count: int
    updated_devices_count: int
    printers_found: int
    cancelled: bool
    duration_sec: float
    devices: list[Device] = field(default_factory=list)


@dataclass
class DashboardSummaryDTO:
    """Real-time operational metrics and recent activity for the Dashboard."""

    db_connected: bool
    db_status_message: str
    total_devices: int = 0
    total_printers: int = 0
    online_devices: int = 0
    offline_devices: int = 0
    open_issues_count: int = 0
    recent_issues: list[tuple[DiagnosticResult, Device | None]] = field(default_factory=list)
    printers_needing_check: list[Device] = field(default_factory=list)
    recent_tasks: list[tuple[RemoteTask, Device | None]] = field(default_factory=list)


@dataclass
class PrinterFullDetailDTO:
    """Aggregated data for the 6-tab Printer Details view."""

    device: Device
    status_history: list[DeviceStatusRecord] = field(default_factory=list)
    diagnostics: list[DiagnosticResult] = field(default_factory=list)
    tasks: list[RemoteTask] = field(default_factory=list)


@dataclass
class DiagnosticStepDTO:
    """Individual step outcome in a multi-step printer/device diagnostic run."""

    step_number: int
    step_code: str
    title: str
    severity: DiagnosticSeverity
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class FullDiagnosticReportDTO:
    """Structured report returned by DiagnosticService."""

    device: Device
    saved_result: DiagnosticResult
    overall_severity: DiagnosticSeverity
    probable_cause: str
    steps: list[DiagnosticStepDTO] = field(default_factory=list)
    recommended_tasks: list[TaskType] = field(default_factory=list)


@dataclass(frozen=True)
class TaskDefinitionDTO:
    """Metadata descriptor for an allowlisted remediation task in TaskRegistry."""

    task_type: TaskType
    title: str
    description: str
    prerequisite_desc: str
    required_role: RoleType
    risk_level: RiskLevel
    requires_confirmation: bool
    timeout_sec: int
    post_verify_desc: str
