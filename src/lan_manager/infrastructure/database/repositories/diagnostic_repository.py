"""Repository for storing and querying device diagnostic results."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from lan_manager.domain.enums.system_enums import DiagnosticCheckType, DiagnosticSeverity
from lan_manager.domain.models.entities import DiagnosticResult, utc_now
from lan_manager.infrastructure.database.models import DiagnosticResultORM


def _diag_orm_to_domain(orm_obj: DiagnosticResultORM) -> DiagnosticResult:
    return DiagnosticResult(
        id=orm_obj.id,
        device_id=orm_obj.device_id,
        check_type=DiagnosticCheckType(orm_obj.check_type),
        severity=DiagnosticSeverity(orm_obj.severity),
        probable_cause=orm_obj.probable_cause,
        diagnostic_data=dict(orm_obj.diagnostic_data or {}),
        performed_by=orm_obj.performed_by,
        checked_at=orm_obj.checked_at,
    )


class DiagnosticRepository:
    """Manages diagnostic result persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        device_id: UUID,
        check_type: DiagnosticCheckType,
        severity: DiagnosticSeverity,
        probable_cause: str,
        diagnostic_data: dict[str, Any],
        performed_by: UUID | None = None,
    ) -> DiagnosticResult:
        orm_obj = DiagnosticResultORM(
            device_id=device_id,
            check_type=check_type.value,
            severity=severity.value,
            probable_cause=probable_cause,
            diagnostic_data=diagnostic_data,
            performed_by=performed_by,
            checked_at=utc_now(),
        )
        self._session.add(orm_obj)
        self._session.flush()
        return _diag_orm_to_domain(orm_obj)

    def list_by_device(self, device_id: UUID, limit: int = 30) -> list[DiagnosticResult]:
        stmt = (
            select(DiagnosticResultORM)
            .where(DiagnosticResultORM.device_id == device_id)
            .order_by(desc(DiagnosticResultORM.checked_at))
            .limit(limit)
        )
        rows = self._session.scalars(stmt).all()
        return [_diag_orm_to_domain(r) for r in rows]

    def list_recent_issues(self, limit: int = 20) -> list[DiagnosticResult]:
        """List recent diagnostic findings with WARNING or ERROR severity."""
        stmt = (
            select(DiagnosticResultORM)
            .where(
                DiagnosticResultORM.severity.in_(
                    [DiagnosticSeverity.ERROR.value, DiagnosticSeverity.WARNING.value]
                )
            )
            .order_by(desc(DiagnosticResultORM.checked_at))
            .limit(limit)
        )
        rows = self._session.scalars(stmt).all()
        return [_diag_orm_to_domain(r) for r in rows]

    def count_open_issues(self) -> int:
        """Count distinct devices whose most recent diagnostic severity is WARNING or ERROR."""
        stmt = select(func.count(func.distinct(DiagnosticResultORM.device_id))).where(
            DiagnosticResultORM.severity.in_(
                [DiagnosticSeverity.ERROR.value, DiagnosticSeverity.WARNING.value]
            )
        )
        return int(self._session.scalar(stmt) or 0)
