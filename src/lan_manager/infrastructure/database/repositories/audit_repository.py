"""Append-only repository for administrative audit logs."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from lan_manager.core.security import sanitize_audit_metadata
from lan_manager.domain.enums.system_enums import AuditResult
from lan_manager.domain.models.entities import AuditLog, utc_now
from lan_manager.infrastructure.database.models import AuditLogORM


def _audit_orm_to_domain(orm_obj: AuditLogORM) -> AuditLog:
    return AuditLog(
        id=orm_obj.id,
        user_id=orm_obj.user_id,
        username=orm_obj.username,
        action=orm_obj.action,
        target_type=orm_obj.target_type,
        target_id=orm_obj.target_id,
        result=AuditResult(orm_obj.result),
        safe_metadata=dict(orm_obj.safe_metadata or {}),
        created_at=orm_obj.created_at,
    )


class AuditRepository:
    """
    Append-only repository for AuditLogORM.
    Intentionally exposes no update or delete methods to preserve audit integrity.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(
        self,
        action: str,
        target_type: str,
        target_id: str,
        result: AuditResult,
        username: str = "system",
        user_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        safe_meta = sanitize_audit_metadata(metadata)
        orm_obj = AuditLogORM(
            user_id=user_id,
            username=username or "system",
            action=action,
            target_type=target_type,
            target_id=str(target_id),
            result=result.value,
            safe_metadata=safe_meta,
            created_at=utc_now(),
        )
        self._session.add(orm_obj)
        self._session.flush()
        return _audit_orm_to_domain(orm_obj)

    def list_logs(
        self,
        search_query: str | None = None,
        action_filter: str | None = None,
        result_filter: AuditResult | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[AuditLog], int]:
        stmt = select(AuditLogORM)
        count_stmt = select(func.count(AuditLogORM.id))

        filters = []
        if action_filter and action_filter.strip():
            filters.append(AuditLogORM.action == action_filter.strip())
        if result_filter is not None:
            filters.append(AuditLogORM.result == result_filter.value)
        if search_query and search_query.strip():
            q = f"%{search_query.strip()}%"
            filters.append(
                or_(
                    AuditLogORM.username.ilike(q),
                    AuditLogORM.action.ilike(q),
                    AuditLogORM.target_type.ilike(q),
                    AuditLogORM.target_id.ilike(q),
                )
            )

        for cond in filters:
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)

        total = int(self._session.scalar(count_stmt) or 0)
        stmt = stmt.order_by(desc(AuditLogORM.created_at)).offset(offset).limit(limit)
        rows = self._session.scalars(stmt).all()
        return [_audit_orm_to_domain(r) for r in rows], total
