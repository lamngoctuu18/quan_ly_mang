"""Repository for managing remote and local administrative remediation tasks."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from lan_manager.domain.enums.system_enums import RiskLevel, TaskStatus, TaskType
from lan_manager.domain.models.entities import RemoteTask, utc_now
from lan_manager.infrastructure.database.models import RemoteTaskORM


def _task_orm_to_domain(orm_obj: RemoteTaskORM) -> RemoteTask:
    return RemoteTask(
        id=orm_obj.id,
        target_device_id=orm_obj.target_device_id,
        task_type=TaskType(orm_obj.task_type),
        requested_by=orm_obj.requested_by,
        requested_by_username=orm_obj.requested_by_username,
        status=TaskStatus(orm_obj.status),
        risk_level=RiskLevel(orm_obj.risk_level),
        parameters=dict(orm_obj.parameters or {}),
        requested_at=orm_obj.requested_at,
        started_at=orm_obj.started_at,
        finished_at=orm_obj.finished_at,
        result_summary=orm_obj.result_summary,
        error_message=orm_obj.error_message,
    )


class TaskRepository:
    """Persistence lifecycle for RemoteTask records."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_task(
        self,
        target_device_id: UUID,
        task_type: TaskType,
        risk_level: RiskLevel,
        requested_by: UUID | None,
        requested_by_username: str,
        parameters: dict[str, Any] | None = None,
    ) -> RemoteTask:
        now = utc_now()
        orm_obj = RemoteTaskORM(
            target_device_id=target_device_id,
            task_type=task_type.value,
            requested_by=requested_by,
            requested_by_username=requested_by_username or "system",
            status=TaskStatus.RUNNING.value,
            risk_level=risk_level.value,
            parameters=dict(parameters or {}),
            requested_at=now,
            started_at=now,
        )
        self._session.add(orm_obj)
        self._session.flush()
        return _task_orm_to_domain(orm_obj)

    def complete_task(
        self,
        task_id: UUID,
        status: TaskStatus,
        result_summary: str | None = None,
        error_message: str | None = None,
    ) -> RemoteTask | None:
        orm_obj = self._session.scalar(select(RemoteTaskORM).where(RemoteTaskORM.id == task_id))
        if orm_obj is None:
            return None
        orm_obj.status = status.value
        orm_obj.finished_at = utc_now()
        orm_obj.result_summary = result_summary
        orm_obj.error_message = error_message
        self._session.flush()
        return _task_orm_to_domain(orm_obj)

    def list_by_device(self, device_id: UUID, limit: int = 30) -> list[RemoteTask]:
        stmt = (
            select(RemoteTaskORM)
            .where(RemoteTaskORM.target_device_id == device_id)
            .order_by(desc(RemoteTaskORM.requested_at))
            .limit(limit)
        )
        rows = self._session.scalars(stmt).all()
        return [_task_orm_to_domain(r) for r in rows]

    def list_recent_tasks(self, limit: int = 50) -> list[RemoteTask]:
        stmt = select(RemoteTaskORM).order_by(desc(RemoteTaskORM.requested_at)).limit(limit)
        rows = self._session.scalars(stmt).all()
        return [_task_orm_to_domain(r) for r in rows]
