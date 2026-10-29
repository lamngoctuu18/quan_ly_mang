"""Audit logging and operator authentication service."""

from __future__ import annotations

from typing import Any

from lan_manager.core.logging_config import get_logger
from lan_manager.core.security import UserSessionContext, verify_password
from lan_manager.domain.enums.system_enums import AuditResult, RoleType
from lan_manager.domain.exceptions import AuthenticationError
from lan_manager.domain.models.entities import AuditLog
from lan_manager.infrastructure.database.connection import DatabaseManager, get_db_manager
from lan_manager.infrastructure.database.repositories import AuditRepository, UserRepository

logger = get_logger(__name__)


class AuditService:
    """Coordinates immutable audit logging and operator authentication."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()

    def record_event(
        self,
        user_ctx: UserSessionContext | None,
        action: str,
        target_type: str,
        target_id: str,
        result: AuditResult,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog | None:
        """Persist an administrative event to audit_logs safely."""
        username = user_ctx.username if user_ctx else "system"
        user_id = user_ctx.user_id if user_ctx else None
        try:
            with self._db.session_scope() as session:
                repo = AuditRepository(session)
                return repo.append(
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    result=result,
                    username=username,
                    user_id=user_id,
                    metadata=metadata,
                )
        except Exception as exc:
            logger.error(
                "Không thể ghi audit log cho hành động %s: %s",
                action,
                exc,
                extra={"error_code": "AUDIT_WRITE_FAILED"},
            )
            return None

    def list_audit_logs(
        self,
        search_query: str | None = None,
        action_filter: str | None = None,
        result_filter: AuditResult | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[AuditLog], int]:
        """Query paginated audit logs."""
        with self._db.session_scope() as session:
            repo = AuditRepository(session)
            return repo.list_logs(
                search_query=search_query,
                action_filter=action_filter,
                result_filter=result_filter,
                offset=offset,
                limit=limit,
            )

    def authenticate_user(self, username: str, password: str) -> UserSessionContext:
        """Authenticate an operator against PostgreSQL users table and record audit log."""
        cleaned_user = username.strip()
        if not cleaned_user or not password:
            raise AuthenticationError("Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.")

        auth_failed = False
        authenticated_ctx: UserSessionContext | None = None

        with self._db.session_scope() as session:
            user_repo = UserRepository(session)
            audit_repo = AuditRepository(session)
            user = user_repo.get_by_username(cleaned_user)

            if (
                user is None
                or not user.is_active
                or not verify_password(password, user.password_hash)
            ):
                audit_repo.append(
                    action="USER_LOGIN",
                    target_type="USER",
                    target_id=cleaned_user,
                    result=AuditResult.FAILURE,
                    username=cleaned_user,
                    metadata={"reason": "Invalid credentials or inactive account"},
                )
                auth_failed = True
            else:
                user_repo.record_login(cleaned_user)
                audit_repo.append(
                    action="USER_LOGIN",
                    target_type="USER",
                    target_id=str(user.id),
                    result=AuditResult.SUCCESS,
                    username=user.username,
                    user_id=user.id,
                    metadata={"role": user.role_name.value},
                )
                authenticated_ctx = UserSessionContext(
                    user_id=user.id,
                    username=user.username,
                    full_name=user.full_name,
                    role=user.role_name,
                )

        if auth_failed or authenticated_ctx is None:
            raise AuthenticationError("Tên đăng nhập hoặc mật khẩu không chính xác.")
        return authenticated_ctx

    @staticmethod
    def create_default_session(
        role: RoleType = RoleType.ADMIN, username: str = "admin"
    ) -> UserSessionContext:
        """Provide an authenticated session context for local workstation administration."""
        return UserSessionContext(
            user_id=None,
            username=username,
            full_name=f"Local Operator ({role.value})",
            role=role,
        )
