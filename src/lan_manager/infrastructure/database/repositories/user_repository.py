"""User and Role repository for RBAC authentication and account management."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from lan_manager.core.security import hash_password
from lan_manager.domain.enums.system_enums import RoleType
from lan_manager.domain.models.entities import Role, User, utc_now
from lan_manager.infrastructure.database.models import RoleORM, UserORM


def _user_orm_to_domain(orm_obj: UserORM) -> User:
    role_enum = RoleType(orm_obj.role.name) if orm_obj.role else RoleType.VIEWER
    return User(
        id=orm_obj.id,
        username=orm_obj.username,
        full_name=orm_obj.full_name,
        password_hash=orm_obj.password_hash,
        role_id=orm_obj.role_id,
        role_name=role_enum,
        is_active=orm_obj.is_active,
        last_login_at=orm_obj.last_login_at,
        created_at=orm_obj.created_at,
        updated_at=orm_obj.updated_at,
    )


class UserRepository:
    """Manages RBAC roles and user accounts."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_default_roles(self) -> dict[RoleType, Role]:
        """Seed standard RBAC roles if they do not exist."""
        role_descriptions = {
            RoleType.VIEWER: "Chỉ xem dữ liệu thiết bị, máy in và trạng thái",
            RoleType.TECHNICIAN: "Thực hiện quét mạng LAN và chạy chẩn đoán sự cố",
            RoleType.OPERATOR: "Thực hiện các tác vụ sửa lỗi từ xa trong danh mục cho phép",
            RoleType.ADMIN: "Quản trị toàn bộ cấu hình hệ thống, phân quyền và nhật ký",
        }
        result: dict[RoleType, Role] = {}
        for role_type, desc_text in role_descriptions.items():
            orm_role = self._session.scalar(select(RoleORM).where(RoleORM.name == role_type.value))
            if orm_role is None:
                orm_role = RoleORM(
                    name=role_type.value,
                    description=desc_text,
                    created_at=utc_now(),
                )
                self._session.add(orm_role)
                self._session.flush()
            result[role_type] = Role(
                id=orm_role.id,
                name=RoleType(orm_role.name),
                description=orm_role.description,
                created_at=orm_role.created_at,
            )
        return result

    def get_by_username(self, username: str) -> User | None:
        orm_obj = self._session.scalar(
            select(UserORM)
            .options(joinedload(UserORM.role))
            .where(UserORM.username == username.strip())
        )
        return _user_orm_to_domain(orm_obj) if orm_obj else None

    def create_user(
        self,
        username: str,
        plain_password: str,
        role_type: RoleType,
        full_name: str = "",
    ) -> User:
        roles = self.ensure_default_roles()
        target_role = roles[role_type]
        now = utc_now()
        orm_user = UserORM(
            username=username.strip(),
            full_name=full_name or username.strip(),
            password_hash=hash_password(plain_password),
            role_id=target_role.id,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        self._session.add(orm_user)
        self._session.flush()
        loaded = self.get_by_username(username.strip())
        assert loaded is not None
        return loaded

    def record_login(self, username: str) -> None:
        orm_obj = self._session.scalar(select(UserORM).where(UserORM.username == username.strip()))
        if orm_obj is not None:
            orm_obj.last_login_at = utc_now()
            self._session.flush()

    def list_users(self) -> list[User]:
        stmt = select(UserORM).options(joinedload(UserORM.role)).order_by(UserORM.username)
        rows = self._session.scalars(stmt).unique().all()
        return [_user_orm_to_domain(r) for r in rows]
