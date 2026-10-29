"""Database initialization, schema verification, and initial RBAC bootstrap script."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lan_manager.core.config import get_config
from lan_manager.core.logging_config import get_logger, setup_logging
from lan_manager.domain.enums.system_enums import AuditResult, RoleType
from lan_manager.infrastructure.database.base import Base
from lan_manager.infrastructure.database.connection import get_db_manager
from lan_manager.infrastructure.database.repositories import AuditRepository, UserRepository


def initialize_database() -> int:
    """Verify PostgreSQL connectivity, ensure schema tables exist, and seed RBAC roles."""
    config = get_config()
    setup_logging(config)
    logger = get_logger("scripts.init_db")

    logger.info("Đang kiểm tra kết nối tới PostgreSQL: %s", config.get_database_url(hide_password=True))
    db_manager = get_db_manager(config)
    ok, msg = db_manager.check_connection()
    if not ok:
        logger.error("Không thể kết nối PostgreSQL: %s", msg)
        logger.info("Hãy xem hướng dẫn tạo database tại scripts/sql_setup_guide.sql và cấu hình file .env.")
        return 1

    logger.info("Kết nối thành công: %s", msg)
    engine = db_manager.get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("Đã đồng bộ cấu trúc bảng cơ sở dữ liệu.")

    admin_user = os.getenv("INITIAL_ADMIN_USERNAME", "admin").strip()
    admin_pass = os.getenv("INITIAL_ADMIN_PASSWORD", "").strip()

    with db_manager.session_scope() as session:
        user_repo = UserRepository(session)
        audit_repo = AuditRepository(session)
        user_repo.ensure_default_roles()

        existing_admin = user_repo.get_by_username(admin_user)
        if existing_admin is None:
            if len(admin_pass) >= 8 and admin_pass != "CHANGE_ME_BEFORE_INIT":
                created = user_repo.create_user(
                    username=admin_user,
                    plain_password=admin_pass,
                    role_type=RoleType.ADMIN,
                    full_name="System Administrator",
                )
                audit_repo.append(
                    action="BOOTSTRAP_ADMIN_USER",
                    target_type="USER",
                    target_id=str(created.id),
                    result=AuditResult.SUCCESS,
                    username="system",
                    metadata={"username": created.username, "role": created.role_name.value},
                )
                logger.info("Đã khởi tạo tài khoản quản trị viên '%s'.", admin_user)
            else:
                logger.warning(
                    "Chưa tạo tài khoản '%s' vì biến môi trường INITIAL_ADMIN_PASSWORD chưa được đặt "
                    "hoặc ngắn hơn 8 ký tự.",
                    admin_user,
                )
        else:
            logger.info("Tài khoản quản trị '%s' đã tồn tại.", admin_user)

    return 0


if __name__ == "__main__":
    raise SystemExit(initialize_database())

