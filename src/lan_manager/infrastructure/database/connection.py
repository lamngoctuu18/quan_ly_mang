"""PostgreSQL engine, session factory, transactional context manager, and health checks."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.domain.exceptions import DatabaseUnavailableError

logger = get_logger(__name__)


class DatabaseManager:
    """Manages SQLAlchemy engine, pooled sessions, and non-blocking health checks."""

    def __init__(self, config: AppConfig | None = None, db_url_override: str | None = None) -> None:
        self._config = config or get_config()
        self._db_url_override = db_url_override
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None

    @property
    def database_url(self) -> str:
        if self._db_url_override:
            return self._db_url_override
        return self._config.get_database_url(hide_password=False)

    def get_engine(self) -> Engine:
        """Lazily initialize and return the pooled SQLAlchemy Engine."""
        if self._engine is None:
            url = self.database_url
            engine_kwargs: dict[str, Any] = {
                "pool_pre_ping": True,
                "future": True,
            }
            if url.startswith("postgresql"):
                engine_kwargs["pool_size"] = self._config.db_pool_size
                engine_kwargs["max_overflow"] = self._config.db_max_overflow
                engine_kwargs["connect_args"] = {
                    "connect_timeout": self._config.db_connect_timeout,
                }
            self._engine = create_engine(url, **engine_kwargs)
            self._session_factory = sessionmaker(
                bind=self._engine,
                autoflush=False,
                autocommit=False,
                expire_on_commit=False,
            )
        return self._engine

    def get_session_factory(self) -> sessionmaker[Session]:
        if self._session_factory is None:
            self.get_engine()
        assert self._session_factory is not None
        return self._session_factory

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """
        Provide a transactional scope around a series of repository operations.
        Ensures the session is always closed and translates connectivity errors cleanly.
        """
        factory = self.get_session_factory()
        session = factory()
        try:
            yield session
            session.commit()
        except OperationalError as exc:
            session.rollback()
            logger.error(
                "Lỗi kết nối cơ sở dữ liệu PostgreSQL: %s",
                exc,
                extra={"error_code": "DB_OPERATIONAL_ERROR"},
            )
            raise DatabaseUnavailableError(
                "Không thể kết nối tới cơ sở dữ liệu PostgreSQL. Vui lòng kiểm tra dịch vụ DB và cấu hình .env."
            ) from exc
        except SQLAlchemyError as exc:
            session.rollback()
            logger.error(
                "Lỗi giao dịch cơ sở dữ liệu: %s",
                exc,
                extra={"error_code": "DB_TRANSACTION_ERROR"},
            )
            raise
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def check_connection(self) -> tuple[bool, str]:
        """
        Verify connectivity to PostgreSQL with a fast query.
        Returns (is_connected, status_message) without raising unhandled exceptions.
        """
        try:
            engine = self.get_engine()
            with engine.connect() as conn:
                version_row = conn.execute(text("SELECT 1")).scalar()
                if version_row == 1:
                    return (
                        True,
                        f"Đã kết nối ({self._config.db_host}:{self._config.db_port}/{self._config.db_name})",
                    )
            return False, "Truy vấn kiểm tra trả về kết quả không hợp lệ."
        except Exception as exc:
            logger.warning(
                "Kiểm tra kết nối PostgreSQL thất bại: %s",
                exc,
                extra={"error_code": "DB_HEALTHCHECK_FAILED"},
            )
            return (
                False,
                f"Không thể kết nối DB ({self._config.db_host}:{self._config.db_port}): {exc.__class__.__name__}",
            )

    def dispose(self) -> None:
        """Close all pooled connections gracefully."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None


_default_db_manager: DatabaseManager | None = None


def get_db_manager(config: AppConfig | None = None, reset: bool = False) -> DatabaseManager:
    """Return the singleton DatabaseManager instance."""
    global _default_db_manager
    if _default_db_manager is None or reset:
        if _default_db_manager is not None:
            _default_db_manager.dispose()
        _default_db_manager = DatabaseManager(config=config)
    return _default_db_manager
