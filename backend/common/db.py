from __future__ import annotations

import ssl
from dataclasses import dataclass

from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from backend.common.config import Settings
from backend.common.logging import get_logger

logger = get_logger(__name__)


def _normalize_async_dsn(dsn: str) -> str:
    url = make_url(dsn)

    if url.drivername in {"postgresql", "postgres"}:
        url = url.set(drivername="postgresql+asyncpg")
    elif url.drivername.startswith("postgresql") and "+" not in url.drivername:
        url = url.set(drivername="postgresql+asyncpg")

    return url.render_as_string(hide_password=False)


def _safe_dsn_for_logging(dsn: str) -> str:
    url: URL = make_url(dsn)
    return url.render_as_string(hide_password=True)


def _build_ssl_context(settings: Settings) -> ssl.SSLContext | None:
    if not settings.db_ssl_required:
        return None

    context = ssl.create_default_context(cafile=settings.db_ssl_ca_file)

    if settings.db_ssl_cert_file and settings.db_ssl_key_file:
        context.load_cert_chain(
            certfile=settings.db_ssl_cert_file,
            keyfile=settings.db_ssl_key_file,
        )

    return context


@dataclass
class Database:
    core_engine: AsyncEngine | None
    secure_engine: AsyncEngine | None
    core_sessionmaker: async_sessionmaker[AsyncSession] | None
    secure_sessionmaker: async_sessionmaker[AsyncSession] | None

    @classmethod
    def from_settings(cls, settings: Settings) -> "Database":
        ssl_context = _build_ssl_context(settings)

        core_engine: AsyncEngine | None = None
        secure_engine: AsyncEngine | None = None

        if settings.core_db_dsn is not None:
            core_dsn = _normalize_async_dsn(settings.core_db_dsn.get_secret_value())
            logger.info("Configuring core database engine: %s", _safe_dsn_for_logging(core_dsn))
            core_engine = create_async_engine(
                core_dsn,
                pool_pre_ping=True,
                pool_size=settings.db_pool_size,
                max_overflow=settings.db_max_overflow,
                pool_timeout=settings.db_pool_timeout_s,
                connect_args={"ssl": ssl_context} if ssl_context else {},
            )

        if settings.secure_db_dsn is not None:
            secure_dsn = _normalize_async_dsn(settings.secure_db_dsn.get_secret_value())
            logger.info(
                "Configuring secure database engine: %s",
                _safe_dsn_for_logging(secure_dsn),
            )
            secure_engine = create_async_engine(
                secure_dsn,
                pool_pre_ping=True,
                pool_size=settings.db_pool_size,
                max_overflow=settings.db_max_overflow,
                pool_timeout=settings.db_pool_timeout_s,
                connect_args={"ssl": ssl_context} if ssl_context else {},
            )

        core_sessionmaker = (
            async_sessionmaker(core_engine, expire_on_commit=False) if core_engine else None
        )
        secure_sessionmaker = (
            async_sessionmaker(secure_engine, expire_on_commit=False) if secure_engine else None
        )

        return cls(
            core_engine=core_engine,
            secure_engine=secure_engine,
            core_sessionmaker=core_sessionmaker,
            secure_sessionmaker=secure_sessionmaker,
        )

    async def ping_core(self) -> str | None:
        if self.core_engine is None:
            return None

        try:
            async with self.core_engine.connect() as conn:
                await conn.exec_driver_sql("SELECT 1")
            return "ok"
        except Exception:
            logger.exception("Core database ping failed")
            return "error"

    async def ping_secure(self) -> str | None:
        if self.secure_engine is None:
            return None

        try:
            async with self.secure_engine.connect() as conn:
                await conn.exec_driver_sql("SELECT 1")
            return "ok"
        except Exception:
            logger.exception("Secure database ping failed")
            return "error"

    async def dispose(self) -> None:
        if self.core_engine is not None:
            await self.core_engine.dispose()

        if self.secure_engine is not None:
            await self.secure_engine.dispose()
