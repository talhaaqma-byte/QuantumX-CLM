"""Test configuration and fixtures."""

import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth.models.audit import AuditLog
from backend.common.models import Base


@pytest_asyncio.fixture
async def db_session():
    """Create an in-memory SQLite database session for testing."""
    # Use in-memory SQLite for tests
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Create only the audit_log table for testing
    async with engine.begin() as conn:
        await conn.run_sync(AuditLog.__table__.create, checkfirst=True)

    # Create session
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session_maker() as session:
        yield session

    # Clean up
    await engine.dispose()
