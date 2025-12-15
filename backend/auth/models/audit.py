from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional
from uuid import UUID as PyUUID

from sqlalchemy import CheckConstraint, DateTime, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from backend.common.models import Base, UUIDMixin


class INETType(TypeDecorator):
    """Custom type that handles INET for PostgreSQL and String for other databases."""
    
    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(INET())
        else:
            return dialect.type_descriptor(String(45))


class JSONBType(TypeDecorator):
    """Custom type that handles JSONB for PostgreSQL and JSON for other databases."""
    
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(JSON())


class AuditLog(Base):
    __tablename__ = "audit_log"

    # Override UUIDMixin to allow client-side UUID generation for SQLite compatibility
    id: Mapped[PyUUID] = mapped_column(
        primary_key=True, default=lambda: PyUUID(int=secrets.randbits(128))
    )

    event_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Actor
    user_id: Mapped[Optional[PyUUID]] = mapped_column()
    username: Mapped[Optional[str]] = mapped_column(String(255))
    organization_id: Mapped[Optional[PyUUID]] = mapped_column()

    # Resource
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    resource_id: Mapped[Optional[PyUUID]] = mapped_column()
    resource_name: Mapped[Optional[str]] = mapped_column(String(255))

    # Action
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    action_result: Mapped[str] = mapped_column(String(50), nullable=False)

    # Context
    ip_address: Mapped[Optional[str]] = mapped_column(INETType)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    session_id: Mapped[Optional[str]] = mapped_column(String(255))
    request_id: Mapped[Optional[str]] = mapped_column(String(255))

    # Changes
    changes_before: Mapped[Optional[dict]] = mapped_column(JSONBType)
    changes_after: Mapped[Optional[dict]] = mapped_column(JSONBType)
    change_summary: Mapped[Optional[str]] = mapped_column(Text)

    # Additional details
    event_data: Mapped[Optional[dict]] = mapped_column(JSONBType)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamp
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.current_timestamp()
    )

    __table_args__ = (
        CheckConstraint(
            "event_category IN ('authentication', 'authorization', 'certificate', "
            "'policy', 'workflow', 'user_management', 'system')",
            name="chk_audit_category",
        ),
        CheckConstraint(
            "severity IN ('info', 'warning', 'error', 'critical')",
            name="chk_audit_severity",
        ),
        CheckConstraint(
            "action_result IN ('success', 'failure', 'partial')",
            name="chk_audit_result",
        ),
    )
