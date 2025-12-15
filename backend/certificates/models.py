"""
Certificate domain models for CLM backend.

This module contains SQLAlchemy models for certificate metadata stored in the core database.
Sensitive certificate data (private keys, certificates) are stored in the secure database.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID as PyUUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    ARRAY,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.models import Base, TimestampMixin, UUIDMixin


class CertificateStatus(str, Enum):
    """Certificate status lifecycle values."""
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class CertificateType(str, Enum):
    """Certificate type classification."""
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CLIENT = "client"
    SERVER = "server"
    CODE_SIGNING = "code_signing"
    EMAIL = "email"


class EnvironmentType(str, Enum):
    """Deployment environment classification."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"


class CertificateMetadata(Base, UUIDMixin, TimestampMixin):
    """
    Certificate metadata model.
    
    This model stores non-sensitive certificate metadata in the core database
    for querying and organization purposes. The actual certificate data
    (private keys, certificates) is stored in the secure database.
    
    Relationships:
        - Links to certificate data in secure DB via certificate_id
        - Owner relationship via owner_user_id
        - Organization relationship via organization_id
    """
    __tablename__ = "certificate_metadata"

    # Primary reference to secure database
    certificate_id: Mapped[PyUUID] = mapped_column(
        String(36), unique=True, nullable=False
    )

    # Basic certificate information (duplicated for query performance)
    common_name: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    certificate_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )

    # Certificate validity period
    not_before: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    not_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Ownership and organization
    owner_user_id: Mapped[PyUUID] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    organization_id: Mapped[Optional[PyUUID]] = mapped_column(
        ForeignKey("organizations.id"), nullable=True
    )

    # Categorization and tagging
    tags: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(100)), nullable=True
    )
    category: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    environment: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )

    # Custom metadata and notes
    custom_fields: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    __table_args__ = (
        # Enum constraints
        CheckConstraint(
            "certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')",
            name="chk_certificate_metadata_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'expiring', 'expired', 'revoked', 'suspended')",
            name="chk_certificate_metadata_status",
        ),
        CheckConstraint(
            "not_before < not_after",
            name="chk_certificate_metadata_validity_period",
        ),
        {"extend_existing": True},
    )

    def __repr__(self) -> str:
        return (
            f"<CertificateMetadata(id={self.id}, certificate_id={self.certificate_id}, "
            f"common_name='{self.common_name}', type='{self.certificate_type}', "
            f"status='{self.status}')>"
        )

    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.utcnow().replace(tzinfo=self.not_after.tzinfo) > self.not_after

    def is_expiring_soon(self, days: int = 30) -> bool:
        """Check if certificate expires within the specified number of days."""
        from datetime import timedelta
        expiry_threshold = datetime.utcnow().replace(tzinfo=self.not_after.tzinfo) + timedelta(days=days)
        return self.not_after <= expiry_threshold

    def get_remaining_days(self) -> int:
        """Get number of days until certificate expires."""
        now = datetime.utcnow().replace(tzinfo=self.not_after.tzinfo)
        return (self.not_after - now).days

    def to_dict(self) -> dict:
        """Convert certificate metadata to dictionary."""
        return {
            "id": str(self.id),
            "certificate_id": str(self.certificate_id),
            "common_name": self.common_name,
            "certificate_type": self.certificate_type,
            "status": self.status,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "owner_user_id": str(self.owner_user_id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "tags": self.tags,
            "category": self.category,
            "environment": self.environment,
            "custom_fields": self.custom_fields,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }