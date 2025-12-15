from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID as PyUUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.models import Base, TimestampMixin, UUIDMixin


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    # Authentication
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_salt: Mapped[str] = mapped_column(String(255), nullable=False)
    password_changed_at: Mapped[Optional[datetime]] = mapped_column()
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    # Profile
    first_name: Mapped[Optional[str]] = mapped_column(String(255))
    last_name: Mapped[Optional[str]] = mapped_column(String(255))
    display_name: Mapped[Optional[str]] = mapped_column(String(255))
    phone_number: Mapped[Optional[str]] = mapped_column(String(50))

    # Status
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False
    )
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column()

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255))
    mfa_backup_codes: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))

    # Session management
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[Optional[datetime]] = mapped_column()
    last_login_ip: Mapped[Optional[str]] = mapped_column(INET)
    last_activity_at: Mapped[Optional[datetime]] = mapped_column()

    # API access
    api_access_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Audit fields
    created_by_user_id: Mapped[Optional[PyUUID]] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        secondary="user_roles", back_populates="users", viewonly=True
    )
    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="user")

    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'inactive', 'locked', 'suspended')",
            name="chk_user_status",
        ),
        # Indexes are already defined in SQL, but good to have them here for reference/autogen
        # However, if I define them here and they exist, autogen might not do anything or might complain.
        # I'll rely on existing schema for existing tables.
    )


class Role(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "roles"

    role_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    role_code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Permissions (legacy JSONB column)
    permissions_json: Mapped[dict] = mapped_column(
        "permissions", JSONB, default=dict, nullable=False
    )

    # Role hierarchy
    parent_role_id: Mapped[Optional[PyUUID]] = mapped_column(
        ForeignKey("roles.id")
    )
    is_system_role: Mapped[bool] = mapped_column(Boolean, default=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Audit fields
    created_by_user_id: Mapped[Optional[PyUUID]] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )

    # Relationships
    users: Mapped[List["User"]] = relationship(
        secondary="user_roles", back_populates="roles", viewonly=True
    )
    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="role")
    
    permissions: Mapped[List["Permission"]] = relationship(
        secondary="role_permissions", back_populates="roles"
    )

    parent_role: Mapped[Optional["Role"]] = relationship(
        remote_side="Role.id", backref="child_roles"
    )


class UserRole(Base, UUIDMixin):
    __tablename__ = "user_roles"

    user_id: Mapped[PyUUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[PyUUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )

    # Temporal assignment
    valid_from: Mapped[Optional[datetime]] = mapped_column(
        default=datetime.now
    )
    valid_until: Mapped[Optional[datetime]] = mapped_column()

    # Audit fields
    assigned_by_user_id: Mapped[Optional[PyUUID]] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        default=datetime.now
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column()
    revoked_by_user_id: Mapped[Optional[PyUUID]] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="user_roles")
    role: Mapped["Role"] = relationship(back_populates="user_roles")

    __table_args__ = (
        CheckConstraint(
            "valid_from < valid_until OR valid_until IS NULL",
            name="chk_valid_period",
        ),
    )


class Permission(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "permissions"

    permission_code: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(Text)
    resource: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        secondary="role_permissions", back_populates="permissions", viewonly=True
    )


class RolePermission(Base, UUIDMixin):
    __tablename__ = "role_permissions"

    role_id: Mapped[PyUUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[PyUUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )
    
    created_at: Mapped[datetime] = mapped_column(
        default=datetime.now
    )
    
    # Relationships
    role: Mapped["Role"] = relationship(backref="role_permissions")
    permission: Mapped["Permission"] = relationship(backref="role_permission_associations")
