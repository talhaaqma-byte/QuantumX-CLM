from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Set
from uuid import UUID

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.deps import get_current_user, UserContext
from backend.common.deps import get_core_session
from backend.auth.models.rbac import User, Role, UserRole, Permission


async def get_user_permissions(
    session: AsyncSession, user_id: UUID
) -> Set[str]:
    """
    Get all permission codes for a user.
    
    Includes permissions from:
    1. Assigned roles (via RolePermission)
    2. Assigned roles (via legacy permissions_json)
    
    Checks for:
    - User not deleted
    - Role assignment validity (not revoked, within time validity)
    - Role active status and not deleted
    """
    stmt = (
        select(User)
        .options(
            selectinload(User.user_roles)
            .selectinload(UserRole.role)
            .selectinload(Role.permissions),
        )
        .where(User.id == user_id)
        .where(User.deleted_at.is_(None))
    )
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        return set()
        
    permissions = set()
    now = datetime.now(timezone.utc).replace(tzinfo=None) # DB might be naive or aware, usually safer to match. 
    # Actually UserRole.valid_until defaults to None.
    # UserRole.valid_from defaults to datetime.now
    
    # Note: timestamps in DB are usually timezone aware if using TimestampMixin with DateTime(timezone=True)
    # But UserRole uses explicit columns. Let's check rbac.py again.
    # valid_until: Mapped[Optional[datetime]] = mapped_column() - default maps to DateTime (naive usually unless configured)
    # But TimestampMixin uses DateTime(timezone=True).
    # Let's assume naive for now or handle both. 
    # If I use datetime.now() it is naive local. 
    
    for user_role in user.user_roles:
        # Check assignment validity
        if user_role.revoked_at is not None:
            continue
            
        # Check time validity
        # We need to be careful with timezone here. 
        # If valid_until is set, check it.
        if user_role.valid_until is not None:
            # Simple comparison assuming compatible types
            if user_role.valid_until < datetime.now(user_role.valid_until.tzinfo):
                 continue
                 
        role = user_role.role
        
        # Check role status
        if role.deleted_at is not None:
            continue
            
        if not role.is_active:
            continue
            
        # 1. RolePermission based permissions
        for perm in role.permissions:
            # Check permission soft delete if applicable (Permission inherits TimestampMixin)
            if perm.deleted_at is not None:
                continue
            permissions.add(perm.permission_code)
            
        # 2. Legacy JSON permissions
        if role.permissions_json:
            for code, granted in role.permissions_json.items():
                if granted:
                    permissions.add(code)
                    
    return permissions


async def check_user_permission(
    session: AsyncSession, user_id: UUID, permission_code: str
) -> bool:
    """
    Check if a user has a specific permission.
    """
    permissions = await get_user_permissions(session, user_id)
    return permission_code in permissions


class PermissionChecker:
    """
    FastAPI dependency for permission checking.
    """
    
    def __init__(self, required_permission: str):
        self.required_permission = required_permission
        
    async def __call__(
        self,
        user: UserContext = Depends(get_current_user),
        session: AsyncSession = Depends(get_core_session),
    ) -> UserContext:
        """
        Check if user has permission.
        """
        has_perm = await check_user_permission(
            session, user.user_id, self.required_permission
        )
        
        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {self.required_permission} required",
            )
            
        return user


class RoleChecker:
    """
    FastAPI dependency for role checking.
    """
    
    def __init__(self, required_role: str):
        self.required_role = required_role
        
    async def __call__(
        self,
        user: UserContext = Depends(get_current_user),
        session: AsyncSession = Depends(get_core_session),
    ) -> UserContext:
        """
        Check if user has role.
        """
        stmt = (
            select(User)
            .options(selectinload(User.user_roles).selectinload(UserRole.role))
            .where(User.id == user.user_id)
            .where(User.deleted_at.is_(None))
        )
        result = await session.execute(stmt)
        db_user = result.scalar_one_or_none()
        
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
            
        # Check active roles
        active_roles = set()
        for user_role in db_user.user_roles:
            if user_role.revoked_at is not None:
                continue
                
            if user_role.valid_until is not None:
                if user_role.valid_until < datetime.now(user_role.valid_until.tzinfo):
                    continue
                    
            if user_role.role.deleted_at is not None:
                continue
                
            if not user_role.role.is_active:
                continue
                
            active_roles.add(user_role.role.role_name)
        
        if self.required_role not in active_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role denied: {self.required_role} required",
            )
            
        return user


def require_permission(permission_code: str) -> PermissionChecker:
    """
    Dependency to require a specific permission.
    
    Example:
        @router.get("/items", dependencies=[Depends(require_permission("items:read"))])
        async def get_items():
            ...
    """
    return PermissionChecker(permission_code)


def require_role(role_name: str) -> RoleChecker:
    """
    Dependency to require a specific role.
    
    Example:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
        async def admin_only():
            ...
    """
    return RoleChecker(role_name)
