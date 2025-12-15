import pytest
from unittest.mock import MagicMock, AsyncMock
from uuid import uuid4
from datetime import datetime, timedelta

from fastapi import HTTPException

from backend.auth.authorization import (
    get_user_permissions,
    check_user_permission,
    PermissionChecker,
    RoleChecker,
    require_permission,
    require_role
)
from backend.auth.models.rbac import User, Role, UserRole, Permission
from backend.auth.deps import UserContext

@pytest.mark.asyncio
async def test_get_user_permissions():
    """Test getting user permissions from roles and legacy JSON."""
    # Setup
    user_id = uuid4()
    session = AsyncMock()
    
    # Mock User
    user = User(id=user_id)
    user.deleted_at = None
    
    # Mock Role 1
    role1 = Role(id=uuid4(), role_name="admin", is_active=True)
    role1.deleted_at = None
    role1.permissions_json = {"legacy:perm": True, "legacy:denied": False}
    
    perm1 = Permission(id=uuid4(), permission_code="resource:action")
    perm1.deleted_at = None
    role1.permissions = [perm1]
    
    # Mock Role 2 (revoked)
    role2 = Role(id=uuid4(), role_name="editor", is_active=True)
    role2.deleted_at = None
    role2.permissions_json = {}
    perm2 = Permission(id=uuid4(), permission_code="resource:edit")
    perm2.deleted_at = None
    role2.permissions = [perm2]
    
    # Mock UserRole 1 (Active)
    ur1 = UserRole(user_id=user_id, role_id=role1.id)
    ur1.revoked_at = None
    ur1.valid_until = None
    ur1.role = role1
    
    # Mock UserRole 2 (Revoked)
    ur2 = UserRole(user_id=user_id, role_id=role2.id)
    ur2.revoked_at = datetime.now()
    ur2.valid_until = None
    ur2.role = role2
    
    user.user_roles = [ur1, ur2]
    
    # Mock session execution
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    perms = await get_user_permissions(session, user_id)
    
    # Assert
    assert "resource:action" in perms
    assert "legacy:perm" in perms
    assert "legacy:denied" not in perms
    assert "resource:edit" not in perms
    assert len(perms) == 2

@pytest.mark.asyncio
async def test_check_user_permission_success():
    """Test check_user_permission returns True when permission exists."""
    user_id = uuid4()
    session = AsyncMock()
    
    # Mock User
    user = User(id=user_id)
    user.deleted_at = None
    
    role = Role(id=uuid4(), role_name="admin", is_active=True)
    role.deleted_at = None
    role.permissions_json = {}
    perm = Permission(id=uuid4(), permission_code="test:perm")
    perm.deleted_at = None
    role.permissions = [perm]
    
    ur = UserRole(user_id=user_id, role_id=role.id)
    ur.revoked_at = None
    ur.valid_until = None
    ur.role = role
    user.user_roles = [ur]
    
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    result = await check_user_permission(session, user_id, "test:perm")
    assert result is True

@pytest.mark.asyncio
async def test_check_user_permission_failure():
    """Test check_user_permission returns False when permission missing."""
    user_id = uuid4()
    session = AsyncMock()
    
    # Mock User
    user = User(id=user_id)
    user.deleted_at = None
    user.user_roles = []
    
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    result = await check_user_permission(session, user_id, "test:perm")
    assert result is False

@pytest.mark.asyncio
async def test_permission_checker_dependency_success():
    """Test PermissionChecker dependency allows access."""
    user_id = uuid4()
    session = AsyncMock()
    checker = require_permission("test:perm")
    
    user_context = UserContext(
        user_id=user_id,
        token_type="access",
        issued_at=datetime.now(),
        expires_at=datetime.now() + timedelta(hours=1),
        claims={}
    )
    
    # Mock User with permission
    user = User(id=user_id)
    user.deleted_at = None
    
    role = Role(id=uuid4(), role_name="admin", is_active=True)
    role.deleted_at = None
    role.permissions_json = {}
    perm = Permission(id=uuid4(), permission_code="test:perm")
    perm.deleted_at = None
    role.permissions = [perm]
    
    ur = UserRole(user_id=user_id, role_id=role.id)
    ur.revoked_at = None
    ur.valid_until = None
    ur.role = role
    user.user_roles = [ur]
    
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    result = await checker(user=user_context, session=session)
    assert result == user_context

@pytest.mark.asyncio
async def test_permission_checker_dependency_forbidden():
    """Test PermissionChecker dependency raises 403."""
    user_id = uuid4()
    session = AsyncMock()
    checker = require_permission("test:perm")
    
    user_context = UserContext(
        user_id=user_id,
        token_type="access",
        issued_at=datetime.now(),
        expires_at=datetime.now() + timedelta(hours=1),
        claims={}
    )
    
    # Mock User without permission
    user = User(id=user_id)
    user.deleted_at = None
    user.user_roles = []
    
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    with pytest.raises(HTTPException) as exc_info:
        await checker(user=user_context, session=session)
    
    assert exc_info.value.status_code == 403
    assert "Permission denied" in exc_info.value.detail

@pytest.mark.asyncio
async def test_role_checker_dependency_success():
    """Test RoleChecker dependency allows access."""
    user_id = uuid4()
    session = AsyncMock()
    checker = require_role("admin")
    
    user_context = UserContext(
        user_id=user_id,
        token_type="access",
        issued_at=datetime.now(),
        expires_at=datetime.now() + timedelta(hours=1),
        claims={}
    )
    
    # Mock User with role
    user = User(id=user_id)
    user.deleted_at = None
    
    role = Role(id=uuid4(), role_name="admin", is_active=True)
    role.deleted_at = None
    
    ur = UserRole(user_id=user_id, role_id=role.id)
    ur.revoked_at = None
    ur.valid_until = None
    ur.role = role
    user.user_roles = [ur]
    
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    result = await checker(user=user_context, session=session)
    assert result == user_context

@pytest.mark.asyncio
async def test_role_checker_dependency_forbidden():
    """Test RoleChecker dependency raises 403."""
    user_id = uuid4()
    session = AsyncMock()
    checker = require_role("admin")
    
    user_context = UserContext(
        user_id=user_id,
        token_type="access",
        issued_at=datetime.now(),
        expires_at=datetime.now() + timedelta(hours=1),
        claims={}
    )
    
    # Mock User without role
    user = User(id=user_id)
    user.deleted_at = None
    user.user_roles = []
    
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute.return_value = result_mock
    
    # Execute
    with pytest.raises(HTTPException) as exc_info:
        await checker(user=user_context, session=session)
    
    assert exc_info.value.status_code == 403
    assert "Role denied" in exc_info.value.detail
