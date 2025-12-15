"""
Authentication models and data structures.

This module contains Pydantic models for authentication requests/responses,
as well as internal data structures for authentication state.

Note: No OAuth, JWT, or complex authentication logic implemented yet.
This is a skeleton for future implementation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


# Request/Response Models
class LoginRequest(BaseModel):
    """Request model for user login."""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")


class RegisterRequest(BaseModel):
    """Request model for user registration."""
    username: str = Field(..., description="Username")
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="User password")
    full_name: Optional[str] = Field(None, description="User full name")


class AuthResponse(BaseModel):
    """Response model for successful authentication."""
    success: bool = True
    message: str = "Authentication successful"
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: list[str] = []


class ErrorResponse(BaseModel):
    """Response model for authentication errors."""
    success: bool = False
    error: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code")


class LogoutResponse(BaseModel):
    """Response model for logout."""
    success: bool = True
    message: str = "Logged out successfully"


class ProfileResponse(BaseModel):
    """Response model for user profile data."""
    user_id: UUID
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True
    created_at: datetime
    updated_at: datetime
    roles: list[str] = []


class TokenRefreshRequest(BaseModel):
    """Request model for token refresh."""
    refresh_token: str = Field(..., description="Refresh token")


class TokenRefreshResponse(BaseModel):
    """Response model for token refresh."""
    access_token: str = Field(..., description="New access token")
    refresh_token: str = Field(..., description="New refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class ChangePasswordRequest(BaseModel):
    """Request model for password change."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., description="New password")


class RoleInfo(BaseModel):
    """Model for role information."""
    role_id: UUID
    role_name: str
    description: Optional[str] = None
    permissions: list[str] = []


class UserRolesResponse(BaseModel):
    """Response model for user roles."""
    user_id: UUID
    roles: list[RoleInfo]


class PermissionInfo(BaseModel):
    """Model for permission information."""
    permission_id: UUID
    permission_name: str
    description: Optional[str] = None
    resource: str = Field(..., description="Resource this permission applies to")
    action: str = Field(..., description="Action this permission allows")


class PermissionsResponse(BaseModel):
    """Response model for permissions listing."""
    permissions: list[PermissionInfo]