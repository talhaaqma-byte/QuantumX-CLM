"""Placeholder authentication schemas."""

from __future__ import annotations

from pydantic import BaseModel


class AuthResponse(BaseModel):
    """Authentication response (placeholder)."""
    access_token: str
    token_type: str = "bearer"


class ProfileResponse(BaseModel):
    """User profile response (placeholder)."""
    id: str
    username: str
    email: str


class TokenRefreshResponse(BaseModel):
    """Token refresh response (placeholder)."""
    access_token: str
    token_type: str = "bearer"


class RoleInfo(BaseModel):
    """Role information (placeholder)."""
    id: str
    name: str


class PermissionInfo(BaseModel):
    """Permission information (placeholder)."""
    id: str
    name: str
