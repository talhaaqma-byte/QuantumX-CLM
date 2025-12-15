"""
Authentication API routes.

This module contains the FastAPI router for authentication endpoints.
Routes are organized by authentication type:
- login: Username/password authentication
- register: User registration  
- logout: Session termination
- refresh: Token refresh (future implementation)
- profile: User profile management
- permissions: Role and permission management
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])

# Import all route modules here to register routes
from backend.auth.api.login import router as login_router
from backend.auth.api.register import router as register_router
from backend.auth.api.logout import router as logout_router
from backend.auth.api.refresh import router as refresh_router
from backend.auth.api.profile import router as profile_router
from backend.auth.api.permissions import router as permissions_router

# Include all route routers (currently disabled - no logic implemented)
# router.include_router(login_router)
# router.include_router(register_router)
# router.include_router(logout_router)
# router.include_router(refresh_router)
# router.include_router(profile_router)
# router.include_router(permissions_router)