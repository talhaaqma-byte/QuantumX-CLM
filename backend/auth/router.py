"""
Auth module router.

This router is imported by the main API router to include all authentication endpoints.
Currently the auth service routes are disabled as they contain no logic yet.
"""

from __future__ import annotations

from fastapi import APIRouter

from backend.auth.api.router import router as auth_api_router
from backend.auth.oauth.api import router as oauth_router

router = APIRouter(prefix="/auth", tags=["auth"])

# Include the API router (currently disabled - no logic implemented)
# router.include_router(auth_api_router)

# Include OAuth2/OIDC router
router.include_router(oauth_router)
