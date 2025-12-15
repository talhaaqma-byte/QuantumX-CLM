"""
Well-known endpoints for OAuth2/OIDC discovery.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["well-known"])


@router.get("/.well-known/jwks.json")
async def jwks() -> JSONResponse:
    """
    Get JSON Web Key Set (JWKS).

    This endpoint serves the public keys used to verify JWT tokens.
    Clients use this to validate ID tokens and access tokens.

    Returns:
        JSONResponse with JWKS
    """
    from backend.auth.oauth import oauth_service
    keys = oauth_service.get_public_jwks()
    return JSONResponse(content=keys)
