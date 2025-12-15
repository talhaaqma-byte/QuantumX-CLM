"""
OAuth2/OIDC API endpoints.

Endpoints:
- GET /oauth/authorize: Authorization request endpoint
- POST /oauth/token: Token endpoint
- GET /.well-known/jwks.json: JWKS endpoint
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from backend.auth.oauth.models import (
    AuthorizationRequest,
    TokenRequest,
)
from backend.auth.oauth.service import OAuthError

router = APIRouter(tags=["oauth"])


def get_oauth_service():
    """Get the OAuth service singleton."""
    from backend.auth.oauth import oauth_service
    return oauth_service


@router.get("/oauth/authorize")
async def authorize(
    response_type: str = Query(..., description="Response type (must be 'code')"),
    client_id: str = Query(..., description="Client ID"),
    redirect_uri: str = Query(..., description="Redirect URI"),
    scope: str | None = Query(None, description="Space-separated scopes"),
    state: str | None = Query(None, description="State parameter for CSRF protection"),
    nonce: str | None = Query(None, description="Nonce for OpenID Connect"),
) -> JSONResponse:
    """
    OAuth2/OIDC authorization endpoint.

    Initiates authorization code flow. User must be authenticated before calling this endpoint.
    In a full implementation, this would:
    1. Verify user is authenticated
    2. Show consent screen
    3. Redirect to redirect_uri with authorization code

    Current implementation returns error response format for testing.

    Args:
        response_type: Response type (must be 'code')
        client_id: Client ID
        redirect_uri: Redirect URI
        scope: Space-separated scopes
        state: State parameter
        nonce: Nonce value

    Returns:
        JSONResponse with error or would redirect to redirect_uri with code
    """
    try:
        # Parse request
        request = AuthorizationRequest(
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
        )

        # Validate request
        oauth = get_oauth_service()
        oauth.validate_authorization_request(request)

        # In production, this would:
        # 1. Check if user is authenticated (via session/JWT)
        # 2. Display consent screen
        # 3. Generate authorization code
        # 4. Redirect to redirect_uri with code

        # For now, return error indicating implementation needed
        return JSONResponse(
            status_code=501,
            content={
                "error": "not_implemented",
                "error_description": "Authorization endpoint requires user authentication context. "
                "In production, implement user authentication check and redirect.",
            },
        )

    except OAuthError as e:
        status_code = 400
        if e.error == "invalid_client":
            status_code = 401

        return JSONResponse(
            status_code=status_code,
            content={
                "error": e.error,
                "error_description": e.error_description,
            },
        )


@router.post("/oauth/token")
async def token(request: TokenRequest) -> JSONResponse:
    """
    OAuth2/OIDC token endpoint.

    Exchanges authorization code for tokens or refreshes access token.

    Args:
        request: TokenRequest with:
            - grant_type: "authorization_code" or "refresh_token"
            - code: Authorization code (for authorization_code grant)
            - redirect_uri: Redirect URI (for authorization_code grant)
            - refresh_token: Refresh token (for refresh_token grant)
            - client_id: Client ID
            - client_secret: Client secret (for confidential clients)

    Returns:
        JSONResponse with TokenResponse or error
    """
    try:
        oauth = get_oauth_service()
        if request.grant_type == "authorization_code":
            response = oauth.exchange_authorization_code(request)
        elif request.grant_type == "refresh_token":
            if not request.refresh_token:
                raise OAuthError("invalid_request", "refresh_token parameter required")
            response = oauth.refresh_access_token(
                refresh_token=request.refresh_token,
                client_id=request.client_id,
                client_secret=request.client_secret,
            )
        else:
            raise OAuthError(
                "unsupported_grant_type",
                f"Grant type '{request.grant_type}' not supported",
            )

        return JSONResponse(
            status_code=200,
            content=response.model_dump(exclude_none=True),
        )

    except OAuthError as e:
        status_code = 400
        if e.error == "invalid_client":
            status_code = 401

        return JSONResponse(
            status_code=status_code,
            content={
                "error": e.error,
                "error_description": e.error_description,
            },
        )


@router.get("/.well-known/jwks.json")
async def jwks() -> JSONResponse:
    """
    Get JSON Web Key Set (JWKS).

    This endpoint serves the public keys used to verify JWT tokens.
    Clients use this to validate ID tokens and access tokens.

    Returns:
        JSONResponse with JWKS
    """
    oauth = get_oauth_service()
    keys = oauth.get_public_jwks()
    return JSONResponse(content=keys)
