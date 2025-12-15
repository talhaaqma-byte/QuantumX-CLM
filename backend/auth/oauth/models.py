"""
OAuth2/OIDC data models for storing OAuth client and authorization state.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class OAuthClient(BaseModel):
    """OAuth client application."""

    client_id: str = Field(..., description="Unique client identifier")
    client_secret_hash: str = Field(..., description="Hashed client secret")
    client_name: str = Field(..., description="Human-readable client name")
    owner_user_id: UUID = Field(..., description="User ID who registered the client")
    
    redirect_uris: list[str] = Field(..., description="Authorized redirect URIs")
    grant_types: list[str] = Field(
        default_factory=lambda: ["authorization_code"],
        description="Supported grant types"
    )
    response_types: list[str] = Field(
        default_factory=lambda: ["code"],
        description="Supported response types"
    )
    
    scopes: list[str] = Field(
        default_factory=lambda: ["openid", "profile"],
        description="Scopes the client can request"
    )
    
    is_confidential: bool = Field(
        default=True,
        description="Whether this is a confidential client (has secret)"
    )
    is_active: bool = Field(default=True, description="Whether client is active")
    
    created_at: datetime = Field(..., description="Client creation timestamp")
    updated_at: datetime = Field(..., description="Client update timestamp")


class AuthorizationCode(BaseModel):
    """OAuth authorization code."""

    code: str = Field(..., description="Authorization code")
    client_id: str = Field(..., description="Client ID that requested the code")
    user_id: UUID = Field(..., description="User who authorized the code")
    redirect_uri: str = Field(..., description="Redirect URI for the code")
    scopes: list[str] = Field(
        default_factory=list,
        description="Scopes requested"
    )
    nonce: str | None = Field(
        default=None,
        description="OpenID Connect nonce"
    )
    
    created_at: datetime = Field(..., description="Code creation timestamp")
    expires_at: datetime = Field(..., description="Code expiration timestamp")
    used: bool = Field(default=False, description="Whether code has been used")
    used_at: datetime | None = Field(default=None, description="When code was used")


class TokenRequest(BaseModel):
    """OAuth token request."""

    grant_type: str = Field(..., description="Grant type (e.g., 'authorization_code')")
    code: str | None = Field(default=None, description="Authorization code")
    redirect_uri: str | None = Field(default=None, description="Redirect URI")
    client_id: str = Field(..., description="Client ID")
    client_secret: str | None = Field(default=None, description="Client secret (for confidential clients)")
    refresh_token: str | None = Field(default=None, description="Refresh token (for refresh_token grant)")


class TokenResponse(BaseModel):
    """OAuth token response."""

    access_token: str = Field(..., description="Access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Expiration time in seconds")
    refresh_token: str | None = Field(default=None, description="Refresh token")
    id_token: str | None = Field(default=None, description="ID token (for OIDC)")
    scope: str | None = Field(default=None, description="Granted scopes")


class AuthorizationRequest(BaseModel):
    """OAuth authorization request."""

    response_type: str = Field(..., description="Response type (e.g., 'code')")
    client_id: str = Field(..., description="Client ID")
    redirect_uri: str = Field(..., description="Redirect URI")
    scope: str | None = Field(default=None, description="Space-separated scopes")
    state: str | None = Field(default=None, description="State parameter for CSRF protection")
    nonce: str | None = Field(default=None, description="Nonce for OpenID Connect")


class JWKSet(BaseModel):
    """JSON Web Key Set (JWKS)."""

    keys: list[dict] = Field(..., description="List of JSON Web Keys")
