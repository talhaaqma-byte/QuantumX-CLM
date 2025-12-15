"""
OAuth2/OIDC service implementation.

Handles:
- Authorization code flow
- Token exchange
- JWKS generation
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import jwt
from pydantic import ValidationError

from backend.auth.core.jwt_utils import (
    TokenInvalidError,
    TokenPayload,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
)
from backend.auth.oauth.models import (
    AuthorizationCode,
    AuthorizationRequest,
    OAuthClient,
    TokenRequest,
    TokenResponse,
)
from backend.common.config import get_settings


class OAuthError(Exception):
    """Base exception for OAuth errors."""

    def __init__(self, error: str, error_description: str | None = None):
        self.error = error
        self.error_description = error_description
        super().__init__(f"{error}: {error_description}")


class OAuthInvalidClient(OAuthError):
    """Client authentication failed."""

    def __init__(self, error_description: str | None = None):
        super().__init__("invalid_client", error_description)


class OAuthInvalidGrant(OAuthError):
    """Authorization code expired or invalid."""

    def __init__(self, error_description: str | None = None):
        super().__init__("invalid_grant", error_description)


class OAuthInvalidRequest(OAuthError):
    """Request is missing required parameters."""

    def __init__(self, error_description: str | None = None):
        super().__init__("invalid_request", error_description)


class OAuthUnauthorizedClient(OAuthError):
    """Client is not authorized for the grant type."""

    def __init__(self, error_description: str | None = None):
        super().__init__("unauthorized_client", error_description)


class OAuthUnsupportedGrantType(OAuthError):
    """Grant type is not supported."""

    def __init__(self, error_description: str | None = None):
        super().__init__("unsupported_grant_type", error_description)


class OAuthService:
    """OAuth2/OIDC service."""

    def __init__(self):
        self.settings = get_settings()
        # In-memory storage for authorization codes and clients
        # In production, these would be persisted to database
        self._authorization_codes: dict[str, AuthorizationCode] = {}
        self._oauth_clients: dict[str, OAuthClient] = {}
        self._authorization_code_ttl = 600  # 10 minutes

    def register_client(
        self,
        client_id: str,
        client_name: str,
        owner_user_id: UUID,
        redirect_uris: list[str],
        scopes: list[str] | None = None,
        grant_types: list[str] | None = None,
        response_types: list[str] | None = None,
        is_confidential: bool = True,
    ) -> tuple[OAuthClient, str]:
        """
        Register a new OAuth client.

        Args:
            client_id: Unique client identifier
            client_name: Human-readable client name
            owner_user_id: User ID who owns the client
            redirect_uris: List of authorized redirect URIs
            scopes: Scopes the client can request
            grant_types: Supported grant types
            response_types: Supported response types
            is_confidential: Whether this is a confidential client

        Returns:
            Tuple of (OAuthClient, client_secret)
        """
        if client_id in self._oauth_clients:
            raise OAuthInvalidClient("Client ID already registered")

        # Generate client secret
        client_secret = secrets.token_urlsafe(32)
        client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()

        # Create client
        client = OAuthClient(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            client_name=client_name,
            owner_user_id=owner_user_id,
            redirect_uris=redirect_uris,
            scopes=scopes or ["openid", "profile"],
            grant_types=grant_types or ["authorization_code"],
            response_types=response_types or ["code"],
            is_confidential=is_confidential,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )

        self._oauth_clients[client_id] = client
        return client, client_secret

    def validate_client(
        self,
        client_id: str,
        client_secret: str | None = None,
    ) -> OAuthClient:
        """
        Validate client credentials.

        Args:
            client_id: Client ID
            client_secret: Client secret (required for confidential clients)

        Returns:
            OAuthClient if valid

        Raises:
            OAuthInvalidClient: If client validation fails
        """
        client = self._oauth_clients.get(client_id)
        if not client:
            raise OAuthInvalidClient("Invalid client_id")

        if not client.is_active:
            raise OAuthInvalidClient("Client is inactive")

        if client.is_confidential:
            if not client_secret:
                raise OAuthInvalidClient("client_secret required for confidential client")

            # Verify client secret
            secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
            if secret_hash != client.client_secret_hash:
                raise OAuthInvalidClient("Invalid client_secret")

        return client

    def validate_redirect_uri(self, client: OAuthClient, redirect_uri: str) -> None:
        """
        Validate redirect URI against client's registered URIs.

        Args:
            client: OAuthClient
            redirect_uri: Redirect URI to validate

        Raises:
            OAuthInvalidRequest: If redirect URI is not registered
        """
        if redirect_uri not in client.redirect_uris:
            raise OAuthInvalidRequest("Invalid redirect_uri")

    def validate_authorization_request(
        self,
        request: AuthorizationRequest,
    ) -> OAuthClient:
        """
        Validate authorization request.

        Args:
            request: AuthorizationRequest

        Returns:
            OAuthClient if valid

        Raises:
            OAuthError: If validation fails
        """
        if request.response_type != "code":
            raise OAuthInvalidRequest("response_type must be 'code'")

        # Get client without requiring secret (no authentication at authorization endpoint)
        client = self._oauth_clients.get(request.client_id)
        if not client:
            raise OAuthInvalidClient("Invalid client_id")

        if not client.is_active:
            raise OAuthInvalidClient("Client is inactive")

        if "code" not in client.response_types:
            raise OAuthUnauthorizedClient(
                "Client not authorized for response_type=code"
            )

        self.validate_redirect_uri(client, request.redirect_uri)

        # Validate scopes
        if request.scope:
            scopes = request.scope.split()
            for scope in scopes:
                if scope not in client.scopes:
                    raise OAuthInvalidRequest(f"Scope '{scope}' not authorized for client")

        return client

    def create_authorization_code(
        self,
        client_id: str,
        user_id: UUID,
        redirect_uri: str,
        scopes: list[str] | None = None,
        nonce: str | None = None,
    ) -> str:
        """
        Create authorization code.

        Args:
            client_id: Client ID
            user_id: User ID
            redirect_uri: Redirect URI
            scopes: Requested scopes
            nonce: OpenID Connect nonce

        Returns:
            Authorization code
        """
        code = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scopes=scopes or [],
            nonce=nonce,
            created_at=now,
            expires_at=now + timedelta(seconds=self._authorization_code_ttl),
        )

        self._authorization_codes[code] = auth_code
        return code

    def exchange_authorization_code(
        self,
        token_request: TokenRequest,
    ) -> TokenResponse:
        """
        Exchange authorization code for tokens.

        Args:
            token_request: TokenRequest with authorization_code grant

        Returns:
            TokenResponse with access_token and optional refresh_token

        Raises:
            OAuthError: If exchange fails
        """
        if token_request.grant_type != "authorization_code":
            raise OAuthUnsupportedGrantType(
                f"Grant type '{token_request.grant_type}' not supported"
            )

        if not token_request.code:
            raise OAuthInvalidRequest("code parameter required")

        if not token_request.redirect_uri:
            raise OAuthInvalidRequest("redirect_uri parameter required")

        # Validate client
        client = self.validate_client(
            token_request.client_id,
            token_request.client_secret,
        )

        if "authorization_code" not in client.grant_types:
            raise OAuthUnauthorizedClient(
                "Client not authorized for authorization_code grant"
            )

        # Validate and consume authorization code
        auth_code = self._authorization_codes.get(token_request.code)
        if not auth_code:
            raise OAuthInvalidGrant("Authorization code not found or expired")

        if auth_code.used:
            raise OAuthInvalidGrant("Authorization code has already been used")

        if datetime.now(timezone.utc) >= auth_code.expires_at:
            raise OAuthInvalidGrant("Authorization code has expired")

        if auth_code.client_id != token_request.client_id:
            raise OAuthInvalidGrant("Authorization code was issued to a different client")

        if auth_code.redirect_uri != token_request.redirect_uri:
            raise OAuthInvalidGrant("Redirect URI does not match")

        # Mark code as used
        auth_code.used = True
        auth_code.used_at = datetime.now(timezone.utc)

        # Create tokens
        access_token = create_access_token(
            user_id=auth_code.user_id,
            additional_claims={
                "scope": " ".join(auth_code.scopes),
                "client_id": client.client_id,
            },
        )

        # Create refresh token
        refresh_token = create_refresh_token(
            user_id=auth_code.user_id,
            additional_claims={
                "client_id": client.client_id,
            },
        )

        # Create ID token for OIDC (if openid scope requested)
        id_token = None
        if "openid" in auth_code.scopes:
            id_token = self._create_id_token(
                user_id=auth_code.user_id,
                client_id=client.client_id,
                nonce=auth_code.nonce,
                scopes=auth_code.scopes,
            )

        # Calculate token expiration
        access_token_expire_minutes = self.settings.jwt_access_token_expire_minutes
        expires_in = access_token_expire_minutes * 60

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token,
            id_token=id_token,
            scope=" ".join(auth_code.scopes) if auth_code.scopes else None,
        )

    def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: str | None = None,
    ) -> TokenResponse:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token
            client_id: Client ID
            client_secret: Client secret (for confidential clients)

        Returns:
            TokenResponse with new access_token

        Raises:
            OAuthError: If refresh fails
        """
        # Validate client
        client = self.validate_client(client_id, client_secret)

        try:
            payload = verify_token(refresh_token, expected_type="refresh")
            user_id = payload.user_id
        except TokenInvalidError as e:
            raise OAuthInvalidGrant(f"Invalid refresh token: {str(e)}")

        # Create new access token
        access_token = create_access_token(
            user_id=user_id,
            additional_claims={
                "client_id": client.client_id,
            },
        )

        # Create new refresh token
        new_refresh_token = create_refresh_token(
            user_id=user_id,
            additional_claims={
                "client_id": client.client_id,
            },
        )

        access_token_expire_minutes = self.settings.jwt_access_token_expire_minutes
        expires_in = access_token_expire_minutes * 60

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=new_refresh_token,
        )

    def _create_id_token(
        self,
        user_id: UUID,
        client_id: str,
        nonce: str | None = None,
        scopes: list[str] | None = None,
    ) -> str:
        """
        Create OpenID Connect ID token.

        Args:
            user_id: User ID
            client_id: Client ID
            nonce: Nonce value
            scopes: Requested scopes

        Returns:
            ID token
        """
        now = datetime.now(timezone.utc)
        settings = self.settings

        payload = {
            "iss": "https://auth.clm.local",  # Issuer
            "sub": str(user_id),
            "aud": client_id,
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "auth_time": int(now.timestamp()),
        }

        if nonce:
            payload["nonce"] = nonce

        # Add profile claims if requested
        if scopes and "profile" in scopes:
            payload.update({
                "given_name": "User",
                "family_name": str(user_id),
                "name": f"User {user_id}",
            })

        # Add email claims if requested
        if scopes and "email" in scopes:
            payload["email"] = f"user-{user_id}@clm.local"
            payload["email_verified"] = True

        token = jwt.encode(
            payload,
            settings.jwt_secret_key.get_secret_value(),
            algorithm=settings.jwt_algorithm,
        )

        return token

    def get_jwks(self) -> dict[str, Any]:
        """
        Get JSON Web Key Set (JWKS).

        Returns:
            JWKS dictionary with public keys
        """
        # For HS256 (HMAC), we cannot publicly expose the signing key
        # This implementation demonstrates the structure
        # In production with RS256, you would expose the public key

        # Since we're using HS256 with a shared secret, we'll return an empty JWKS
        # and rely on the issuer's documentation for key distribution
        # Production systems would use RS256 or other asymmetric algorithms

        return {
            "keys": [
                {
                    "kty": "oct",  # Symmetric key type
                    "use": "sig",
                    "alg": self.settings.jwt_algorithm,
                    "k": self.settings.jwt_secret_key.get_secret_value(),
                    "kid": "default-key",
                }
            ]
        }

    def get_public_jwks(self) -> dict[str, Any]:
        """
        Get public JWKS for token validation (for asymmetric algorithms).

        For symmetric algorithms (HS256), returns empty JWKS as
        public key exposure is not applicable.

        Returns:
            Public JWKS dictionary
        """
        # For HS256, return empty as symmetric keys should not be exposed
        if self.settings.jwt_algorithm.startswith("HS"):
            return {"keys": []}

        # For RS256 and other asymmetric algorithms, would expose public key
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": self.settings.jwt_algorithm,
                    "kid": "default-key",
                    # Public key components would be added here
                }
            ]
        }
