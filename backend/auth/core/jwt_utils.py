"""
JWT Token Utilities.

This module provides pure Python utilities for JWT token creation, verification,
and expiration handling. It does not include any FastAPI-specific code or OAuth/OIDC logic.

Main functions:
- create_access_token: Generate JWT access tokens with custom claims
- create_refresh_token: Generate JWT refresh tokens with custom claims
- verify_token: Verify and decode JWT tokens
- decode_token: Decode token without verification (for inspection)
- get_token_expiration: Extract expiration timestamp from token
- is_token_expired: Check if token is expired

Token Types:
- access: Short-lived tokens for API access (default: 60 minutes)
- refresh: Long-lived tokens for obtaining new access tokens (default: 7 days)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import jwt
from pydantic import BaseModel, Field, field_validator

from backend.common.config import get_settings


class TokenPayload(BaseModel):
    """JWT token payload model with standard claims."""

    sub: str = Field(..., description="Subject (typically user ID)")
    exp: int = Field(..., description="Expiration timestamp (Unix time)")
    iat: int = Field(..., description="Issued at timestamp (Unix time)")
    type: str = Field(..., description="Token type (access or refresh)")
    jti: str | None = Field(default=None, description="JWT ID (unique token identifier)")

    @field_validator("type")
    @classmethod
    def validate_token_type(cls, v: str) -> str:
        if v not in ("access", "refresh"):
            raise ValueError("Token type must be 'access' or 'refresh'")
        return v

    @property
    def user_id(self) -> UUID:
        """Get user ID as UUID from subject claim."""
        return UUID(self.sub)

    @property
    def expires_at(self) -> datetime:
        """Get expiration datetime in UTC."""
        return datetime.fromtimestamp(self.exp, tz=timezone.utc)

    @property
    def issued_at(self) -> datetime:
        """Get issued at datetime in UTC."""
        return datetime.fromtimestamp(self.iat, tz=timezone.utc)

    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(timezone.utc) >= self.expires_at


class JWTError(Exception):
    """Base exception for JWT-related errors."""

    pass


class TokenExpiredError(JWTError):
    """Raised when a token has expired."""

    pass


class TokenInvalidError(JWTError):
    """Raised when a token is invalid."""

    pass


def create_access_token(
    user_id: UUID,
    additional_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        user_id: User ID to include in token subject
        additional_claims: Optional additional claims to include in token
        expires_delta: Optional custom expiration time delta. If not provided,
                      uses configured default (jwt_access_token_expire_minutes)

    Returns:
        str: Encoded JWT access token

    Example:
        >>> from uuid import uuid4
        >>> user_id = uuid4()
        >>> token = create_access_token(user_id)
        >>> # Token with custom expiration
        >>> token = create_access_token(user_id, expires_delta=timedelta(hours=2))
        >>> # Token with additional claims
        >>> token = create_access_token(
        ...     user_id,
        ...     additional_claims={"role": "admin", "org_id": "123"}
        ... )
    """
    settings = get_settings()

    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)

    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    claims = {
        "sub": str(user_id),
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "type": "access",
    }

    if additional_claims:
        claims.update(additional_claims)

    token = jwt.encode(
        claims,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )

    return token


def create_refresh_token(
    user_id: UUID,
    additional_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT refresh token.

    Args:
        user_id: User ID to include in token subject
        additional_claims: Optional additional claims to include in token
        expires_delta: Optional custom expiration time delta. If not provided,
                      uses configured default (jwt_refresh_token_expire_days)

    Returns:
        str: Encoded JWT refresh token

    Example:
        >>> from uuid import uuid4
        >>> user_id = uuid4()
        >>> token = create_refresh_token(user_id)
        >>> # Token with custom expiration
        >>> token = create_refresh_token(user_id, expires_delta=timedelta(days=30))
    """
    settings = get_settings()

    if expires_delta is None:
        expires_delta = timedelta(days=settings.jwt_refresh_token_expire_days)

    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    claims = {
        "sub": str(user_id),
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "type": "refresh",
    }

    if additional_claims:
        claims.update(additional_claims)

    token = jwt.encode(
        claims,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )

    return token


def verify_token(token: str, expected_type: str = "access") -> TokenPayload:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token string to verify
        expected_type: Expected token type ('access' or 'refresh')

    Returns:
        TokenPayload: Decoded and validated token payload

    Raises:
        TokenExpiredError: If token has expired
        TokenInvalidError: If token is invalid or type doesn't match

    Example:
        >>> token = create_access_token(user_id)
        >>> payload = verify_token(token, expected_type="access")
        >>> print(payload.user_id)
        >>> print(payload.expires_at)
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError as e:
        raise TokenExpiredError("Token has expired") from e
    except jwt.InvalidTokenError as e:
        raise TokenInvalidError(f"Invalid token: {str(e)}") from e

    try:
        token_payload = TokenPayload(**payload)
    except Exception as e:
        raise TokenInvalidError(f"Invalid token payload: {str(e)}") from e

    if token_payload.type != expected_type:
        raise TokenInvalidError(
            f"Invalid token type. Expected '{expected_type}', got '{token_payload.type}'"
        )

    return token_payload


def decode_token(token: str, verify: bool = False) -> dict[str, Any]:
    """
    Decode a JWT token without full verification (useful for inspection).

    Args:
        token: JWT token string to decode
        verify: If True, verify signature and expiration. If False, only decode.

    Returns:
        dict: Decoded token payload

    Raises:
        TokenInvalidError: If token cannot be decoded

    Example:
        >>> token = create_access_token(user_id)
        >>> # Decode without verification (for inspection)
        >>> payload = decode_token(token, verify=False)
        >>> # Decode with verification
        >>> payload = decode_token(token, verify=True)
    """
    settings = get_settings()

    try:
        if verify:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key.get_secret_value(),
                algorithms=[settings.jwt_algorithm],
            )
        else:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
                algorithms=[settings.jwt_algorithm],
            )
        return payload
    except jwt.InvalidTokenError as e:
        raise TokenInvalidError(f"Cannot decode token: {str(e)}") from e


def get_token_expiration(token: str) -> datetime:
    """
    Extract expiration timestamp from token without full verification.

    Args:
        token: JWT token string

    Returns:
        datetime: Expiration timestamp in UTC

    Raises:
        TokenInvalidError: If token cannot be decoded or has no expiration

    Example:
        >>> token = create_access_token(user_id)
        >>> expiration = get_token_expiration(token)
        >>> print(f"Token expires at: {expiration}")
    """
    payload = decode_token(token, verify=False)

    if "exp" not in payload:
        raise TokenInvalidError("Token has no expiration claim")

    return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)


def is_token_expired(token: str) -> bool:
    """
    Check if a token is expired without full verification.

    Args:
        token: JWT token string

    Returns:
        bool: True if token is expired, False otherwise

    Raises:
        TokenInvalidError: If token cannot be decoded

    Example:
        >>> token = create_access_token(user_id)
        >>> if is_token_expired(token):
        ...     print("Token has expired")
        ... else:
        ...     print("Token is still valid")
    """
    try:
        expiration = get_token_expiration(token)
        return datetime.now(timezone.utc) >= expiration
    except TokenInvalidError:
        return True
