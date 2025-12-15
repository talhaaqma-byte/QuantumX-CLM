"""
FastAPI dependencies for JWT authentication.

This module provides FastAPI dependency functions to extract and validate
user identity from JWT tokens in HTTP requests.

Main dependencies:
- get_token_from_header: Extract Bearer token from Authorization header
- get_current_user: Validate token and return user context (access tokens only)
- get_current_user_refresh: Validate token and return user context (refresh tokens only)
- get_optional_user: Same as get_current_user but returns None if no token provided

Usage Examples:
    Basic authentication requirement:
        ```python
        from fastapi import APIRouter, Depends
        from backend.auth.deps import get_current_user, UserContext
        
        router = APIRouter()
        
        @router.get("/protected")
        async def protected_endpoint(
            user: UserContext = Depends(get_current_user)
        ):
            return {
                "message": f"Hello {user.user_id}",
                "user_id": str(user.user_id),
                "token_issued_at": user.issued_at.isoformat()
            }
        ```
    
    Optional authentication:
        ```python
        @router.get("/public-or-private")
        async def flexible_endpoint(
            user: UserContext | None = Depends(get_optional_user)
        ):
            if user:
                return {"message": f"Hello authenticated user {user.user_id}"}
            else:
                return {"message": "Hello anonymous user"}
        ```
    
    Refresh token validation:
        ```python
        @router.post("/refresh")
        async def refresh_token_endpoint(
            user: UserContext = Depends(get_current_user_refresh)
        ):
            # This will only accept valid refresh tokens
            new_access_token = create_access_token(user.user_id)
            return {"access_token": new_access_token}
        ```
    
    Access additional token claims:
        ```python
        @router.get("/admin-only")
        async def admin_endpoint(
            user: UserContext = Depends(get_current_user)
        ):
            # Access custom claims from the token
            role = user.claims.get("role", "user")
            org_id = user.claims.get("org_id")
            
            return {
                "user_id": str(user.user_id),
                "role": role,
                "org_id": org_id
            }
        ```
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from backend.auth.core.jwt_utils import (
    TokenExpiredError,
    TokenInvalidError,
    TokenPayload,
    decode_token,
    verify_token,
)

security = HTTPBearer(auto_error=False)


class UserContext(BaseModel):
    """
    User context extracted from JWT token.
    
    This model provides easy access to user identity and token metadata
    without exposing the raw token payload.
    """

    user_id: UUID
    token_type: str
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any]

    @classmethod
    def from_token_payload(cls, payload: TokenPayload, raw_payload: dict[str, Any]) -> UserContext:
        """
        Create UserContext from TokenPayload and raw decoded payload.
        
        Args:
            payload: Validated TokenPayload with standard JWT claims
            raw_payload: Raw decoded JWT payload dictionary containing all claims
        
        Returns:
            UserContext with user identity and custom claims
        """
        standard_claims = {"sub", "exp", "iat", "type", "jti"}
        custom_claims = {
            key: value 
            for key, value in raw_payload.items() 
            if key not in standard_claims
        }
        
        return cls(
            user_id=payload.user_id,
            token_type=payload.type,
            issued_at=payload.issued_at,
            expires_at=payload.expires_at,
            claims=custom_claims,
        )


async def get_token_from_header(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> str:
    """
    Extract JWT token from Authorization header.
    
    Expects header format: "Authorization: Bearer <token>"
    
    Args:
        credentials: HTTP Bearer credentials from security scheme
        
    Returns:
        str: JWT token string
        
    Raises:
        HTTPException: 401 if no token provided or invalid format
        
    Example:
        ```python
        @router.get("/test")
        async def test(token: str = Depends(get_token_from_header)):
            # token is the raw JWT string
            return {"token_length": len(token)}
        ```
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return credentials.credentials


async def get_current_user(
    token: str = Depends(get_token_from_header),
) -> UserContext:
    """
    Validate JWT access token and return user context.
    
    This dependency:
    1. Extracts token from Authorization header
    2. Verifies token signature and expiration
    3. Ensures token is an access token
    4. Returns user context with identity and metadata
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        UserContext: User identity and token metadata
        
    Raises:
        HTTPException: 401 if token is invalid, expired, or wrong type
        
    Example:
        ```python
        @router.get("/me")
        async def get_profile(user: UserContext = Depends(get_current_user)):
            return {
                "user_id": str(user.user_id),
                "issued_at": user.issued_at.isoformat(),
                "expires_at": user.expires_at.isoformat()
            }
        ```
    """
    try:
        payload = verify_token(token, expected_type="access")
        raw_payload = decode_token(token, verify=False)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return UserContext.from_token_payload(payload, raw_payload)


async def get_current_user_refresh(
    token: str = Depends(get_token_from_header),
) -> UserContext:
    """
    Validate JWT refresh token and return user context.
    
    Use this dependency for endpoints that require refresh tokens
    (e.g., token refresh endpoints).
    
    This dependency:
    1. Extracts token from Authorization header
    2. Verifies token signature and expiration
    3. Ensures token is a refresh token
    4. Returns user context with identity and metadata
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        UserContext: User identity and token metadata
        
    Raises:
        HTTPException: 401 if token is invalid, expired, or wrong type
        
    Example:
        ```python
        @router.post("/refresh")
        async def refresh_tokens(
            user: UserContext = Depends(get_current_user_refresh)
        ):
            # This will only accept valid refresh tokens
            new_access = create_access_token(user.user_id)
            new_refresh = create_refresh_token(user.user_id)
            return {"access_token": new_access, "refresh_token": new_refresh}
        ```
    """
    try:
        payload = verify_token(token, expected_type="refresh")
        raw_payload = decode_token(token, verify=False)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return UserContext.from_token_payload(payload, raw_payload)


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> UserContext | None:
    """
    Optionally validate JWT access token and return user context.
    
    Similar to get_current_user but returns None instead of raising
    an exception if no token is provided. Still raises exceptions if
    a token is provided but is invalid.
    
    Use this for endpoints that work for both authenticated and
    unauthenticated users.
    
    Args:
        credentials: HTTP Bearer credentials from security scheme
        
    Returns:
        UserContext | None: User context if token provided and valid, None otherwise
        
    Raises:
        HTTPException: 401 if token is provided but invalid or expired
        
    Example:
        ```python
        @router.get("/content")
        async def get_content(
            user: UserContext | None = Depends(get_optional_user)
        ):
            if user:
                # Return personalized content
                return {"message": f"Content for user {user.user_id}"}
            else:
                # Return public content
                return {"message": "Public content"}
        ```
    """
    if credentials is None:
        return None
    
    token = credentials.credentials
    
    try:
        payload = verify_token(token, expected_type="access")
        raw_payload = decode_token(token, verify=False)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return UserContext.from_token_payload(payload, raw_payload)
