"""
Tests for JWT authentication dependencies.

Tests the FastAPI dependency functions that extract and validate
user identity from JWT tokens.
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from backend.auth.core.jwt_utils import create_access_token, create_refresh_token
from backend.auth.deps import (
    UserContext,
    get_current_user,
    get_current_user_refresh,
    get_optional_user,
    get_token_from_header,
)


class TestGetTokenFromHeader:
    """Tests for get_token_from_header dependency."""

    @pytest.mark.asyncio
    async def test_extract_valid_token(self):
        """Test extracting valid token from credentials."""
        test_token = "test.jwt.token"
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=test_token
        )
        
        result = await get_token_from_header(credentials)
        
        assert result == test_token

    @pytest.mark.asyncio
    async def test_no_credentials_provided(self):
        """Test that missing credentials raise 401."""
        with pytest.raises(HTTPException) as exc_info:
            await get_token_from_header(None)
        
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Not authenticated"
        assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


class TestUserContext:
    """Tests for UserContext model."""

    def test_from_token_payload(self):
        """Test creating UserContext from TokenPayload."""
        from backend.auth.core.jwt_utils import decode_token, verify_token
        
        user_id = uuid4()
        token = create_access_token(
            user_id,
            additional_claims={
                "username": "testuser",
                "org_id": "org123",
            }
        )
        
        payload = verify_token(token)
        raw_payload = decode_token(token, verify=False)
        context = UserContext.from_token_payload(payload, raw_payload)
        
        assert context.user_id == user_id
        assert context.token_type == "access"
        assert "username" in context.claims
        assert context.claims["username"] == "testuser"
        assert context.claims["org_id"] == "org123"

    def test_user_context_attributes(self):
        """Test UserContext has all expected attributes."""
        user_id = uuid4()
        token = create_access_token(user_id)
        
        from backend.auth.core.jwt_utils import decode_token, verify_token
        payload = verify_token(token)
        raw_payload = decode_token(token, verify=False)
        context = UserContext.from_token_payload(payload, raw_payload)
        
        assert hasattr(context, "user_id")
        assert hasattr(context, "token_type")
        assert hasattr(context, "issued_at")
        assert hasattr(context, "expires_at")
        assert hasattr(context, "claims")
        
        assert context.user_id == user_id
        assert context.token_type == "access"


class TestGetCurrentUser:
    """Tests for get_current_user dependency."""

    @pytest.mark.asyncio
    async def test_valid_access_token(self):
        """Test with valid access token."""
        user_id = uuid4()
        token = create_access_token(user_id)
        
        user = await get_current_user(token)
        
        assert isinstance(user, UserContext)
        assert user.user_id == user_id
        assert user.token_type == "access"

    @pytest.mark.asyncio
    async def test_valid_token_with_custom_claims(self):
        """Test that custom claims are accessible."""
        user_id = uuid4()
        token = create_access_token(
            user_id,
            additional_claims={
                "role": "admin",
                "org_id": "org123",
                "permissions": ["read", "write"],
            }
        )
        
        user = await get_current_user(token)
        
        assert user.user_id == user_id
        assert user.claims["role"] == "admin"
        assert user.claims["org_id"] == "org123"
        assert user.claims["permissions"] == ["read", "write"]

    @pytest.mark.asyncio
    async def test_expired_access_token(self):
        """Test with expired access token."""
        user_id = uuid4()
        token = create_access_token(
            user_id,
            expires_delta=timedelta(seconds=-1)
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token)
        
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_invalid_token_format(self):
        """Test with invalid token format."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user("not.a.valid.token")
        
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_token_rejected(self):
        """Test that refresh token is rejected for access endpoint."""
        user_id = uuid4()
        refresh_token = create_refresh_token(user_id)
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(refresh_token)
        
        assert exc_info.value.status_code == 401
        assert "type" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_malformed_token(self):
        """Test with malformed token."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user("malformed_token")
        
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_token(self):
        """Test with empty token."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user("")
        
        assert exc_info.value.status_code == 401


class TestGetCurrentUserRefresh:
    """Tests for get_current_user_refresh dependency."""

    @pytest.mark.asyncio
    async def test_valid_refresh_token(self):
        """Test with valid refresh token."""
        user_id = uuid4()
        token = create_refresh_token(user_id)
        
        user = await get_current_user_refresh(token)
        
        assert isinstance(user, UserContext)
        assert user.user_id == user_id
        assert user.token_type == "refresh"

    @pytest.mark.asyncio
    async def test_access_token_rejected(self):
        """Test that access token is rejected for refresh endpoint."""
        user_id = uuid4()
        access_token = create_access_token(user_id)
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_refresh(access_token)
        
        assert exc_info.value.status_code == 401
        assert "type" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_expired_refresh_token(self):
        """Test with expired refresh token."""
        user_id = uuid4()
        token = create_refresh_token(
            user_id,
            expires_delta=timedelta(seconds=-1)
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_refresh(token)
        
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_invalid_refresh_token(self):
        """Test with invalid refresh token."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_refresh("invalid.token.here")
        
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_token_with_custom_claims(self):
        """Test refresh token with custom claims."""
        user_id = uuid4()
        token = create_refresh_token(
            user_id,
            additional_claims={"session_id": "sess123"}
        )
        
        user = await get_current_user_refresh(token)
        
        assert user.user_id == user_id
        assert user.claims["session_id"] == "sess123"


class TestGetOptionalUser:
    """Tests for get_optional_user dependency."""

    @pytest.mark.asyncio
    async def test_valid_token_provided(self):
        """Test with valid token provided."""
        user_id = uuid4()
        token = create_access_token(user_id)
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        user = await get_optional_user(credentials)
        
        assert user is not None
        assert isinstance(user, UserContext)
        assert user.user_id == user_id

    @pytest.mark.asyncio
    async def test_no_token_provided(self):
        """Test with no token provided (should return None)."""
        user = await get_optional_user(None)
        
        assert user is None

    @pytest.mark.asyncio
    async def test_invalid_token_provided(self):
        """Test that invalid token still raises exception."""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="invalid.token.here"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_optional_user(credentials)
        
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_token_provided(self):
        """Test that expired token raises exception."""
        user_id = uuid4()
        token = create_access_token(
            user_id,
            expires_delta=timedelta(seconds=-1)
        )
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_optional_user(credentials)
        
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_refresh_token_rejected(self):
        """Test that refresh token is rejected."""
        user_id = uuid4()
        token = create_refresh_token(user_id)
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_optional_user(credentials)
        
        assert exc_info.value.status_code == 401


class TestIntegration:
    """Integration tests for dependencies."""

    @pytest.mark.asyncio
    async def test_full_flow_access_token(self):
        """Test full flow: create token, extract, validate."""
        user_id = uuid4()
        
        token = create_access_token(
            user_id,
            additional_claims={"username": "testuser"}
        )
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        extracted_token = await get_token_from_header(credentials)
        assert extracted_token == token
        
        user = await get_current_user(extracted_token)
        assert user.user_id == user_id
        assert user.claims["username"] == "testuser"

    @pytest.mark.asyncio
    async def test_full_flow_refresh_token(self):
        """Test full flow with refresh token."""
        user_id = uuid4()
        
        token = create_refresh_token(user_id)
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        extracted_token = await get_token_from_header(credentials)
        user = await get_current_user_refresh(extracted_token)
        
        assert user.user_id == user_id
        assert user.token_type == "refresh"

    @pytest.mark.asyncio
    async def test_multiple_custom_claims(self):
        """Test handling multiple custom claims."""
        user_id = uuid4()
        claims = {
            "username": "testuser",
            "email": "test@example.com",
            "org_id": "org123",
            "role": "admin",
            "permissions": ["read", "write", "delete"],
            "metadata": {"created": "2024-01-01"},
        }
        
        token = create_access_token(user_id, additional_claims=claims)
        user = await get_current_user(token)
        
        assert user.user_id == user_id
        for key, value in claims.items():
            assert user.claims[key] == value

    @pytest.mark.asyncio
    async def test_token_metadata_accessible(self):
        """Test that token metadata is accessible."""
        user_id = uuid4()
        token = create_access_token(user_id)
        user = await get_current_user(token)
        
        assert user.issued_at is not None
        assert user.expires_at is not None
        assert user.expires_at > user.issued_at
