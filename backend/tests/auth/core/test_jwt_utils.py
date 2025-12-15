"""
Unit tests for JWT token utilities.

Tests cover:
- Token creation (access and refresh)
- Token verification and validation
- Expiration handling
- Error cases and edge conditions
- Custom claims and expiration deltas
"""

from datetime import datetime, timedelta, timezone
from time import sleep
from uuid import UUID, uuid4

import jwt
import pytest

from backend.auth.core.jwt_utils import (
    JWTError,
    TokenExpiredError,
    TokenInvalidError,
    TokenPayload,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_expiration,
    is_token_expired,
    verify_token,
)
from backend.common.config import get_settings


class TestTokenCreation:
    """Tests for token creation functions."""

    def test_create_access_token_basic(self):
        """Test basic access token creation."""
        user_id = uuid4()
        token = create_access_token(user_id)

        assert isinstance(token, str)
        assert len(token) > 0

        payload = decode_token(token, verify=False)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload

    def test_create_refresh_token_basic(self):
        """Test basic refresh token creation."""
        user_id = uuid4()
        token = create_refresh_token(user_id)

        assert isinstance(token, str)
        assert len(token) > 0

        payload = decode_token(token, verify=False)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"
        assert "exp" in payload
        assert "iat" in payload

    def test_create_token_with_additional_claims(self):
        """Test token creation with additional custom claims."""
        user_id = uuid4()
        additional_claims = {
            "role": "admin",
            "org_id": "org-123",
            "permissions": ["read", "write"],
        }

        token = create_access_token(user_id, additional_claims=additional_claims)
        payload = decode_token(token, verify=False)

        assert payload["role"] == "admin"
        assert payload["org_id"] == "org-123"
        assert payload["permissions"] == ["read", "write"]

    def test_create_token_with_custom_expiration(self):
        """Test token creation with custom expiration delta."""
        user_id = uuid4()
        custom_delta = timedelta(hours=2)

        token = create_access_token(user_id, expires_delta=custom_delta)
        payload = decode_token(token, verify=False)

        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat_time = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        actual_delta = exp_time - iat_time

        assert abs(actual_delta.total_seconds() - custom_delta.total_seconds()) < 2

    def test_create_token_default_expiration(self):
        """Test that tokens use configured default expiration times."""
        settings = get_settings()
        user_id = uuid4()

        access_token = create_access_token(user_id)
        access_payload = decode_token(access_token, verify=False)
        access_exp = datetime.fromtimestamp(access_payload["exp"], tz=timezone.utc)
        access_iat = datetime.fromtimestamp(access_payload["iat"], tz=timezone.utc)
        access_delta = access_exp - access_iat

        expected_minutes = settings.jwt_access_token_expire_minutes
        assert abs(access_delta.total_seconds() - (expected_minutes * 60)) < 2

        refresh_token = create_refresh_token(user_id)
        refresh_payload = decode_token(refresh_token, verify=False)
        refresh_exp = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)
        refresh_iat = datetime.fromtimestamp(refresh_payload["iat"], tz=timezone.utc)
        refresh_delta = refresh_exp - refresh_iat

        expected_days = settings.jwt_refresh_token_expire_days
        assert abs(refresh_delta.total_seconds() - (expected_days * 86400)) < 2


class TestTokenVerification:
    """Tests for token verification and validation."""

    def test_verify_valid_access_token(self):
        """Test verification of valid access token."""
        user_id = uuid4()
        token = create_access_token(user_id)

        payload = verify_token(token, expected_type="access")

        assert isinstance(payload, TokenPayload)
        assert payload.user_id == user_id
        assert payload.type == "access"
        assert not payload.is_expired()

    def test_verify_valid_refresh_token(self):
        """Test verification of valid refresh token."""
        user_id = uuid4()
        token = create_refresh_token(user_id)

        payload = verify_token(token, expected_type="refresh")

        assert isinstance(payload, TokenPayload)
        assert payload.user_id == user_id
        assert payload.type == "refresh"
        assert not payload.is_expired()

    def test_verify_token_wrong_type(self):
        """Test that verification fails when token type doesn't match expected."""
        user_id = uuid4()
        access_token = create_access_token(user_id)

        with pytest.raises(TokenInvalidError) as exc_info:
            verify_token(access_token, expected_type="refresh")

        assert "Invalid token type" in str(exc_info.value)
        assert "Expected 'refresh'" in str(exc_info.value)
        assert "got 'access'" in str(exc_info.value)

    def test_verify_expired_token(self):
        """Test that verification fails for expired tokens."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=1))

        sleep(2)

        with pytest.raises(TokenExpiredError) as exc_info:
            verify_token(token, expected_type="access")

        assert "expired" in str(exc_info.value).lower()

    def test_verify_invalid_signature(self):
        """Test that verification fails for tokens with invalid signature."""
        user_id = uuid4()
        token = create_access_token(user_id)

        token_parts = token.split(".")
        tampered_token = ".".join([token_parts[0], token_parts[1], "invalid_signature"])

        with pytest.raises(TokenInvalidError) as exc_info:
            verify_token(tampered_token, expected_type="access")

        assert "Invalid token" in str(exc_info.value)

    def test_verify_malformed_token(self):
        """Test that verification fails for malformed tokens."""
        malformed_tokens = [
            "not.a.jwt",
            "invalid",
            "",
            "only.two.parts",
        ]

        for bad_token in malformed_tokens:
            with pytest.raises(TokenInvalidError):
                verify_token(bad_token, expected_type="access")

    def test_verify_token_missing_required_claims(self):
        """Test that verification fails when required claims are missing."""
        settings = get_settings()

        payload = {"sub": str(uuid4())}

        token = jwt.encode(
            payload,
            settings.jwt_secret_key.get_secret_value(),
            algorithm=settings.jwt_algorithm,
        )

        with pytest.raises(TokenInvalidError):
            verify_token(token, expected_type="access")


class TestTokenDecoding:
    """Tests for token decoding functions."""

    def test_decode_token_without_verification(self):
        """Test decoding token without verification."""
        user_id = uuid4()
        token = create_access_token(user_id)

        payload = decode_token(token, verify=False)

        assert isinstance(payload, dict)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"

    def test_decode_token_with_verification(self):
        """Test decoding token with verification enabled."""
        user_id = uuid4()
        token = create_access_token(user_id)

        payload = decode_token(token, verify=True)

        assert isinstance(payload, dict)
        assert payload["sub"] == str(user_id)

    def test_decode_expired_token_without_verification(self):
        """Test that expired tokens can be decoded without verification."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=1))

        sleep(2)

        payload = decode_token(token, verify=False)

        assert payload["sub"] == str(user_id)

    def test_decode_expired_token_with_verification(self):
        """Test that expired tokens fail verification when verify=True."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=1))

        sleep(2)

        with pytest.raises(TokenInvalidError):
            decode_token(token, verify=True)

    def test_decode_invalid_token(self):
        """Test that invalid tokens raise error even without verification."""
        with pytest.raises(TokenInvalidError):
            decode_token("completely.invalid.token", verify=False)


class TestExpirationHandling:
    """Tests for token expiration handling."""

    def test_get_token_expiration(self):
        """Test getting expiration timestamp from token."""
        user_id = uuid4()
        expires_delta = timedelta(hours=1)
        token = create_access_token(user_id, expires_delta=expires_delta)

        expiration = get_token_expiration(token)

        assert isinstance(expiration, datetime)
        assert expiration.tzinfo == timezone.utc

        now = datetime.now(timezone.utc)
        time_until_expiry = expiration - now
        assert timedelta(minutes=59) < time_until_expiry < timedelta(minutes=61)

    def test_get_token_expiration_invalid_token(self):
        """Test that getting expiration from invalid token raises error."""
        with pytest.raises(TokenInvalidError):
            get_token_expiration("invalid.token.here")

    def test_is_token_expired_for_valid_token(self):
        """Test expiration check for valid, non-expired token."""
        user_id = uuid4()
        token = create_access_token(user_id)

        assert not is_token_expired(token)

    def test_is_token_expired_for_expired_token(self):
        """Test expiration check for expired token."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=1))

        sleep(2)

        assert is_token_expired(token)

    def test_is_token_expired_for_invalid_token(self):
        """Test that invalid tokens are considered expired."""
        assert is_token_expired("invalid.token.here")

    def test_token_expiration_edge_case(self):
        """Test token expiration at exact boundary."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=2))

        assert not is_token_expired(token)

        sleep(1)
        assert not is_token_expired(token)

        sleep(2)
        assert is_token_expired(token)


class TestTokenPayload:
    """Tests for TokenPayload model."""

    def test_token_payload_creation(self):
        """Test TokenPayload creation from valid data."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        payload = TokenPayload(
            sub=str(user_id),
            exp=int((now + timedelta(hours=1)).timestamp()),
            iat=int(now.timestamp()),
            type="access",
        )

        assert payload.user_id == user_id
        assert payload.type == "access"
        assert isinstance(payload.expires_at, datetime)
        assert isinstance(payload.issued_at, datetime)

    def test_token_payload_invalid_type(self):
        """Test that TokenPayload validates token type."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        with pytest.raises(ValueError) as exc_info:
            TokenPayload(
                sub=str(user_id),
                exp=int((now + timedelta(hours=1)).timestamp()),
                iat=int(now.timestamp()),
                type="invalid_type",
            )

        assert "Token type must be" in str(exc_info.value)

    def test_token_payload_properties(self):
        """Test TokenPayload properties work correctly."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        exp_time = now + timedelta(hours=1)

        payload = TokenPayload(
            sub=str(user_id),
            exp=int(exp_time.timestamp()),
            iat=int(now.timestamp()),
            type="access",
            jti="token-123",
        )

        assert payload.user_id == user_id
        assert payload.jti == "token-123"

        assert abs((payload.expires_at - exp_time).total_seconds()) < 1
        assert abs((payload.issued_at - now).total_seconds()) < 1

    def test_token_payload_is_expired(self):
        """Test TokenPayload.is_expired() method."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        future_payload = TokenPayload(
            sub=str(user_id),
            exp=int((now + timedelta(hours=1)).timestamp()),
            iat=int(now.timestamp()),
            type="access",
        )
        assert not future_payload.is_expired()

        past_payload = TokenPayload(
            sub=str(user_id),
            exp=int((now - timedelta(hours=1)).timestamp()),
            iat=int((now - timedelta(hours=2)).timestamp()),
            type="access",
        )
        assert past_payload.is_expired()


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_token_with_zero_expiration(self):
        """Test creating token with zero expiration time."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=0))

        assert is_token_expired(token)

    def test_token_with_negative_expiration(self):
        """Test creating token with negative expiration (already expired)."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(seconds=-1))

        assert is_token_expired(token)

        with pytest.raises(TokenExpiredError):
            verify_token(token, expected_type="access")

    def test_token_with_very_long_expiration(self):
        """Test creating token with very long expiration time."""
        user_id = uuid4()
        token = create_access_token(user_id, expires_delta=timedelta(days=365))

        payload = verify_token(token, expected_type="access")
        assert not payload.is_expired()

        expiration = get_token_expiration(token)
        now = datetime.now(timezone.utc)
        time_until_expiry = expiration - now

        assert timedelta(days=364) < time_until_expiry < timedelta(days=366)

    def test_token_with_special_characters_in_claims(self):
        """Test token with special characters in additional claims."""
        user_id = uuid4()
        additional_claims = {
            "email": "user@example.com",
            "name": "John O'Brien",
            "org": "Acme Corp & Co.",
        }

        token = create_access_token(user_id, additional_claims=additional_claims)
        payload = verify_token(token, expected_type="access")

        decoded = decode_token(token, verify=False)
        assert decoded["email"] == additional_claims["email"]
        assert decoded["name"] == additional_claims["name"]
        assert decoded["org"] == additional_claims["org"]

    def test_multiple_tokens_for_same_user(self):
        """Test that multiple tokens can be created for the same user."""
        user_id = uuid4()

        token1 = create_access_token(user_id, additional_claims={"jti": str(uuid4())})
        token2 = create_access_token(user_id, additional_claims={"jti": str(uuid4())})
        token3 = create_access_token(user_id, additional_claims={"jti": str(uuid4())})

        assert token1 != token2
        assert token2 != token3
        assert token1 != token3

        payload1 = verify_token(token1, expected_type="access")
        payload2 = verify_token(token2, expected_type="access")
        payload3 = verify_token(token3, expected_type="access")

        assert payload1.user_id == user_id
        assert payload2.user_id == user_id
        assert payload3.user_id == user_id


class TestIntegration:
    """Integration tests combining multiple JWT operations."""

    def test_full_token_lifecycle(self):
        """Test complete token lifecycle: create, verify, check expiration."""
        user_id = uuid4()

        token = create_access_token(
            user_id,
            additional_claims={"role": "admin"},
            expires_delta=timedelta(minutes=5),
        )

        assert not is_token_expired(token)

        payload = verify_token(token, expected_type="access")
        assert payload.user_id == user_id
        assert not payload.is_expired()

        decoded = decode_token(token, verify=False)
        assert decoded["role"] == "admin"

        expiration = get_token_expiration(token)
        assert expiration > datetime.now(timezone.utc)

    def test_access_and_refresh_token_pair(self):
        """Test creating and using both access and refresh tokens."""
        user_id = uuid4()

        access_token = create_access_token(user_id)
        refresh_token = create_refresh_token(user_id)

        access_payload = verify_token(access_token, expected_type="access")
        refresh_payload = verify_token(refresh_token, expected_type="refresh")

        assert access_payload.user_id == user_id
        assert refresh_payload.user_id == user_id
        assert access_payload.type == "access"
        assert refresh_payload.type == "refresh"

        with pytest.raises(TokenInvalidError):
            verify_token(access_token, expected_type="refresh")

        with pytest.raises(TokenInvalidError):
            verify_token(refresh_token, expected_type="access")

    def test_token_refresh_scenario(self):
        """Test typical token refresh scenario."""
        user_id = uuid4()

        old_access_token = create_access_token(
            user_id, expires_delta=timedelta(seconds=1)
        )
        refresh_token = create_refresh_token(user_id)

        sleep(2)

        assert is_token_expired(old_access_token)
        assert not is_token_expired(refresh_token)

        refresh_payload = verify_token(refresh_token, expected_type="refresh")
        new_access_token = create_access_token(refresh_payload.user_id)

        new_payload = verify_token(new_access_token, expected_type="access")
        assert new_payload.user_id == user_id
        assert not new_payload.is_expired()
