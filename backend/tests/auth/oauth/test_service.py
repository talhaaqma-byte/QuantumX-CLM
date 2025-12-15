"""
Tests for OAuth2/OIDC service.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.auth.oauth.models import (
    AuthorizationRequest,
    TokenRequest,
)
from backend.auth.oauth.service import (
    OAuthInvalidClient,
    OAuthInvalidGrant,
    OAuthInvalidRequest,
    OAuthService,
    OAuthUnauthorizedClient,
    OAuthUnsupportedGrantType,
)


@pytest.fixture
def oauth_service():
    """Create OAuth service instance."""
    return OAuthService()


@pytest.fixture
def test_user_id():
    """Create test user ID."""
    return uuid4()


@pytest.fixture
def test_client(oauth_service, test_user_id):
    """Register test OAuth client."""
    client, secret = oauth_service.register_client(
        client_id="test-client",
        client_name="Test Client",
        owner_user_id=test_user_id,
        redirect_uris=["https://localhost:3000/callback"],
        scopes=["openid", "profile", "email"],
        grant_types=["authorization_code", "refresh_token"],
    )
    return client, secret


class TestClientRegistration:
    """Tests for OAuth client registration."""

    def test_register_client(self, oauth_service, test_user_id):
        """Test registering a new OAuth client."""
        client, secret = oauth_service.register_client(
            client_id="my-app",
            client_name="My App",
            owner_user_id=test_user_id,
            redirect_uris=["https://myapp.com/callback"],
        )

        assert client.client_id == "my-app"
        assert client.client_name == "My App"
        assert client.owner_user_id == test_user_id
        assert client.redirect_uris == ["https://myapp.com/callback"]
        assert client.is_confidential is True
        assert client.is_active is True
        assert len(secret) > 20

    def test_register_client_duplicate_id(self, oauth_service, test_user_id):
        """Test registering duplicate client ID fails."""
        oauth_service.register_client(
            client_id="duplicate",
            client_name="First",
            owner_user_id=test_user_id,
            redirect_uris=["https://first.com/callback"],
        )

        with pytest.raises(OAuthInvalidClient):
            oauth_service.register_client(
                client_id="duplicate",
                client_name="Second",
                owner_user_id=test_user_id,
                redirect_uris=["https://second.com/callback"],
            )

    def test_register_client_public_client(self, oauth_service, test_user_id):
        """Test registering public client without secret."""
        client, secret = oauth_service.register_client(
            client_id="public-app",
            client_name="Public App",
            owner_user_id=test_user_id,
            redirect_uris=["https://publicapp.com/callback"],
            is_confidential=False,
        )

        assert client.is_confidential is False


class TestClientValidation:
    """Tests for client validation."""

    def test_validate_client_success(self, oauth_service, test_client):
        """Test successful client validation."""
        client, secret = test_client
        validated = oauth_service.validate_client(client.client_id, secret)
        assert validated.client_id == client.client_id

    def test_validate_client_invalid_id(self, oauth_service):
        """Test validation fails with invalid client ID."""
        with pytest.raises(OAuthInvalidClient):
            oauth_service.validate_client("nonexistent", "secret")

    def test_validate_client_invalid_secret(self, oauth_service, test_client):
        """Test validation fails with invalid secret."""
        client, _ = test_client
        with pytest.raises(OAuthInvalidClient):
            oauth_service.validate_client(client.client_id, "wrong-secret")

    def test_validate_client_missing_secret(self, oauth_service, test_client):
        """Test validation fails when secret missing for confidential client."""
        client, _ = test_client
        with pytest.raises(OAuthInvalidClient):
            oauth_service.validate_client(client.client_id)

    def test_validate_client_inactive(self, oauth_service, test_client):
        """Test validation fails for inactive client."""
        client, secret = test_client
        client.is_active = False

        with pytest.raises(OAuthInvalidClient):
            oauth_service.validate_client(client.client_id, secret)


class TestRedirectUriValidation:
    """Tests for redirect URI validation."""

    def test_validate_redirect_uri_success(self, oauth_service, test_client):
        """Test successful redirect URI validation."""
        client, _ = test_client
        oauth_service.validate_redirect_uri(client, "https://localhost:3000/callback")

    def test_validate_redirect_uri_not_registered(self, oauth_service, test_client):
        """Test validation fails for unregistered redirect URI."""
        client, _ = test_client
        with pytest.raises(OAuthInvalidRequest):
            oauth_service.validate_redirect_uri(
                client, "https://attacker.com/callback"
            )


class TestAuthorizationRequest:
    """Tests for authorization request validation."""

    def test_validate_authorization_request_success(
        self, oauth_service, test_client
    ):
        """Test successful authorization request validation."""
        client, _ = test_client
        request = AuthorizationRequest(
            response_type="code",
            client_id=client.client_id,
            redirect_uri="https://localhost:3000/callback",
            scope="openid profile",
            state="abc123",
        )

        validated = oauth_service.validate_authorization_request(request)
        assert validated.client_id == client.client_id

    def test_validate_authorization_request_invalid_response_type(
        self, oauth_service, test_client
    ):
        """Test validation fails with invalid response_type."""
        client, _ = test_client
        request = AuthorizationRequest(
            response_type="token",  # Invalid, must be 'code'
            client_id=client.client_id,
            redirect_uri="https://localhost:3000/callback",
        )

        with pytest.raises(OAuthInvalidRequest):
            oauth_service.validate_authorization_request(request)

    def test_validate_authorization_request_invalid_scope(
        self, oauth_service, test_client
    ):
        """Test validation fails with unauthorized scope."""
        client, _ = test_client
        request = AuthorizationRequest(
            response_type="code",
            client_id=client.client_id,
            redirect_uri="https://localhost:3000/callback",
            scope="unauthorized_scope",
        )

        with pytest.raises(OAuthInvalidRequest):
            oauth_service.validate_authorization_request(request)


class TestAuthorizationCode:
    """Tests for authorization code generation and validation."""

    def test_create_authorization_code(self, oauth_service, test_client, test_user_id):
        """Test creating authorization code."""
        client, _ = test_client
        code = oauth_service.create_authorization_code(
            client_id=client.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
            scopes=["openid", "profile"],
            nonce="test-nonce",
        )

        assert len(code) > 20
        assert code in oauth_service._authorization_codes

        stored_code = oauth_service._authorization_codes[code]
        assert stored_code.client_id == client.client_id
        assert stored_code.user_id == test_user_id
        assert stored_code.scopes == ["openid", "profile"]
        assert stored_code.nonce == "test-nonce"
        assert not stored_code.used

    def test_authorization_code_expiration(self, oauth_service, test_client, test_user_id):
        """Test authorization code expires."""
        client, _ = test_client
        code = oauth_service.create_authorization_code(
            client_id=client.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
        )

        stored_code = oauth_service._authorization_codes[code]
        assert stored_code.expires_at > datetime.now(timezone.utc)
        assert stored_code.expires_at <= datetime.now(timezone.utc) + timedelta(minutes=11)


class TestTokenExchange:
    """Tests for authorization code exchange for tokens."""

    def test_exchange_authorization_code_success(
        self, oauth_service, test_client, test_user_id
    ):
        """Test successful authorization code exchange."""
        client, secret = test_client

        # Create authorization code
        code = oauth_service.create_authorization_code(
            client_id=client.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
            scopes=["openid", "profile"],
        )

        # Exchange for tokens
        token_request = TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://localhost:3000/callback",
            client_id=client.client_id,
            client_secret=secret,
        )

        response = oauth_service.exchange_authorization_code(token_request)

        assert response.access_token
        assert response.token_type == "Bearer"
        assert response.expires_in > 0
        assert response.refresh_token
        assert response.id_token  # Since openid scope included

    def test_exchange_invalid_grant_type(self, oauth_service, test_client):
        """Test exchange fails with invalid grant type."""
        client, secret = test_client
        token_request = TokenRequest(
            grant_type="invalid_grant",
            client_id=client.client_id,
            client_secret=secret,
        )

        with pytest.raises(OAuthUnsupportedGrantType):
            oauth_service.exchange_authorization_code(token_request)

    def test_exchange_missing_code(self, oauth_service, test_client):
        """Test exchange fails when code missing."""
        client, secret = test_client
        token_request = TokenRequest(
            grant_type="authorization_code",
            redirect_uri="https://localhost:3000/callback",
            client_id=client.client_id,
            client_secret=secret,
        )

        with pytest.raises(OAuthInvalidRequest):
            oauth_service.exchange_authorization_code(token_request)

    def test_exchange_invalid_code(self, oauth_service, test_client):
        """Test exchange fails with invalid code."""
        client, secret = test_client
        token_request = TokenRequest(
            grant_type="authorization_code",
            code="invalid-code",
            redirect_uri="https://localhost:3000/callback",
            client_id=client.client_id,
            client_secret=secret,
        )

        with pytest.raises(OAuthInvalidGrant):
            oauth_service.exchange_authorization_code(token_request)

    def test_exchange_expired_code(self, oauth_service, test_client, test_user_id):
        """Test exchange fails with expired code."""
        client, secret = test_client

        # Create and immediately expire code
        code = oauth_service.create_authorization_code(
            client_id=client.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
        )
        auth_code = oauth_service._authorization_codes[code]
        auth_code.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        token_request = TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://localhost:3000/callback",
            client_id=client.client_id,
            client_secret=secret,
        )

        with pytest.raises(OAuthInvalidGrant):
            oauth_service.exchange_authorization_code(token_request)

    def test_exchange_code_already_used(
        self, oauth_service, test_client, test_user_id
    ):
        """Test exchange fails when code already used."""
        client, secret = test_client

        code = oauth_service.create_authorization_code(
            client_id=client.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
        )

        token_request = TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://localhost:3000/callback",
            client_id=client.client_id,
            client_secret=secret,
        )

        # First exchange succeeds
        oauth_service.exchange_authorization_code(token_request)

        # Second exchange fails
        with pytest.raises(OAuthInvalidGrant):
            oauth_service.exchange_authorization_code(token_request)

    def test_exchange_code_wrong_client(
        self, oauth_service, test_user_id
    ):
        """Test exchange fails when code issued to different client."""
        # Create two clients
        client1, secret1 = oauth_service.register_client(
            client_id="client-1",
            client_name="Client 1",
            owner_user_id=test_user_id,
            redirect_uris=["https://localhost:3000/callback"],
        )

        client2, secret2 = oauth_service.register_client(
            client_id="client-2",
            client_name="Client 2",
            owner_user_id=test_user_id,
            redirect_uris=["https://localhost:3000/callback"],
        )

        # Create code for client 1
        code = oauth_service.create_authorization_code(
            client_id=client1.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
        )

        # Try to exchange with client 2
        token_request = TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://localhost:3000/callback",
            client_id=client2.client_id,
            client_secret=secret2,
        )

        with pytest.raises(OAuthInvalidGrant):
            oauth_service.exchange_authorization_code(token_request)


class TestTokenRefresh:
    """Tests for token refresh."""

    def test_refresh_token_success(self, oauth_service, test_client, test_user_id):
        """Test successful token refresh."""
        client, secret = test_client

        # Get refresh token via authorization code exchange
        code = oauth_service.create_authorization_code(
            client_id=client.client_id,
            user_id=test_user_id,
            redirect_uri="https://localhost:3000/callback",
        )

        token_request = TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://localhost:3000/callback",
            client_id=client.client_id,
            client_secret=secret,
        )

        initial_response = oauth_service.exchange_authorization_code(token_request)
        refresh_token = initial_response.refresh_token

        # Refresh token
        refreshed = oauth_service.refresh_access_token(
            refresh_token=refresh_token,
            client_id=client.client_id,
            client_secret=secret,
        )

        assert refreshed.access_token
        assert refreshed.refresh_token
        assert refreshed.access_token != initial_response.access_token

    def test_refresh_token_invalid(self, oauth_service, test_client):
        """Test refresh with invalid token."""
        client, secret = test_client

        with pytest.raises(OAuthInvalidGrant):
            oauth_service.refresh_access_token(
                refresh_token="invalid-token",
                client_id=client.client_id,
                client_secret=secret,
            )


class TestJWKS:
    """Tests for JWKS endpoint."""

    def test_get_jwks(self, oauth_service):
        """Test getting JWKS."""
        jwks = oauth_service.get_jwks()
        assert "keys" in jwks
        assert isinstance(jwks["keys"], list)

    def test_get_public_jwks(self, oauth_service):
        """Test getting public JWKS."""
        jwks = oauth_service.get_public_jwks()
        assert "keys" in jwks
        assert isinstance(jwks["keys"], list)
