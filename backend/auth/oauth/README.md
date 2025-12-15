# OAuth2/OpenID Connect Provider

## Overview

OAuth2/OpenID Connect provider implementation for QuantumX-CLM with support for:

- **Authorization Code Flow**: Standard OAuth2 flow for server-side applications
- **Token Exchange**: Exchange authorization codes for access/refresh tokens
- **OpenID Connect**: ID tokens with user claims
- **JWKS**: JSON Web Key Set endpoint for token validation
- **Token Refresh**: Refresh expired access tokens

## Quick Start

### 1. Import the Service

```python
from backend.auth.oauth import oauth_service
```

### 2. Register a Client

```python
client, secret = oauth_service.register_client(
    client_id="my-app",
    client_name="My Application",
    owner_user_id=user_id,
    redirect_uris=["https://myapp.com/callback"],
    scopes=["openid", "profile", "email"],
)
```

### 3. Exchange Authorization Code for Tokens

```python
from backend.auth.oauth.models import TokenRequest

token_response = oauth_service.exchange_authorization_code(
    TokenRequest(
        grant_type="authorization_code",
        code=auth_code,
        redirect_uri="https://myapp.com/callback",
        client_id="my-app",
        client_secret=secret,
    )
)
```

## Endpoints

### Authorization Endpoint
```
GET /auth/oauth/authorize
  ?response_type=code
  &client_id=my-app
  &redirect_uri=https://myapp.com/callback
  &scope=openid+profile+email
  &state=abc123
  &nonce=xyz789
```

### Token Endpoint
```
POST /auth/oauth/token
Content-Type: application/json

{
    "grant_type": "authorization_code",
    "code": "AUTHORIZATION_CODE",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "my-app",
    "client_secret": "SECRET"
}
```

### JWKS Endpoint
```
GET /.well-known/jwks.json
```

## File Structure

```
backend/auth/oauth/
├── __init__.py              # Module exports
├── models.py                # Pydantic models for OAuth entities
├── service.py               # Core OAuth2/OIDC service logic
├── api.py                   # FastAPI endpoints
├── README.md                # This file
├── CONFIG.md                # Configuration documentation
└── IMPLEMENTATION_GUIDE.md  # Detailed implementation guide
```

## Models

### OAuthClient
Represents an OAuth client application:
- `client_id`: Unique identifier
- `client_secret_hash`: Hashed client secret
- `redirect_uris`: Authorized redirect URIs
- `scopes`: Authorized scopes
- `grant_types`: Supported grant types
- `response_types`: Supported response types

### AuthorizationCode
Represents an authorization code:
- `code`: Authorization code value
- `client_id`: Issuing client
- `user_id`: User who authorized
- `redirect_uri`: Redirect URI
- `scopes`: Requested scopes
- `nonce`: OIDC nonce
- `expires_at`: Expiration time
- `used`: Whether code has been used

### TokenRequest
Token endpoint request:
- `grant_type`: "authorization_code" or "refresh_token"
- `code`: Authorization code (for authorization_code grant)
- `refresh_token`: Refresh token (for refresh_token grant)
- `client_id`: Client ID
- `client_secret`: Client secret

### TokenResponse
Token endpoint response:
- `access_token`: Access token
- `token_type`: Token type (Bearer)
- `expires_in`: Expiration time in seconds
- `refresh_token`: Refresh token
- `id_token`: ID token (OIDC)
- `scope`: Granted scopes

## Service API

### Client Management
```python
# Register client
client, secret = oauth_service.register_client(
    client_id="app-id",
    client_name="App Name",
    owner_user_id=uuid4(),
    redirect_uris=["https://app.com/callback"],
    is_confidential=True,
)

# Validate client
client = oauth_service.validate_client(
    client_id="app-id",
    client_secret=secret,  # Optional for public clients
)
```

### Authorization Flow
```python
# Validate authorization request
client = oauth_service.validate_authorization_request(
    AuthorizationRequest(
        response_type="code",
        client_id="app-id",
        redirect_uri="https://app.com/callback",
        scope="openid profile",
    )
)

# Create authorization code
code = oauth_service.create_authorization_code(
    client_id="app-id",
    user_id=user_id,
    redirect_uri="https://app.com/callback",
    scopes=["openid", "profile"],
)
```

### Token Exchange
```python
# Exchange authorization code for tokens
response = oauth_service.exchange_authorization_code(
    TokenRequest(
        grant_type="authorization_code",
        code=code,
        redirect_uri="https://app.com/callback",
        client_id="app-id",
        client_secret=secret,
    )
)

# Refresh access token
response = oauth_service.refresh_access_token(
    refresh_token=refresh_token,
    client_id="app-id",
    client_secret=secret,
)
```

### JWKS
```python
# Get JWKS
jwks = oauth_service.get_jwks()

# Get public JWKS (for token validation)
jwks = oauth_service.get_public_jwks()
```

## Error Handling

Exceptions follow RFC 6749:

```python
from backend.auth.oauth.service import (
    OAuthError,
    OAuthInvalidClient,
    OAuthInvalidGrant,
    OAuthInvalidRequest,
    OAuthUnauthorizedClient,
    OAuthUnsupportedGrantType,
)

try:
    client = oauth_service.validate_client(client_id, secret)
except OAuthInvalidClient as e:
    # Handle invalid client
    print(f"Error: {e.error}, Description: {e.error_description}")
```

## Configuration

See [CONFIG.md](CONFIG.md) for detailed configuration options.

**Key Environment Variables:**
```bash
CLM_JWT_SECRET_KEY=your-secret-key
CLM_JWT_ALGORITHM=HS256
CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
CLM_OAUTH_AUTHORIZATION_CODE_TTL_SECONDS=600
CLM_OAUTH_ISSUER=https://auth.clm.local
```

## Testing

```bash
cd backend
pytest tests/auth/oauth/test_service.py -v
```

Test coverage includes:
- Client registration and validation
- Authorization request validation
- Authorization code generation and expiration
- Token exchange (success and error cases)
- Token refresh
- JWKS endpoint
- Error handling

## Implementation Notes

### Current State
- In-memory storage (not persistent)
- No user authentication context (returns 501)
- No consent screen
- No audit logging (per constraints)
- No RBAC (per constraints)
- No middleware (per constraints)

### Future Enhancements
- Database persistence
- User authentication integration
- Consent screen
- PKCE support
- Token introspection
- Token revocation
- Distributed session state (Redis)

## Security

### Development
- JWT secret is insecure default
- In-memory storage
- HS256 symmetric algorithm

### Production
- Change JWT secret key
- Use RS256/RS512 asymmetric algorithm
- Persist state to database
- Enforce HTTPS
- Implement rate limiting
- Add user authentication
- Enable PKCE for public clients

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for detailed security checklist.

## Integration

The OAuth module is integrated into the FastAPI app:

```python
# backend/auth/router.py
from backend.auth.oauth.api import router as oauth_router

router = APIRouter(prefix="/auth")
router.include_router(oauth_router)
```

Endpoints are available at:
- `/auth/oauth/authorize`
- `/auth/oauth/token`
- `/.well-known/jwks.json`

## References

- [OAuth 2.0 Authorization Framework (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [JSON Web Key (JWK) Format (RFC 7517)](https://tools.ietf.org/html/rfc7517)

## Support

For detailed implementation information, see:
- [CONFIG.md](CONFIG.md) - Configuration guide
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Detailed implementation guide
- [tests/auth/oauth/](../../tests/auth/oauth/) - Test examples
