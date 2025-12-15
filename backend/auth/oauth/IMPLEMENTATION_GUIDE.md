# OAuth2/OIDC Implementation Guide

## Overview

This guide documents the OAuth2/OpenID Connect provider implementation for the QuantumX-CLM platform. The implementation provides a foundation for OAuth2/OIDC flows with support for:

- Authorization Code Flow (with code exchange)
- Token Exchange (authorization code → access token/refresh token)
- OpenID Connect ID tokens
- JWKS (JSON Web Key Set) endpoint for token validation
- Token Refresh (refresh token → new access token)

## Architecture

### Core Components

#### 1. Service Layer (`service.py`)

The `OAuthService` class provides:

**Client Management**
- `register_client()`: Register new OAuth client
- `validate_client()`: Validate client credentials

**Authorization Flow**
- `validate_authorization_request()`: Validate authorization requests
- `validate_redirect_uri()`: Validate redirect URIs
- `create_authorization_code()`: Generate authorization codes

**Token Exchange**
- `exchange_authorization_code()`: Exchange code for tokens
- `refresh_access_token()`: Refresh expired tokens

**Key Distribution**
- `get_jwks()`: Get full JWKS (includes secret for symmetric algorithms)
- `get_public_jwks()`: Get public JWKS (for token validation)

**Utilities**
- `_create_id_token()`: Generate OpenID Connect ID tokens

#### 2. Models (`models.py`)

**Data Models**
- `OAuthClient`: OAuth client application
- `AuthorizationCode`: Authorization code with metadata
- `TokenRequest`: Token endpoint request
- `TokenResponse`: Token endpoint response
- `AuthorizationRequest`: Authorization endpoint request
- `JWKSet`: JSON Web Key Set structure

#### 3. API Endpoints (`api.py`)

**OAuth2/OIDC Endpoints**
- `GET /oauth/authorize`: Authorization endpoint
- `POST /oauth/token`: Token endpoint
- `GET /.well-known/jwks.json`: JWKS endpoint

### Current Implementation Status

**Implemented:**
- ✅ Authorization code generation and validation
- ✅ Token exchange (authorization_code grant)
- ✅ Token refresh (refresh_token grant)
- ✅ ID token generation (OpenID Connect)
- ✅ Client registration and validation
- ✅ Redirect URI validation
- ✅ Scope validation
- ✅ JWKS endpoint
- ✅ Error handling with standard OAuth2 error codes

**Not Implemented (As Per Constraints):**
- ❌ Audit logging (constraint: no audit logging)
- ❌ RBAC/authorization checks (constraint: no RBAC)
- ❌ Middleware (constraint: no middleware)
- ❌ Persistent storage (in-memory only)
- ❌ User authentication context (endpoint returns 501)
- ❌ Consent screen

**Future Enhancements:**
- Database persistence
- Redis for distributed state
- PKCE support
- Consent screen UI
- User authentication endpoints
- Client management endpoints
- Token introspection
- Token revocation
- Device flow
- Assertion-based flows

## Usage

### 1. Register a Client

```python
from backend.auth.oauth import oauth_service
from uuid import UUID

# Register confidential client
client, secret = oauth_service.register_client(
    client_id="web-app",
    client_name="Web Application",
    owner_user_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
    redirect_uris=[
        "https://localhost:3000/callback",
        "https://localhost:3000/silent-refresh",
    ],
    scopes=["openid", "profile", "email"],
    grant_types=["authorization_code", "refresh_token"],
    response_types=["code"],
    is_confidential=True,
)

print(f"Client ID: {client.client_id}")
print(f"Client Secret: {secret}")  # Keep this secret!
```

### 2. Authorization Code Flow

#### Step 1: User requests authorization

```
GET /oauth/authorize?response_type=code&client_id=web-app&redirect_uri=https://localhost:3000/callback&scope=openid+profile&state=abc123&nonce=xyz789
```

**Note:** In production, this would:
1. Check user is authenticated
2. Display consent screen
3. Generate authorization code
4. Redirect to `redirect_uri?code=AUTH_CODE&state=abc123`

#### Step 2: Exchange code for tokens

```python
from backend.auth.oauth.models import TokenRequest

token_request = TokenRequest(
    grant_type="authorization_code",
    code="AUTHORIZATION_CODE",
    redirect_uri="https://localhost:3000/callback",
    client_id="web-app",
    client_secret="SECRET",
)

response = oauth_service.exchange_authorization_code(token_request)

# {
#     "access_token": "eyJhbGc...",
#     "token_type": "Bearer",
#     "expires_in": 3600,
#     "refresh_token": "eyJhbGc...",
#     "id_token": "eyJhbGc...",
#     "scope": "openid profile"
# }
```

### 3. Token Refresh

```python
from backend.auth.oauth.models import TokenRequest

token_request = TokenRequest(
    grant_type="refresh_token",
    refresh_token="REFRESH_TOKEN",
    client_id="web-app",
    client_secret="SECRET",
)

response = oauth_service.refresh_access_token(
    refresh_token=token_request.refresh_token,
    client_id=token_request.client_id,
    client_secret=token_request.client_secret,
)

# {
#     "access_token": "eyJhbGc...",
#     "token_type": "Bearer",
#     "expires_in": 3600,
#     "refresh_token": "eyJhbGc..."
# }
```

### 4. Get JWKS

```
GET /.well-known/jwks.json
```

Response:
```json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "default-key"
        }
    ]
}
```

## Error Handling

All OAuth endpoints follow RFC 6749 error response format:

```json
{
    "error": "invalid_grant",
    "error_description": "Authorization code has expired"
}
```

### Standard Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `invalid_request` | 400 | Request missing required parameters |
| `invalid_client` | 401 | Client authentication failed |
| `invalid_grant` | 400 | Code invalid/expired |
| `unauthorized_client` | 400 | Client not authorized for grant type |
| `unsupported_grant_type` | 400 | Grant type not supported |

## Configuration

### Environment Variables

```bash
# JWT Configuration (affects token generation)
CLM_JWT_SECRET_KEY=your-secret-key
CLM_JWT_ALGORITHM=HS256
CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# OAuth Configuration
CLM_OAUTH_AUTHORIZATION_CODE_TTL_SECONDS=600
CLM_OAUTH_ISSUER=https://auth.clm.local
```

### JWT Algorithm Selection

**HS256 (Current - Development)**
- Symmetric algorithm
- Uses shared secret
- Simpler to set up
- Not suitable for public key validation

**RS256 (Recommended - Production)**
- Asymmetric algorithm
- Public key can be exposed via JWKS
- Allows clients to validate tokens independently
- Requires key pair management

## Testing

### Run Tests

```bash
cd /home/engine/project
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
cd backend && pytest tests/auth/oauth/test_service.py -v
```

### Test Coverage

Tests cover:
- ✅ Client registration
- ✅ Client validation
- ✅ Redirect URI validation
- ✅ Authorization request validation
- ✅ Authorization code generation
- ✅ Authorization code expiration
- ✅ Token exchange (success/failure cases)
- ✅ Token refresh
- ✅ JWKS endpoint
- ✅ Error handling

## Integration with FastAPI

The OAuth service is integrated into the FastAPI app via routers:

```python
# backend/auth/router.py
from backend.auth.oauth.api import router as oauth_router

router = APIRouter(prefix="/auth", tags=["auth"])
router.include_router(oauth_router)

# Endpoints available at:
# - /auth/oauth/authorize
# - /auth/oauth/token
# - /.well-known/jwks.json (via wellknown router)
```

## Security Considerations

### Development

- JWT secret is default insecure value
- Clients stored in memory (not persistent)
- Authorization codes stored in memory with 10-minute TTL
- No HTTPS enforcement

### Production Checklist

- [ ] Change JWT secret key
- [ ] Use RS256 or RS512 algorithm
- [ ] Persist clients to database
- [ ] Persist authorization codes to database
- [ ] Implement automatic code cleanup
- [ ] Enforce HTTPS for all OAuth endpoints
- [ ] Implement rate limiting on token endpoint
- [ ] Add user authentication to authorization endpoint
- [ ] Implement consent screen
- [ ] Enable PKCE support for public clients
- [ ] Implement client secret rotation
- [ ] Add audit logging for token generation
- [ ] Monitor for suspicious patterns
- [ ] Set up security alerts

## Persistence Strategy

Currently uses in-memory storage. To add persistence:

1. **Create database table for oauth_clients**
   ```sql
   CREATE TABLE oauth_clients (
       id UUID PRIMARY KEY,
       client_id VARCHAR(255) UNIQUE NOT NULL,
       client_secret_hash VARCHAR(255) NOT NULL,
       client_name VARCHAR(255) NOT NULL,
       owner_user_id UUID NOT NULL,
       redirect_uris TEXT[] NOT NULL,
       scopes TEXT[] NOT NULL,
       grant_types TEXT[] NOT NULL,
       response_types TEXT[] NOT NULL,
       is_confidential BOOLEAN DEFAULT TRUE,
       is_active BOOLEAN DEFAULT TRUE,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   ```

2. **Create database table for authorization_codes**
   ```sql
   CREATE TABLE authorization_codes (
       id UUID PRIMARY KEY,
       code VARCHAR(255) UNIQUE NOT NULL,
       client_id VARCHAR(255) NOT NULL,
       user_id UUID NOT NULL,
       redirect_uri TEXT NOT NULL,
       scopes TEXT[],
       nonce VARCHAR(255),
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       expires_at TIMESTAMP NOT NULL,
       used BOOLEAN DEFAULT FALSE,
       used_at TIMESTAMP
   );
   ```

3. **Update OAuthService to use SQLAlchemy models**
   - Replace in-memory dictionaries with database queries
   - Implement cleanup for expired codes

## Roadmap

### Phase 1 (Current)
- ✅ Authorization code flow
- ✅ Token exchange
- ✅ JWKS endpoint
- ✅ Token refresh

### Phase 2 (Future)
- User authentication context
- Consent screen
- Database persistence
- Client management endpoints

### Phase 3 (Future)
- PKCE support
- Device flow
- Assertion-based flows
- Introspection endpoint
- Revocation endpoint

## References

- [OAuth 2.0 Authorization Framework (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [JSON Web Key (JWK) Format (RFC 7517)](https://tools.ietf.org/html/rfc7517)
- [OAuth 2.0 Proof Key for Public Clients (RFC 7636)](https://tools.ietf.org/html/rfc7636)
