# OAuth2/OpenID Connect Provider Configuration

## Overview

The OAuth2/OIDC provider implementation supports:
- **Authorization Code Flow**: Standard OAuth2 flow for server-side applications
- **Token Exchange**: Exchanging authorization codes for access tokens
- **JWKS Handling**: Serving JSON Web Key Sets for token validation
- **Refresh Token Support**: Refreshing expired access tokens

## Configuration

### Environment Variables

All OAuth configuration uses the `CLM_` prefix as per the Pydantic Settings convention.

#### JWT Configuration (Used for Token Generation)

```bash
# JWT Secret Key (MUST be changed in production)
CLM_JWT_SECRET_KEY=dev-secret-key-change-in-production

# JWT Algorithm (HS256, HS384, HS512, RS256, etc.)
CLM_JWT_ALGORITHM=HS256

# Access Token Expiration (minutes)
CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60

# Refresh Token Expiration (days)
CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Client Registration

Clients are registered via the `OAuthService.register_client()` method:

```python
from backend.auth.oauth import oauth_service
from uuid import UUID

client, secret = oauth_service.register_client(
    client_id="my-app",
    client_name="My Application",
    owner_user_id=UUID("..."),
    redirect_uris=["https://myapp.com/callback"],
    scopes=["openid", "profile", "email"],
    grant_types=["authorization_code", "refresh_token"],
    response_types=["code"],
    is_confidential=True,
)
```

**Parameters:**

- `client_id` (str): Unique identifier for the client
- `client_name` (str): Human-readable name
- `owner_user_id` (UUID): User who registered the client
- `redirect_uris` (list[str]): Authorized redirect URIs
- `scopes` (list[str], optional): Scopes the client can request (default: `["openid", "profile"]`)
- `grant_types` (list[str], optional): Supported grant types (default: `["authorization_code"]`)
- `response_types` (list[str], optional): Supported response types (default: `["code"]`)
- `is_confidential` (bool, optional): Whether client has a secret (default: `True`)

**Returns:** Tuple of `(OAuthClient, client_secret)`

## Endpoints

### Authorization Endpoint
```
GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&nonce=...
```

**Parameters:**
- `response_type` (required): Must be "code"
- `client_id` (required): Client ID
- `redirect_uri` (required): Redirect URI (must match registered URI)
- `scope` (optional): Space-separated scopes
- `state` (optional): Opaque state parameter for CSRF protection
- `nonce` (optional): Nonce for OpenID Connect binding

**Response:**
In a full implementation, would redirect to:
```
redirect_uri?code=AUTHORIZATION_CODE&state=STATE
```

**Current Implementation Note:**
Returns 501 Not Implemented. Full implementation requires:
1. User authentication context (via session/JWT)
2. Consent screen
3. Authorization code generation
4. Redirect to redirect_uri

### Token Endpoint
```
POST /oauth/token
Content-Type: application/json

{
    "grant_type": "authorization_code",
    "code": "AUTHORIZATION_CODE",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "my-app",
    "client_secret": "SECRET"
}
```

**Grant Types:**

#### Authorization Code Grant
Exchanges authorization code for tokens.

**Parameters:**
- `grant_type`: "authorization_code"
- `code`: Authorization code from authorization endpoint
- `redirect_uri`: Must match the redirect_uri used in authorization request
- `client_id`: Client ID
- `client_secret`: Client secret (required for confidential clients)

**Response:**
```json
{
    "access_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "eyJhbGc...",
    "id_token": "eyJhbGc...",
    "scope": "openid profile"
}
```

#### Refresh Token Grant
Refreshes an expired access token.

**Parameters:**
- `grant_type`: "refresh_token"
- `refresh_token`: Valid refresh token
- `client_id`: Client ID
- `client_secret`: Client secret (required for confidential clients)

**Response:**
```json
{
    "access_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "eyJhbGc..."
}
```

**Error Responses:**
```json
{
    "error": "invalid_grant",
    "error_description": "Authorization code has expired"
}
```

### JWKS Endpoint
```
GET /.well-known/jwks.json
```

**Response:**
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

**Note:** For symmetric algorithms (HS256), returns empty keys array as public key exposure is not applicable.

## Token Structure

### Access Token Claims

```json
{
    "sub": "user-id",
    "exp": 1234567890,
    "iat": 1234567800,
    "type": "access",
    "scope": "openid profile",
    "client_id": "my-app"
}
```

### ID Token Claims (OpenID Connect)

Generated when "openid" scope is requested:

```json
{
    "iss": "https://auth.clm.local",
    "sub": "user-id",
    "aud": "my-app",
    "exp": 1234567890,
    "iat": 1234567800,
    "auth_time": 1234567800,
    "nonce": "nonce-value",
    "given_name": "User",
    "family_name": "user-id",
    "email": "user@clm.local"
}
```

## Supported Scopes

The following scopes are supported:

- `openid`: Request an ID token
- `profile`: Request user profile information (name, etc.)
- `email`: Request email information
- Custom scopes can be added per client

## Error Codes

Standard OAuth2 error codes:

| Code | Description |
|------|-------------|
| `invalid_request` | Request is missing required parameters |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Authorization code invalid or expired |
| `unauthorized_client` | Client not authorized for grant type |
| `unsupported_grant_type` | Grant type not supported |

## Security Considerations

### In Development
- JWT secret key is a default insecure value
- Clients stored in memory (not persistent)
- Authorization codes stored in memory with 10-minute TTL
- No HTTPS enforcement in development mode

### For Production

1. **Change JWT Secret Key**
   ```bash
   CLM_JWT_SECRET_KEY=$(openssl rand -base64 32)
   ```

2. **Use RS256 or RS512 Algorithm**
   - Switch from HS256 to asymmetric algorithm
   - Expose public key via JWKS endpoint
   - Keep private key secure

3. **Persist OAuth State**
   - Move `_authorization_codes` to database
   - Move `_oauth_clients` to database
   - Implement proper cleanup of expired codes

4. **Enforce HTTPS**
   - All OAuth endpoints must use HTTPS
   - Reject non-HTTPS redirect URIs

5. **Client Authentication**
   - Use strong client secrets
   - Consider mutual TLS for confidential clients
   - Implement client secret rotation

6. **Rate Limiting**
   - Add rate limiting to token endpoint
   - Prevent authorization code enumeration attacks

7. **PKCE Support**
   - Implement PKCE (RFC 7636) for public clients
   - Prevent authorization code interception attacks

8. **User Consent**
   - Implement consent screen before issuing authorization code
   - Allow users to revoke client access

## Integration Example

```python
from fastapi import FastAPI
from backend.auth.oauth import oauth_service
from backend.auth.oauth.api import router as oauth_router
from uuid import UUID

app = FastAPI()
app.include_router(oauth_router)

# Register a client
client, secret = oauth_service.register_client(
    client_id="web-app",
    client_name="Web Application",
    owner_user_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
    redirect_uris=["https://localhost:3000/callback"],
    scopes=["openid", "profile", "email"],
)

print(f"Client ID: {client.client_id}")
print(f"Client Secret: {secret}")
```

## Testing OAuth Flow

### 1. Create Test Client
```python
from backend.auth.oauth import oauth_service
from uuid import uuid4

client, secret = oauth_service.register_client(
    client_id="test-client",
    client_name="Test Client",
    owner_user_id=uuid4(),
    redirect_uris=["http://localhost:3000/callback"],
)
```

### 2. Request Authorization Code
```
GET /oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=openid+profile&state=abc123&nonce=xyz789
```

### 3. Exchange for Tokens
```bash
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTHORIZATION_CODE",
    "redirect_uri": "http://localhost:3000/callback",
    "client_id": "test-client",
    "client_secret": "'$secret'"
  }'
```

### 4. Get JWKS
```
GET /.well-known/jwks.json
```

### 5. Refresh Token
```bash
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "REFRESH_TOKEN",
    "client_id": "test-client",
    "client_secret": "'$secret'"
  }'
```

## Architecture Notes

### Current Implementation
- In-memory storage for clients and authorization codes
- 10-minute TTL for authorization codes
- No audit logging (as per constraints)
- No RBAC (as per constraints)
- No middleware (as per constraints)

### Future Enhancements
- Database persistence for clients and codes
- Redis for distributed session state
- PKCE support for public clients
- Consent screen UI
- Client management endpoints
- Token revocation endpoint
- Introspection endpoint
- Device flow support
