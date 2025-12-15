# OAuth2/OIDC Quick Reference

## Endpoints

### Authorization Endpoint
```
GET /auth/oauth/authorize
  ?response_type=code
  &client_id=my-app
  &redirect_uri=https://myapp.com/callback
  &scope=openid+profile
  &state=random-state
  &nonce=random-nonce
```
**Status:** Returns 501 (requires user authentication context)

### Token Endpoint
```
POST /auth/oauth/token
Content-Type: application/json

# Exchange authorization code
{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "my-app",
    "client_secret": "SECRET"
}

# Refresh access token
{
    "grant_type": "refresh_token",
    "refresh_token": "REFRESH_TOKEN",
    "client_id": "my-app",
    "client_secret": "SECRET"
}
```
**Returns:**
```json
{
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "...",
    "id_token": "...",
    "scope": "openid profile"
}
```

### JWKS Endpoint
```
GET /.well-known/jwks.json
```
**Returns:** JSON Web Key Set for token validation

## Service API

### Import
```python
from backend.auth.oauth import oauth_service
```

### Register Client
```python
client, secret = oauth_service.register_client(
    client_id="app-id",
    client_name="App Name",
    owner_user_id=user_id,
    redirect_uris=["https://app.com/callback"],
    scopes=["openid", "profile", "email"],
)
```

### Create Authorization Code
```python
code = oauth_service.create_authorization_code(
    client_id="app-id",
    user_id=user_id,
    redirect_uri="https://app.com/callback",
    scopes=["openid", "profile"],
    nonce="nonce-value"
)
```

### Exchange Code for Tokens
```python
from backend.auth.oauth.models import TokenRequest

response = oauth_service.exchange_authorization_code(
    TokenRequest(
        grant_type="authorization_code",
        code=code,
        redirect_uri="https://app.com/callback",
        client_id="app-id",
        client_secret=secret,
    )
)

# Access tokens
access_token = response.access_token
refresh_token = response.refresh_token
id_token = response.id_token
```

### Refresh Token
```python
response = oauth_service.refresh_access_token(
    refresh_token=refresh_token,
    client_id="app-id",
    client_secret=secret,
)
```

### Get JWKS
```python
jwks = oauth_service.get_public_jwks()
```

## Configuration

```bash
# In .env or environment
CLM_JWT_SECRET_KEY=your-secret-key
CLM_JWT_ALGORITHM=HS256
CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
CLM_OAUTH_AUTHORIZATION_CODE_TTL_SECONDS=600
CLM_OAUTH_ISSUER=https://auth.clm.local
```

## Error Codes

| Code | Status | Meaning |
|------|--------|---------|
| `invalid_request` | 400 | Missing required parameters |
| `invalid_client` | 401 | Client authentication failed |
| `invalid_grant` | 400 | Authorization code invalid/expired |
| `unauthorized_client` | 400 | Client not authorized for grant |
| `unsupported_grant_type` | 400 | Grant type not supported |

## Token Claims

### Access Token
```json
{
    "sub": "user-id",
    "exp": 1234567890,
    "iat": 1234567800,
    "type": "access",
    "scope": "openid profile",
    "client_id": "app-id"
}
```

### ID Token (OIDC)
```json
{
    "iss": "https://auth.clm.local",
    "sub": "user-id",
    "aud": "app-id",
    "exp": 1234567890,
    "iat": 1234567800,
    "auth_time": 1234567800,
    "nonce": "nonce-value",
    "given_name": "User",
    "email": "user@clm.local"
}
```

### Refresh Token
```json
{
    "sub": "user-id",
    "exp": 1234627200,
    "iat": 1234567800,
    "type": "refresh",
    "client_id": "app-id"
}
```

## Exception Handling

```python
from backend.auth.oauth.service import (
    OAuthError,
    OAuthInvalidClient,
    OAuthInvalidGrant,
    OAuthInvalidRequest,
)

try:
    response = oauth_service.exchange_authorization_code(request)
except OAuthInvalidGrant as e:
    print(f"Error: {e.error}, Description: {e.error_description}")
except OAuthError as e:
    print(f"Error: {e.error}")
```

## Tests

```bash
cd backend
pytest tests/auth/oauth/test_service.py -v

# Run specific test
pytest tests/auth/oauth/test_service.py::TestTokenExchange::test_exchange_authorization_code_success -v
```

## Documentation

- **README.md**: Overview and quick start
- **CONFIG.md**: Detailed configuration guide
- **IMPLEMENTATION_GUIDE.md**: Architecture and integration guide

## Common Tasks

### Test OAuth Flow
1. Register client: `oauth_service.register_client(...)`
2. Create code: `oauth_service.create_authorization_code(...)`
3. Exchange code: `oauth_service.exchange_authorization_code(...)`
4. Refresh token: `oauth_service.refresh_access_token(...)`

### Verify Token
```python
from backend.auth.core.jwt_utils import verify_token

payload = verify_token(access_token, expected_type="access")
user_id = payload.user_id
expiration = payload.expires_at
```

### Decode Token (No Verification)
```python
from backend.auth.core.jwt_utils import decode_token

payload = decode_token(token, verify=False)
```

## Key Constraints
- ❌ No RBAC
- ❌ No middleware
- ❌ No audit logging
- ✅ Standards-compliant OAuth2/OIDC

## Integration
OAuth router is registered in `backend/auth/router.py`:
```python
from backend.auth.oauth.api import router as oauth_router
router.include_router(oauth_router)
```

JWKS endpoint in `backend/app/api/router.py`:
```python
from backend.app.api.routes.wellknown import router as wellknown_router
api_router.include_router(wellknown_router)
```

## Production Checklist
- [ ] Change `CLM_JWT_SECRET_KEY`
- [ ] Use RS256 algorithm
- [ ] Persist OAuth clients to database
- [ ] Persist authorization codes to database
- [ ] Enforce HTTPS
- [ ] Add rate limiting
- [ ] Implement user authentication
- [ ] Add consent screen
- [ ] Enable PKCE for public clients

## References
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
