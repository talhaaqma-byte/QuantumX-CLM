# Authentication Core Utilities

This directory contains core authentication utilities for the QuantumX-CLM platform.

## JWT Utilities (`jwt_utils.py`)

Pure Python JWT (JSON Web Token) utilities for token creation, verification, and expiration handling.

### Features

- **Token Creation**: Generate access and refresh tokens with custom claims
- **Token Verification**: Verify token signatures and validate claims
- **Expiration Handling**: Check token expiration and extract expiration timestamps
- **Type Safety**: Pydantic models for token payload validation
- **Custom Claims**: Support for additional custom claims in tokens
- **Configurable**: All settings configurable via environment variables

### Configuration

JWT settings are configured via environment variables (prefixed with `CLM_`):

```bash
# Secret key for signing tokens (REQUIRED - change in production!)
CLM_JWT_SECRET_KEY=your-secret-key-here

# JWT signing algorithm (default: HS256)
CLM_JWT_ALGORITHM=HS256

# Access token expiration in minutes (default: 60)
CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60

# Refresh token expiration in days (default: 7)
CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Usage Examples

#### Creating Tokens

```python
from uuid import uuid4
from datetime import timedelta
from backend.auth.core.jwt_utils import create_access_token, create_refresh_token

# Basic access token
user_id = uuid4()
access_token = create_access_token(user_id)

# Access token with custom claims
access_token = create_access_token(
    user_id,
    additional_claims={"role": "admin", "org_id": "org-123"}
)

# Access token with custom expiration
access_token = create_access_token(
    user_id,
    expires_delta=timedelta(hours=2)
)

# Refresh token
refresh_token = create_refresh_token(user_id)

# Refresh token with custom expiration
refresh_token = create_refresh_token(
    user_id,
    expires_delta=timedelta(days=30)
)
```

#### Verifying Tokens

```python
from backend.auth.core.jwt_utils import verify_token, TokenExpiredError, TokenInvalidError

try:
    # Verify access token
    payload = verify_token(token, expected_type="access")
    user_id = payload.user_id
    print(f"Token valid for user: {user_id}")
    
    # Check if token is expired
    if payload.is_expired():
        print("Token has expired")
    
except TokenExpiredError:
    print("Token has expired")
except TokenInvalidError as e:
    print(f"Invalid token: {e}")
```

#### Decoding Tokens

```python
from backend.auth.core.jwt_utils import decode_token

# Decode without verification (for inspection)
payload = decode_token(token, verify=False)
print(f"User ID: {payload['sub']}")
print(f"Token type: {payload['type']}")

# Decode with verification
payload = decode_token(token, verify=True)
```

#### Expiration Handling

```python
from backend.auth.core.jwt_utils import (
    get_token_expiration,
    is_token_expired,
    TokenInvalidError
)

try:
    # Get expiration timestamp
    expiration = get_token_expiration(token)
    print(f"Token expires at: {expiration}")
    
    # Check if expired
    if is_token_expired(token):
        print("Token has expired")
    else:
        print("Token is still valid")
        
except TokenInvalidError as e:
    print(f"Cannot process token: {e}")
```

#### Token Refresh Flow

```python
from backend.auth.core.jwt_utils import (
    create_access_token,
    create_refresh_token,
    verify_token,
    is_token_expired,
)

# Initial login - create both tokens
user_id = user.id
access_token = create_access_token(user_id)
refresh_token = create_refresh_token(user_id)

# Later - access token expires, use refresh token to get new access token
if is_token_expired(access_token):
    try:
        # Verify refresh token
        refresh_payload = verify_token(refresh_token, expected_type="refresh")
        
        # Create new access token
        new_access_token = create_access_token(refresh_payload.user_id)
        
    except (TokenExpiredError, TokenInvalidError):
        # Refresh token also expired/invalid - user needs to re-authenticate
        pass
```

### API Reference

#### Functions

##### `create_access_token(user_id, additional_claims=None, expires_delta=None)`

Create a JWT access token.

- **Parameters:**
  - `user_id` (UUID): User ID to include in token subject
  - `additional_claims` (dict, optional): Additional claims to include
  - `expires_delta` (timedelta, optional): Custom expiration time delta
- **Returns:** str - Encoded JWT access token

##### `create_refresh_token(user_id, additional_claims=None, expires_delta=None)`

Create a JWT refresh token.

- **Parameters:** Same as `create_access_token`
- **Returns:** str - Encoded JWT refresh token

##### `verify_token(token, expected_type="access")`

Verify and decode a JWT token.

- **Parameters:**
  - `token` (str): JWT token string to verify
  - `expected_type` (str): Expected token type ('access' or 'refresh')
- **Returns:** TokenPayload - Decoded and validated token payload
- **Raises:**
  - `TokenExpiredError`: If token has expired
  - `TokenInvalidError`: If token is invalid or type doesn't match

##### `decode_token(token, verify=False)`

Decode a JWT token (optionally without verification).

- **Parameters:**
  - `token` (str): JWT token string to decode
  - `verify` (bool): If True, verify signature and expiration
- **Returns:** dict - Decoded token payload
- **Raises:** `TokenInvalidError`: If token cannot be decoded

##### `get_token_expiration(token)`

Extract expiration timestamp from token.

- **Parameters:** `token` (str): JWT token string
- **Returns:** datetime - Expiration timestamp in UTC
- **Raises:** `TokenInvalidError`: If token cannot be decoded

##### `is_token_expired(token)`

Check if a token is expired.

- **Parameters:** `token` (str): JWT token string
- **Returns:** bool - True if expired, False otherwise

#### Models

##### `TokenPayload`

Pydantic model for JWT token payload.

**Fields:**
- `sub` (str): Subject (user ID)
- `exp` (int): Expiration timestamp (Unix time)
- `iat` (int): Issued at timestamp (Unix time)
- `type` (str): Token type ('access' or 'refresh')
- `jti` (str, optional): JWT ID (unique token identifier)

**Properties:**
- `user_id`: Get user ID as UUID
- `expires_at`: Get expiration datetime in UTC
- `issued_at`: Get issued at datetime in UTC

**Methods:**
- `is_expired()`: Check if token is expired

#### Exceptions

##### `JWTError`

Base exception for JWT-related errors.

##### `TokenExpiredError`

Raised when a token has expired.

##### `TokenInvalidError`

Raised when a token is invalid (bad signature, malformed, wrong type, etc.).

### Security Considerations

1. **Secret Key**: The JWT secret key (`CLM_JWT_SECRET_KEY`) MUST be:
   - Changed from the default in production
   - Kept secure and never committed to version control
   - Sufficiently long and random (at least 32 characters)
   - Rotated periodically

2. **Token Storage**: 
   - Access tokens should be stored securely (e.g., httpOnly cookies)
   - Refresh tokens should be stored even more securely
   - Never store tokens in localStorage in production

3. **Token Expiration**:
   - Use short expiration times for access tokens (default: 60 minutes)
   - Use longer expiration for refresh tokens (default: 7 days)
   - Implement token refresh flow to improve user experience

4. **HTTPS**: Always use HTTPS in production to prevent token interception

5. **Token Revocation**: For critical operations, implement a token blacklist/revocation mechanism

### Testing

Comprehensive unit tests are available in `backend/tests/auth/core/test_jwt_utils.py`.

Run tests with:
```bash
cd backend
pytest tests/auth/core/test_jwt_utils.py -v
```

Test coverage includes:
- Token creation (access and refresh)
- Token verification and validation
- Expiration handling
- Error cases and edge conditions
- Custom claims and expiration deltas
- Integration scenarios (token refresh flow)

### Dependencies

- **PyJWT**: JWT encoding/decoding library
- **Pydantic**: Data validation and settings management
