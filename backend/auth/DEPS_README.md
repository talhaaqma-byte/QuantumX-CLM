# JWT Authentication Dependencies

FastAPI dependencies for extracting and validating user identity from JWT tokens.

## Overview

The `backend/auth/deps.py` module provides reusable FastAPI dependencies that handle JWT token extraction, validation, and user context creation. These dependencies follow the FastAPI dependency injection pattern and integrate seamlessly with the existing JWT utilities.

## Dependencies

### `get_token_from_header()`

Extracts JWT token from the Authorization header.

**Returns:** `str` - The JWT token string

**Raises:** `HTTPException(401)` if no token provided

**Usage:**
```python
@router.get("/raw-token")
async def example(token: str = Depends(get_token_from_header)):
    return {"token_length": len(token)}
```

---

### `get_current_user()`

Validates JWT access token and returns user context.

**Returns:** `UserContext` - User identity and token metadata

**Raises:** 
- `HTTPException(401)` if token is invalid
- `HTTPException(401)` if token is expired
- `HTTPException(401)` if token is not an access token

**Usage:**
```python
@router.get("/protected")
async def example(user: UserContext = Depends(get_current_user)):
    return {
        "user_id": str(user.user_id),
        "issued_at": user.issued_at.isoformat()
    }
```

---

### `get_current_user_refresh()`

Validates JWT refresh token and returns user context.

**Returns:** `UserContext` - User identity and token metadata

**Raises:** 
- `HTTPException(401)` if token is invalid
- `HTTPException(401)` if token is expired
- `HTTPException(401)` if token is not a refresh token

**Usage:**
```python
@router.post("/refresh")
async def example(user: UserContext = Depends(get_current_user_refresh)):
    new_access = create_access_token(user.user_id)
    return {"access_token": new_access}
```

---

### `get_optional_user()`

Optionally validates JWT access token. Returns `None` if no token provided, but still validates if a token is present.

**Returns:** `UserContext | None` - User context or None

**Raises:** `HTTPException(401)` if token is provided but invalid

**Usage:**
```python
@router.get("/flexible")
async def example(user: UserContext | None = Depends(get_optional_user)):
    if user:
        return {"message": f"Hello {user.user_id}"}
    return {"message": "Hello anonymous"}
```

## UserContext Model

The `UserContext` model provides structured access to user identity and token metadata:

```python
class UserContext(BaseModel):
    user_id: UUID           # User identifier from token subject
    token_type: str         # "access" or "refresh"
    issued_at: datetime     # When token was issued (UTC)
    expires_at: datetime    # When token expires (UTC)
    claims: dict[str, Any]  # Additional custom claims
```

### Accessing Custom Claims

Custom claims added during token creation are available in the `claims` dictionary:

```python
# Creating token with custom claims
token = create_access_token(
    user_id=user_id,
    additional_claims={
        "username": "john_doe",
        "org_id": "org123",
        "role": "admin",
    }
)

# Accessing claims in endpoint
@router.get("/example")
async def example(user: UserContext = Depends(get_current_user)):
    username = user.claims.get("username")
    org_id = user.claims.get("org_id")
    role = user.claims.get("role", "user")  # with default
    
    return {
        "user_id": str(user.user_id),
        "username": username,
        "org_id": org_id,
        "role": role,
    }
```

## Common Patterns

### Basic Authentication

Require authentication for an endpoint:

```python
from fastapi import APIRouter, Depends
from backend.auth.deps import get_current_user, UserContext

router = APIRouter()

@router.get("/protected")
async def protected_resource(user: UserContext = Depends(get_current_user)):
    return {"message": "Access granted", "user_id": str(user.user_id)}
```

### Optional Authentication

Allow both authenticated and anonymous access:

```python
@router.get("/content")
async def get_content(user: UserContext | None = Depends(get_optional_user)):
    if user:
        # Return personalized content
        return {"content": "personalized", "user_id": str(user.user_id)}
    else:
        # Return public content
        return {"content": "public"}
```

### Token Refresh

Use refresh tokens to generate new access tokens:

```python
from backend.auth.core.jwt_utils import create_access_token, create_refresh_token
from backend.auth.deps import get_current_user_refresh

@router.post("/auth/refresh")
async def refresh_tokens(user: UserContext = Depends(get_current_user_refresh)):
    # This dependency ensures only valid refresh tokens are accepted
    new_access_token = create_access_token(user.user_id)
    new_refresh_token = create_refresh_token(user.user_id)
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }
```

### Custom Authorization Logic

Implement custom authorization based on token claims:

```python
from fastapi import HTTPException, status

@router.get("/admin/dashboard")
async def admin_dashboard(user: UserContext = Depends(get_current_user)):
    # Check role from custom claims
    role = user.claims.get("role", "user")
    
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return {"message": "Admin dashboard", "user_id": str(user.user_id)}
```

### Multiple Dependencies

Combine authentication with other dependencies:

```python
from sqlalchemy.ext.asyncio import AsyncSession
from backend.common.deps import get_core_session

@router.get("/users/me/profile")
async def get_profile(
    user: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_core_session),
):
    # Fetch user profile from database
    # query = select(User).where(User.id == user.user_id)
    # result = await db.execute(query)
    # user_record = result.scalar_one_or_none()
    
    return {
        "user_id": str(user.user_id),
        "token_issued": user.issued_at.isoformat(),
    }
```

## Testing

### Manual Testing with cURL

1. Generate a token:
```python
from uuid import uuid4
from backend.auth.core.jwt_utils import create_access_token

user_id = uuid4()
token = create_access_token(user_id)
print(f"Token: {token}")
```

2. Make authenticated request:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/protected
```

3. Test without token (should fail):
```bash
curl http://localhost:8000/api/protected
# Expected: {"detail": "Not authenticated"}
```

### Testing with Python

```python
import requests
from uuid import uuid4
from backend.auth.core.jwt_utils import create_access_token

# Create token
user_id = uuid4()
token = create_access_token(user_id)

# Make request
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://localhost:8000/api/protected", headers=headers)
print(response.json())
```

### Unit Tests

Comprehensive unit tests are available in `backend/tests/auth/core/test_deps.py`:

```bash
# Run dependency tests
cd backend
pytest tests/auth/core/test_deps.py -v

# Run with coverage
pytest tests/auth/core/test_deps.py --cov=backend.auth.deps -v
```

## Error Handling

All dependencies raise `HTTPException` with appropriate status codes:

| Error | Status Code | Detail | Headers |
|-------|-------------|--------|---------|
| No token | 401 | "Not authenticated" | `WWW-Authenticate: Bearer` |
| Token expired | 401 | "Token has expired" | `WWW-Authenticate: Bearer` |
| Invalid token | 401 | "Invalid token: ..." | `WWW-Authenticate: Bearer` |
| Wrong token type | 401 | "Invalid token type..." | `WWW-Authenticate: Bearer` |

Example error response:
```json
{
    "detail": "Token has expired"
}
```

## Security Considerations

1. **Token in Header Only**: Tokens must be in the Authorization header with Bearer scheme
2. **Token Type Validation**: Access and refresh tokens are validated separately
3. **Signature Verification**: All tokens are cryptographically verified
4. **Expiration Checks**: Expired tokens are rejected immediately
5. **No Token Storage**: Dependencies are stateless; no token storage in memory

## Configuration

Dependencies use settings from `backend/common/config.py`:

- `CLM_JWT_SECRET_KEY`: Secret key for token signing (MUST change in production)
- `CLM_JWT_ALGORITHM`: Signing algorithm (default: HS256)
- `CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES`: Access token lifetime (default: 60)
- `CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token lifetime (default: 7)

## Examples

See `backend/auth/deps_examples.py` for comprehensive usage examples including:
- Basic protected endpoints
- Optional authentication
- Token refresh flows
- Custom claims access
- Multiple dependencies
- Error handling patterns

## Integration with Existing Code

These dependencies integrate with:
- `backend/auth/core/jwt_utils.py` - JWT token utilities
- `backend/common/deps.py` - Database session dependencies
- `backend/common/config.py` - Application configuration

## Next Steps

To use these dependencies in your application:

1. Import the dependencies in your router:
   ```python
   from backend.auth.deps import get_current_user, UserContext
   ```

2. Add to your endpoint:
   ```python
   @router.get("/protected")
   async def endpoint(user: UserContext = Depends(get_current_user)):
       return {"user_id": str(user.user_id)}
   ```

3. Register your router in `backend/app/main.py`

4. Test with valid JWT tokens from `create_access_token()`

## Limitations

- **No RBAC**: Role-based access control must be implemented separately
- **No Middleware**: These are dependencies, not middleware
- **No Routes**: Route implementation is separate
- **No Database Lookups**: Dependencies only validate tokens; database queries are separate
- **Stateless**: No session management or token revocation lists
