# JWT Dependencies Integration Guide

Quick guide for integrating JWT authentication dependencies into your FastAPI routes.

## Quick Start

### 1. Import Dependencies

```python
from fastapi import APIRouter, Depends
from backend.auth.deps import get_current_user, UserContext
```

### 2. Add to Your Route

```python
router = APIRouter()

@router.get("/protected")
async def protected_resource(user: UserContext = Depends(get_current_user)):
    return {"user_id": str(user.user_id)}
```

### 3. Test Your Route

```python
# Generate a token
from uuid import uuid4
from backend.auth.core.jwt_utils import create_access_token

user_id = uuid4()
token = create_access_token(user_id)

# Make request
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/protected
```

## Complete Example

Here's a complete working example with multiple endpoints:

```python
"""
Example router showing JWT authentication integration.
File: backend/app/routes/example.py
"""

from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, status
from backend.auth.deps import (
    get_current_user,
    get_current_user_refresh,
    get_optional_user,
    UserContext,
)
from backend.auth.core.jwt_utils import (
    create_access_token,
    create_refresh_token,
)

router = APIRouter(prefix="/api/example", tags=["example"])


@router.get("/public")
async def public_endpoint():
    """Public endpoint - no authentication required."""
    return {"message": "This is public"}


@router.get("/protected")
async def protected_endpoint(user: UserContext = Depends(get_current_user)):
    """Protected endpoint - authentication required."""
    return {
        "message": "Access granted",
        "user_id": str(user.user_id),
        "token_issued": user.issued_at.isoformat(),
    }


@router.get("/flexible")
async def flexible_endpoint(user: UserContext | None = Depends(get_optional_user)):
    """Flexible endpoint - works with or without authentication."""
    if user:
        return {
            "type": "authenticated",
            "user_id": str(user.user_id),
        }
    return {"type": "anonymous"}


@router.post("/auth/refresh")
async def refresh_endpoint(user: UserContext = Depends(get_current_user_refresh)):
    """Token refresh endpoint - requires refresh token."""
    new_access = create_access_token(user.user_id)
    new_refresh = create_refresh_token(user.user_id)
    
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


@router.get("/admin")
async def admin_endpoint(user: UserContext = Depends(get_current_user)):
    """Admin-only endpoint - checks role from custom claims."""
    role = user.claims.get("role", "user")
    
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return {"message": "Admin area", "user_id": str(user.user_id)}


@router.get("/me")
async def get_profile(user: UserContext = Depends(get_current_user)):
    """Get current user's profile."""
    return {
        "user_id": str(user.user_id),
        "token_type": user.token_type,
        "issued_at": user.issued_at.isoformat(),
        "expires_at": user.expires_at.isoformat(),
        "custom_claims": user.claims,
    }
```

## Register Router in Main App

Add to `backend/app/main.py`:

```python
from backend.app.routes import example

app = FastAPI(title="CLM Platform")

# Register routers
app.include_router(example.router)
```

## Testing Authentication Flow

### 1. Generate Tokens

```python
from uuid import uuid4
from backend.auth.core.jwt_utils import create_access_token, create_refresh_token

# Create user ID
user_id = uuid4()

# Create access token with custom claims
access_token = create_access_token(
    user_id,
    additional_claims={
        "username": "john_doe",
        "role": "admin",
        "org_id": "org123",
    }
)

# Create refresh token
refresh_token = create_refresh_token(user_id)

print(f"Access Token: {access_token}")
print(f"Refresh Token: {refresh_token}")
```

### 2. Test with cURL

```bash
# Public endpoint (no auth)
curl http://localhost:8000/api/example/public

# Protected endpoint (with auth)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8000/api/example/protected

# Refresh tokens (with refresh token)
curl -X POST \
     -H "Authorization: Bearer YOUR_REFRESH_TOKEN" \
     http://localhost:8000/api/example/auth/refresh

# Flexible endpoint (works both ways)
curl http://localhost:8000/api/example/flexible
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8000/api/example/flexible
```

### 3. Test with Python Requests

```python
import requests

base_url = "http://localhost:8000/api/example"
headers = {"Authorization": f"Bearer {access_token}"}

# Public endpoint
response = requests.get(f"{base_url}/public")
print(response.json())

# Protected endpoint
response = requests.get(f"{base_url}/protected", headers=headers)
print(response.json())

# Get profile
response = requests.get(f"{base_url}/me", headers=headers)
print(response.json())
```

## Common Patterns

### Pattern 1: Database Integration

```python
from sqlalchemy.ext.asyncio import AsyncSession
from backend.common.deps import get_core_session

@router.get("/users/me/details")
async def get_user_details(
    user: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_core_session),
):
    # Use user.user_id to fetch from database
    # query = select(User).where(User.id == user.user_id)
    # result = await db.execute(query)
    # user_record = result.scalar_one_or_none()
    
    return {"user_id": str(user.user_id)}
```

### Pattern 2: Role-Based Authorization

```python
from enum import Enum

class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"

def require_role(required_role: Role):
    """Dependency factory for role-based access control."""
    async def check_role(user: UserContext = Depends(get_current_user)):
        role = user.claims.get("role", "user")
        
        if role != required_role.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role.value}' required"
            )
        
        return user
    
    return check_role

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: UserContext = Depends(require_role(Role.ADMIN)),
):
    return {"message": f"User {user_id} deleted by {admin.user_id}"}
```

### Pattern 3: Organization Scoping

```python
@router.get("/organizations/data")
async def get_org_data(user: UserContext = Depends(get_current_user)):
    org_id = user.claims.get("org_id")
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not associated with organization"
        )
    
    # Fetch data scoped to this organization
    return {"org_id": org_id, "user_id": str(user.user_id)}
```

### Pattern 4: Rate Limiting by User

```python
from collections import defaultdict
from datetime import datetime, timedelta

# Simple in-memory rate limiter (use Redis in production)
rate_limit_store = defaultdict(list)

async def rate_limit(user: UserContext = Depends(get_current_user)):
    """Rate limit: 100 requests per minute per user."""
    user_id = str(user.user_id)
    now = datetime.now()
    minute_ago = now - timedelta(minutes=1)
    
    # Clean old requests
    rate_limit_store[user_id] = [
        ts for ts in rate_limit_store[user_id] if ts > minute_ago
    ]
    
    if len(rate_limit_store[user_id]) >= 100:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    rate_limit_store[user_id].append(now)
    return user

@router.get("/limited")
async def rate_limited_endpoint(user: UserContext = Depends(rate_limit)):
    return {"message": "Request processed"}
```

## Error Handling

The dependencies automatically handle authentication errors:

| Error | Status | Response |
|-------|--------|----------|
| No token | 401 | `{"detail": "Not authenticated"}` |
| Expired token | 401 | `{"detail": "Token has expired"}` |
| Invalid token | 401 | `{"detail": "Invalid token: ..."}` |
| Wrong token type | 401 | `{"detail": "Invalid token type..."}` |

### Custom Error Handling

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return JSONResponse(
            status_code=401,
            content={
                "error": "authentication_failed",
                "message": exc.detail,
                "timestamp": datetime.now().isoformat(),
            },
            headers=exc.headers,
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
```

## Best Practices

1. **Always use `get_current_user` for protected endpoints**
   - Don't manually parse tokens
   - Let the dependency handle validation

2. **Use `get_optional_user` for flexible endpoints**
   - Public content with personalization
   - Anonymous + authenticated users

3. **Use `get_current_user_refresh` only for token refresh**
   - Never accept refresh tokens for regular endpoints
   - Keep refresh logic separate

4. **Store sensitive data in custom claims carefully**
   - Tokens are readable by anyone with the token
   - Don't store passwords or secrets
   - Include only necessary information

5. **Implement proper authorization after authentication**
   - Check roles/permissions from claims
   - Validate resource ownership
   - Use database lookups when needed

6. **Handle token expiration gracefully**
   - Frontend should refresh tokens before expiry
   - Implement refresh token rotation
   - Clear expired tokens from client

## OpenAPI/Swagger Integration

The dependencies automatically integrate with FastAPI's OpenAPI docs:

1. Navigate to `http://localhost:8000/docs`
2. Click "Authorize" button
3. Enter: `Bearer YOUR_TOKEN`
4. Test protected endpoints directly

## Security Considerations

1. **HTTPS Only**: Always use HTTPS in production
2. **Secret Key**: Change `CLM_JWT_SECRET_KEY` in production
3. **Token Storage**: Store tokens securely on client (not in localStorage)
4. **Token Lifetime**: Use short-lived access tokens
5. **Refresh Rotation**: Implement refresh token rotation
6. **Revocation**: Consider token revocation lists for critical operations

## Next Steps

1. Implement login endpoint to generate tokens
2. Add database user lookup after token validation
3. Implement role and permission checks
4. Add refresh token rotation
5. Implement token revocation
6. Add audit logging for authentication events

## Troubleshooting

### "Not authenticated" error

```bash
# Check token format
curl -v -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/protected

# Verify token is valid
python3 -c "from backend.auth.core.jwt_utils import verify_token; print(verify_token('YOUR_TOKEN'))"
```

### "Token has expired" error

```python
# Check token expiration
from backend.auth.core.jwt_utils import get_token_expiration
exp = get_token_expiration("YOUR_TOKEN")
print(f"Expires at: {exp}")
```

### Custom claims not appearing

```python
# Verify claims are in token
from backend.auth.core.jwt_utils import decode_token
payload = decode_token("YOUR_TOKEN", verify=False)
print(payload)
```

## Additional Resources

- Full API documentation: `backend/auth/DEPS_README.md`
- Usage examples: `backend/auth/deps_examples.py`
- JWT utilities: `backend/auth/core/jwt_utils.py`
- Tests: `backend/tests/auth/core/test_deps.py`
