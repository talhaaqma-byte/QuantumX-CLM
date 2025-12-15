# JWT Dependencies - Quick Start Guide

⚡ **Get started with JWT authentication in 60 seconds**

## Basic Usage

### 1. Protect an Endpoint

```python
from fastapi import APIRouter, Depends
from backend.auth.deps import get_current_user, UserContext

router = APIRouter()

@router.get("/protected")
async def protected_endpoint(user: UserContext = Depends(get_current_user)):
    return {"user_id": str(user.user_id)}
```

### 2. Generate a Test Token

```python
from uuid import uuid4
from backend.auth.core.jwt_utils import create_access_token

user_id = uuid4()
token = create_access_token(user_id)
print(f"Token: {token}")
```

### 3. Make a Request

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/protected
```

## Common Patterns

### Protected Endpoint
```python
@router.get("/data")
async def get_data(user: UserContext = Depends(get_current_user)):
    return {"data": "sensitive", "user": str(user.user_id)}
```

### Optional Authentication
```python
@router.get("/content")
async def get_content(user: UserContext | None = Depends(get_optional_user)):
    if user:
        return {"type": "personalized", "user": str(user.user_id)}
    return {"type": "public"}
```

### Token Refresh
```python
@router.post("/refresh")
async def refresh_tokens(user: UserContext = Depends(get_current_user_refresh)):
    new_token = create_access_token(user.user_id)
    return {"access_token": new_token}
```

### Access Custom Claims
```python
@router.get("/admin")
async def admin_area(user: UserContext = Depends(get_current_user)):
    role = user.claims.get("role", "user")
    if role != "admin":
        raise HTTPException(403, "Admin required")
    return {"message": "Admin area"}
```

### Create Token with Custom Claims
```python
token = create_access_token(
    user_id,
    additional_claims={
        "username": "john",
        "role": "admin",
        "org_id": "org123"
    }
)
```

## Available Dependencies

| Dependency | Purpose | Returns |
|------------|---------|---------|
| `get_current_user()` | Validate access token | `UserContext` |
| `get_current_user_refresh()` | Validate refresh token | `UserContext` |
| `get_optional_user()` | Optional authentication | `UserContext \| None` |
| `get_token_from_header()` | Extract raw token | `str` |

## UserContext Properties

```python
user.user_id          # UUID - User identifier
user.token_type       # str - "access" or "refresh"
user.issued_at        # datetime - Token issue time
user.expires_at       # datetime - Token expiration time
user.claims           # dict - Custom claims
```

## Error Responses

| Error | Status | Response |
|-------|--------|----------|
| No token | 401 | `{"detail": "Not authenticated"}` |
| Expired | 401 | `{"detail": "Token has expired"}` |
| Invalid | 401 | `{"detail": "Invalid token: ..."}` |

## Testing

### Run Tests
```bash
cd backend
pytest tests/auth/core/test_deps.py -v
```

### Test with cURL
```bash
# Generate token
python3 -c "from uuid import uuid4; from backend.auth.core.jwt_utils import create_access_token; print(create_access_token(uuid4()))"

# Use token
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/endpoint
```

### Test with Python
```python
import requests

token = "YOUR_TOKEN"
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://localhost:8000/api/endpoint", headers=headers)
print(response.json())
```

## Configuration

Set these environment variables:

```bash
CLM_JWT_SECRET_KEY=your-secret-key-here
CLM_JWT_ALGORITHM=HS256
CLM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
CLM_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

## Complete Example

```python
from fastapi import APIRouter, Depends, HTTPException
from backend.auth.deps import get_current_user, UserContext
from backend.auth.core.jwt_utils import create_access_token
from uuid import uuid4

router = APIRouter()

@router.post("/login")
async def login(username: str, password: str):
    # Validate credentials (implement your logic)
    user_id = uuid4()
    
    token = create_access_token(
        user_id,
        additional_claims={"username": username}
    )
    
    return {
        "access_token": token,
        "token_type": "bearer"
    }

@router.get("/me")
async def get_current_user_info(user: UserContext = Depends(get_current_user)):
    return {
        "user_id": str(user.user_id),
        "username": user.claims.get("username"),
        "expires_at": user.expires_at.isoformat()
    }

@router.get("/public")
async def public_endpoint():
    return {"message": "Public content"}

@router.get("/flexible")
async def flexible_endpoint(user: UserContext | None = Depends(get_optional_user)):
    if user:
        return {"message": f"Hello {user.claims.get('username', 'user')}"}
    return {"message": "Hello anonymous"}
```

## Documentation

- 📘 Full API Reference: `backend/auth/DEPS_README.md`
- 🚀 Integration Guide: `backend/auth/INTEGRATION_GUIDE.md`
- 💡 Usage Examples: `backend/auth/deps_examples.py`
- 📊 Summary: `backend/auth/JWT_DEPENDENCIES_SUMMARY.md`

## Troubleshooting

### Token not working?
```python
# Verify token
from backend.auth.core.jwt_utils import verify_token
payload = verify_token("YOUR_TOKEN")
print(payload)
```

### Check expiration
```python
from backend.auth.core.jwt_utils import get_token_expiration
exp = get_token_expiration("YOUR_TOKEN")
print(f"Expires: {exp}")
```

### Debug claims
```python
from backend.auth.core.jwt_utils import decode_token
claims = decode_token("YOUR_TOKEN", verify=False)
print(claims)
```

## Next Steps

1. ✅ Import dependencies in your routes
2. ✅ Add authentication to endpoints
3. ✅ Generate tokens in login endpoint
4. ✅ Test with cURL or Python
5. ✅ Add custom claims as needed
6. ✅ Implement authorization logic

---

**Need help?** Check the full documentation or run tests to see working examples.
