# JWT Dependencies Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        FastAPI Application                       │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       API Endpoint Layer                         │
│                                                                  │
│  @router.get("/protected")                                       │
│  async def endpoint(user: UserContext = Depends(...))            │
└─────────────────────────┬───────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│get_current   │  │get_current   │  │get_optional  │
│_user()       │  │_user_refresh │  │_user()       │
│              │  │()            │  │              │
│Access Token  │  │Refresh Token │  │Optional Auth │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │   get_token_from_header()      │
        │                                │
        │ HTTPBearer Security Scheme     │
        │ Extracts: "Bearer <token>"     │
        └────────────────┬───────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │      JWT Validation Layer      │
        │                                │
        │  1. verify_token()             │
        │     - Signature check          │
        │     - Expiration check         │
        │     - Type validation          │
        │                                │
        │  2. decode_token()             │
        │     - Extract custom claims    │
        └────────────────┬───────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │      UserContext Creation      │
        │                                │
        │  UserContext(                  │
        │    user_id: UUID,              │
        │    token_type: str,            │
        │    issued_at: datetime,        │
        │    expires_at: datetime,       │
        │    claims: dict                │
        │  )                             │
        └────────────────┬───────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │   Return to Endpoint Handler   │
        │                                │
        │   user.user_id → UUID          │
        │   user.claims → dict           │
        │   user.expires_at → datetime   │
        └────────────────────────────────┘
```

## Component Breakdown

### 1. Security Layer (HTTPBearer)

```python
security = HTTPBearer(auto_error=False)
```

**Purpose:** Extract Bearer token from Authorization header
**Input:** HTTP Request with `Authorization: Bearer <token>`
**Output:** `HTTPAuthorizationCredentials` or `None`

### 2. Token Extraction

```python
async def get_token_from_header(
    credentials: HTTPAuthorizationCredentials | None = Depends(security)
) -> str:
```

**Purpose:** Extract raw token string
**Raises:** `HTTPException(401)` if no token
**Returns:** Token string

### 3. Token Validation Dependencies

#### get_current_user()
```python
async def get_current_user(
    token: str = Depends(get_token_from_header)
) -> UserContext:
```

- ✅ Validates access tokens only
- ✅ Checks signature and expiration
- ✅ Extracts custom claims
- ❌ Rejects refresh tokens

#### get_current_user_refresh()
```python
async def get_current_user_refresh(
    token: str = Depends(get_token_from_header)
) -> UserContext:
```

- ✅ Validates refresh tokens only
- ✅ Checks signature and expiration
- ✅ Extracts custom claims
- ❌ Rejects access tokens

#### get_optional_user()
```python
async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security)
) -> UserContext | None:
```

- ✅ Returns `None` if no token
- ✅ Validates if token provided
- ✅ Still raises errors for invalid tokens

### 4. UserContext Model

```python
class UserContext(BaseModel):
    user_id: UUID
    token_type: str
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any]
```

**Purpose:** Type-safe container for user identity
**Features:**
- Pydantic validation
- Easy attribute access
- Datetime handling
- Custom claims support

## Data Flow

### Successful Authentication Flow

```
1. Client sends request
   GET /api/protected
   Authorization: Bearer eyJhbGc...

2. HTTPBearer extracts token
   → credentials.credentials = "eyJhbGc..."

3. get_token_from_header() returns token
   → token = "eyJhbGc..."

4. get_current_user() validates
   → verify_token(token, "access")
   → decode_token(token, verify=False)

5. UserContext created
   → UserContext(user_id=UUID(...), ...)

6. Handler receives user
   → async def endpoint(user: UserContext)

7. Response sent
   → {"user_id": "...", "data": "..."}
```

### Error Flow

```
1. Client sends request (no token)
   GET /api/protected

2. HTTPBearer returns None
   → credentials = None

3. get_token_from_header() raises
   → HTTPException(401, "Not authenticated")

4. FastAPI returns error
   → {"detail": "Not authenticated"}
   → Status: 401
   → Header: WWW-Authenticate: Bearer
```

## Integration with JWT Utils

```
┌─────────────────────────────────────────────┐
│          backend/auth/core/jwt_utils.py      │
│                                              │
│  create_access_token(user_id, claims)       │
│         │                                    │
│         ▼                                    │
│    JWT Token (signed, with claims)          │
│         │                                    │
│         ▼                                    │
│  verify_token(token, expected_type)         │
│         │                                    │
│         ▼                                    │
│    TokenPayload (validated)                 │
└─────────────────────────────────────────────┘
                    │
                    │ Used by
                    ▼
┌─────────────────────────────────────────────┐
│          backend/auth/deps.py                │
│                                              │
│  get_current_user()                          │
│  get_current_user_refresh()                  │
│  get_optional_user()                         │
│         │                                    │
│         ▼                                    │
│    UserContext (with claims)                │
└─────────────────────────────────────────────┘
                    │
                    │ Used in
                    ▼
┌─────────────────────────────────────────────┐
│          FastAPI Route Handlers              │
│                                              │
│  @router.get("/endpoint")                    │
│  async def handler(user: UserContext):       │
│      # Use user.user_id, user.claims         │
└─────────────────────────────────────────────┘
```

## Token Types

### Access Token Flow

```
Login → create_access_token() → JWT Token
                                     │
                                     ▼
Client Request → Authorization: Bearer <token>
                                     │
                                     ▼
                         get_current_user()
                                     │
                                     ▼
                              UserContext
                                     │
                                     ▼
                           Protected Resource
```

### Refresh Token Flow

```
Login → create_refresh_token() → JWT Token
                                      │
                                      ▼
Client Request → Authorization: Bearer <token>
                                      │
                                      ▼
                      get_current_user_refresh()
                                      │
                                      ▼
                               UserContext
                                      │
                                      ▼
                    create_access_token(user.user_id)
                                      │
                                      ▼
                              New Access Token
```

## Error Handling Matrix

| Scenario | Dependency | Status | Response |
|----------|------------|--------|----------|
| No token | `get_current_user()` | 401 | "Not authenticated" |
| No token | `get_optional_user()` | 200 | `None` |
| Expired token | `get_current_user()` | 401 | "Token has expired" |
| Invalid signature | `get_current_user()` | 401 | "Invalid token: ..." |
| Wrong type (refresh) | `get_current_user()` | 401 | "Invalid token type..." |
| Wrong type (access) | `get_current_user_refresh()` | 401 | "Invalid token type..." |
| Malformed token | `get_current_user()` | 401 | "Invalid token: ..." |

## Security Layers

```
┌─────────────────────────────────────────┐
│  Layer 1: Transport Security (HTTPS)    │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Layer 2: Token Extraction (HTTPBearer) │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Layer 3: Signature Verification (JWT)  │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Layer 4: Expiration Check              │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Layer 5: Token Type Validation         │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Layer 6: UserContext Creation          │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│  Layer 7: Authorization (in handler)    │
└─────────────────────────────────────────┘
```

## Dependency Injection Flow

```
FastAPI Dependency Resolution:

1. FastAPI sees: Depends(get_current_user)
2. get_current_user needs: Depends(get_token_from_header)
3. get_token_from_header needs: Depends(security)
4. security extracts: Authorization header
5. Chain resolves bottom-up:
   security → token → validation → UserContext
6. Handler receives: user: UserContext
```

## Testing Architecture

```
┌─────────────────────────────────────────┐
│     backend/tests/auth/core/            │
│                                         │
│  test_deps.py (25 tests)               │
│                                         │
│  ├─ TestGetTokenFromHeader (2)         │
│  ├─ TestUserContext (2)                │
│  ├─ TestGetCurrentUser (7)             │
│  ├─ TestGetCurrentUserRefresh (5)      │
│  ├─ TestGetOptionalUser (5)            │
│  └─ TestIntegration (4)                │
│                                         │
│  Coverage:                              │
│  ✅ Valid tokens                        │
│  ✅ Invalid tokens                      │
│  ✅ Expired tokens                      │
│  ✅ Wrong token types                   │
│  ✅ Custom claims                       │
│  ✅ Error handling                      │
└─────────────────────────────────────────┘
```

## Performance Considerations

### Time Complexity

- Token extraction: O(1)
- Token validation: O(1)
- Claim extraction: O(n) where n = number of claims
- UserContext creation: O(1)

**Total per request:** O(n) where n is typically < 10

### Space Complexity

- Token string: ~200-500 bytes
- Decoded payload: ~100-300 bytes
- UserContext: ~200 bytes

**Total per request:** < 1KB

### Optimization Strategies

1. **No database calls** - Pure token validation
2. **Single verification** - Token verified once
3. **Lazy evaluation** - Only validates when dependency used
4. **Stateless** - No session storage required
5. **Cacheable** - Can add token caching layer

## Extension Points

### 1. Add Token Caching

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def cached_verify_token(token: str) -> TokenPayload:
    return verify_token(token)
```

### 2. Add Database User Lookup

```python
async def get_current_user_with_db(
    user: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_core_session),
):
    # Fetch user from database
    query = select(User).where(User.id == user.user_id)
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()
    return db_user
```

### 3. Add Role-Based Authorization

```python
def require_role(role: str):
    async def check_role(user: UserContext = Depends(get_current_user)):
        if user.claims.get("role") != role:
            raise HTTPException(403, "Insufficient permissions")
        return user
    return check_role
```

### 4. Add Token Revocation Check

```python
async def get_current_user_not_revoked(
    user: UserContext = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
):
    # Check revocation list
    if await redis.get(f"revoked:{user.user_id}"):
        raise HTTPException(401, "Token revoked")
    return user
```

## Summary

The JWT dependencies architecture provides:

- ✅ Clean separation of concerns
- ✅ Type-safe user context
- ✅ Comprehensive error handling
- ✅ Multiple authentication patterns
- ✅ Easy integration with FastAPI
- ✅ Extensible design
- ✅ Production-ready implementation

All components work together to provide a robust, secure, and maintainable authentication system.
