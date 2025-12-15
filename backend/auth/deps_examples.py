"""
Usage examples for JWT authentication dependencies.

This file demonstrates various ways to use the JWT authentication
dependencies in FastAPI routes. These are example patterns, not
production routes.

Note: These are examples only - they are not registered as actual API routes.
"""

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from backend.auth.core.jwt_utils import create_access_token, create_refresh_token
from backend.auth.deps import (
    UserContext,
    get_current_user,
    get_current_user_refresh,
    get_optional_user,
    get_token_from_header,
)

example_router = APIRouter()


# Example 1: Basic protected endpoint
@example_router.get("/api/protected")
async def protected_endpoint(user: UserContext = Depends(get_current_user)):
    """
    Basic protected endpoint that requires authentication.
    
    Returns user information from the validated token.
    """
    return {
        "message": "Access granted to protected resource",
        "user_id": str(user.user_id),
        "token_type": user.token_type,
        "issued_at": user.issued_at.isoformat(),
        "expires_at": user.expires_at.isoformat(),
    }


# Example 2: Get current user profile
@example_router.get("/api/me")
async def get_current_user_profile(user: UserContext = Depends(get_current_user)):
    """
    Get the authenticated user's profile information.
    
    In a real implementation, you would fetch user details from the database
    using user.user_id.
    """
    return {
        "user_id": str(user.user_id),
        "token_issued_at": user.issued_at.isoformat(),
        "token_expires_at": user.expires_at.isoformat(),
        "additional_claims": user.claims,
    }


# Example 3: Optional authentication
@example_router.get("/api/content")
async def get_content(user: UserContext | None = Depends(get_optional_user)):
    """
    Endpoint that works for both authenticated and anonymous users.
    
    Returns different content based on authentication status.
    """
    if user:
        return {
            "content_type": "personalized",
            "message": f"Personalized content for user {user.user_id}",
            "user_id": str(user.user_id),
        }
    else:
        return {
            "content_type": "public",
            "message": "Public content for anonymous users",
        }


# Example 4: Token refresh endpoint
@example_router.post("/api/auth/refresh")
async def refresh_token(user: UserContext = Depends(get_current_user_refresh)):
    """
    Refresh access token using a valid refresh token.
    
    This endpoint requires a refresh token (not an access token).
    Returns new access and refresh tokens.
    """
    new_access_token = create_access_token(user.user_id)
    new_refresh_token = create_refresh_token(user.user_id)
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


# Example 5: Working with custom claims
@example_router.get("/api/organization/data")
async def get_organization_data(user: UserContext = Depends(get_current_user)):
    """
    Access custom claims from the JWT token.
    
    If you include additional claims when creating tokens, they are
    available in user.claims dictionary.
    """
    org_id = user.claims.get("org_id")
    role = user.claims.get("role", "user")
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not associated with an organization",
        )
    
    return {
        "organization_id": org_id,
        "user_id": str(user.user_id),
        "role": role,
        "message": f"Organization data for {org_id}",
    }


# Example 6: Multiple dependencies
@example_router.post("/api/data/process")
async def process_data(
    user: UserContext = Depends(get_current_user),
    data: dict = None,
):
    """
    Endpoint with multiple dependencies including authentication.
    
    Combines user authentication with other dependencies.
    """
    return {
        "status": "processing",
        "user_id": str(user.user_id),
        "data_received": data is not None,
    }


# Example 7: Raw token extraction
@example_router.get("/api/token/info")
async def get_token_info(token: str = Depends(get_token_from_header)):
    """
    Get the raw token string without validation.
    
    Useful for debugging or when you need to pass the token to another service.
    Note: The token is still extracted but not validated in this example.
    """
    return {
        "token_length": len(token),
        "token_prefix": token[:20] + "..." if len(token) > 20 else token,
    }


# Example 8: Create login endpoint (generates tokens)
@example_router.post("/api/auth/login")
async def login(username: str, password: str):
    """
    Example login endpoint that generates JWT tokens.
    
    In a real implementation:
    1. Validate credentials against database
    2. Fetch user details
    3. Create tokens with appropriate claims
    
    This is a simplified example for demonstration.
    """
    user_id = uuid4()
    
    access_token = create_access_token(
        user_id=user_id,
        additional_claims={
            "username": username,
            "role": "user",
        }
    )
    
    refresh_token = create_refresh_token(user_id=user_id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


# Example 9: Validate token before expensive operation
@example_router.post("/api/expensive-operation")
async def expensive_operation(user: UserContext = Depends(get_current_user)):
    """
    Use authentication dependency to validate before expensive operations.
    
    The dependency will fail fast if authentication is invalid,
    preventing unnecessary processing.
    """
    return {
        "status": "started",
        "operation_id": str(uuid4()),
        "initiated_by": str(user.user_id),
    }


# Example 10: Combining with other FastAPI features
@example_router.get("/api/items/{item_id}")
async def get_item(
    item_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Combine path parameters, query parameters, and authentication.
    """
    return {
        "item_id": item_id,
        "owner_id": str(user.user_id),
        "message": f"Item {item_id} accessed by user {user.user_id}",
    }


"""
Testing the dependencies:

1. Generate a token:
   ```python
   from uuid import uuid4
   from backend.auth.core.jwt_utils import create_access_token
   
   user_id = uuid4()
   token = create_access_token(user_id)
   print(f"Token: {token}")
   ```

2. Make a request with the token:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN_HERE" http://localhost:8000/api/protected
   ```

3. Test with Python requests:
   ```python
   import requests
   
   token = "your_token_here"
   headers = {"Authorization": f"Bearer {token}"}
   
   response = requests.get("http://localhost:8000/api/protected", headers=headers)
   print(response.json())
   ```

4. Test without token (should fail):
   ```bash
   curl http://localhost:8000/api/protected
   # Returns: {"detail": "Not authenticated"}
   ```

5. Test optional authentication:
   ```bash
   # Without token - works
   curl http://localhost:8000/api/content
   
   # With token - works
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/content
   ```

6. Test refresh token endpoint:
   ```python
   from backend.auth.core.jwt_utils import create_refresh_token
   
   user_id = uuid4()
   refresh_token = create_refresh_token(user_id)
   
   headers = {"Authorization": f"Bearer {refresh_token}"}
   response = requests.post("http://localhost:8000/api/auth/refresh", headers=headers)
   print(response.json())
   ```
"""
