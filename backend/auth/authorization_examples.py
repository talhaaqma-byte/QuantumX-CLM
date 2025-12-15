from fastapi import APIRouter, Depends

from backend.auth.authorization import require_permission, require_role
from backend.auth.deps import UserContext, get_current_user

# Create a router to demonstrate authorization usage
router = APIRouter(prefix="/protected-resources", tags=["Authorization Examples"])


@router.get("/public")
async def public_endpoint():
    """
    Endpoint accessible to everyone (no auth required).
    """
    return {"message": "Public access allowed"}


@router.get("/authenticated")
async def authenticated_only(user: UserContext = Depends(get_current_user)):
    """
    Endpoint accessible to any authenticated user.
    """
    return {"message": f"Hello {user.user_id}, you are authenticated"}


@router.get(
    "/admin-only",
    dependencies=[Depends(require_role("admin"))]
)
async def admin_dashboard():
    """
    Endpoint accessible only to users with 'admin' role.
    """
    return {"message": "Welcome to the admin dashboard"}


@router.get(
    "/users:read",
    dependencies=[Depends(require_permission("users:read"))]
)
async def list_users():
    """
    Endpoint accessible to users with 'users:read' permission.
    """
    return {"message": "Listing users..."}


@router.post(
    "/users:write",
    dependencies=[Depends(require_permission("users:write"))]
)
async def create_user():
    """
    Endpoint accessible to users with 'users:write' permission.
    """
    return {"message": "Creating user..."}


@router.get("/combined-check")
async def complex_check(
    user: UserContext = Depends(require_permission("audit:read")),
):
    """
    Endpoint that requires permission and uses the user context.
    The require_permission dependency returns the UserContext.
    """
    return {
        "message": "You have audit:read permission",
        "user_id": str(user.user_id)
    }
