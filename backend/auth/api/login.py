"""
Login routes - placeholder for username/password authentication.

This module will contain endpoints for user authentication including:
- POST /auth/login - User login with username/password
- GET /auth/login/status - Check login session status (future)
- POST /auth/login/verify - Verify credentials without login (future)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/login", tags=["auth-login"])


@router.post("/")
async def login() -> dict:
    """
    Authenticate user with username and password.
    
    Placeholder endpoint - no logic implemented yet.
    
    Returns:
        dict: Authentication result
        
    Raises:
        HTTPException: When authentication fails or is not implemented
    """
    raise HTTPException(
        status_code=501,
        detail="Login functionality not yet implemented"
    )


@router.get("/status")
async def login_status() -> dict:
    """
    Check current login session status.
    
    Placeholder endpoint - no logic implemented yet.
    
    Returns:
        dict: Current session information
    """
    raise HTTPException(
        status_code=501,
        detail="Login status check not yet implemented"
    )


@router.post("/verify")
async def verify_credentials() -> dict:
    """
    Verify credentials without creating a session.
    
    Placeholder endpoint - no logic implemented yet.
    
    Returns:
        dict: Verification result
    """
    raise HTTPException(
        status_code=501,
        detail="Credential verification not yet implemented"
    )