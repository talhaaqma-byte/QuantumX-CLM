"""
OAuth2/OpenID Connect provider implementation.

This module provides OAuth2/OIDC provider functionality including:
- Authorization code flow
- Token exchange
- JWKS (JSON Web Key Set) handling
"""

from __future__ import annotations

__all__ = [
    "oauth_service",
    "OAuthService",
]

from backend.auth.oauth.service import OAuthService

oauth_service = OAuthService()
