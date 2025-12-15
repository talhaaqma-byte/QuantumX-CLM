"""
Demo script showcasing JWT utility functions.

This script demonstrates the key features of the jwt_utils module:
- Creating access and refresh tokens
- Verifying tokens
- Handling expiration
- Custom claims
- Error handling

Run with: python -m backend.auth.core.jwt_utils_demo
"""

from datetime import timedelta
from time import sleep
from uuid import uuid4

from backend.auth.core.jwt_utils import (
    JWTError,
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_expiration,
    is_token_expired,
    verify_token,
)


def demo_basic_token_creation():
    """Demonstrate basic token creation."""
    print("=" * 70)
    print("1. BASIC TOKEN CREATION")
    print("=" * 70)

    user_id = uuid4()
    print(f"User ID: {user_id}\n")

    access_token = create_access_token(user_id)
    print(f"Access Token: {access_token[:50]}...\n")

    refresh_token = create_refresh_token(user_id)
    print(f"Refresh Token: {refresh_token[:50]}...\n")


def demo_custom_claims():
    """Demonstrate tokens with custom claims."""
    print("=" * 70)
    print("2. TOKENS WITH CUSTOM CLAIMS")
    print("=" * 70)

    user_id = uuid4()
    custom_claims = {
        "role": "admin",
        "org_id": "org-12345",
        "permissions": ["read", "write", "delete"],
        "email": "admin@example.com",
    }

    token = create_access_token(user_id, additional_claims=custom_claims)
    print(f"Token created with custom claims\n")

    payload = decode_token(token, verify=False)
    print("Decoded payload:")
    for key, value in payload.items():
        if key not in ["sub", "exp", "iat", "type"]:
            print(f"  {key}: {value}")
    print()


def demo_token_verification():
    """Demonstrate token verification."""
    print("=" * 70)
    print("3. TOKEN VERIFICATION")
    print("=" * 70)

    user_id = uuid4()
    access_token = create_access_token(user_id)

    try:
        payload = verify_token(access_token, expected_type="access")
        print(f"✓ Token verified successfully")
        print(f"  User ID: {payload.user_id}")
        print(f"  Token type: {payload.type}")
        print(f"  Expires at: {payload.expires_at}")
        print(f"  Issued at: {payload.issued_at}")
        print(f"  Is expired: {payload.is_expired()}\n")
    except (TokenExpiredError, TokenInvalidError) as e:
        print(f"✗ Token verification failed: {e}\n")


def demo_wrong_token_type():
    """Demonstrate token type validation."""
    print("=" * 70)
    print("4. TOKEN TYPE VALIDATION")
    print("=" * 70)

    user_id = uuid4()
    access_token = create_access_token(user_id)

    print("Attempting to verify access token as refresh token...")
    try:
        verify_token(access_token, expected_type="refresh")
        print("✗ Should have failed!\n")
    except TokenInvalidError as e:
        print(f"✓ Correctly rejected: {e}\n")


def demo_expired_token():
    """Demonstrate expiration handling."""
    print("=" * 70)
    print("5. EXPIRATION HANDLING")
    print("=" * 70)

    user_id = uuid4()
    short_lived_token = create_access_token(
        user_id, expires_delta=timedelta(seconds=2)
    )

    print("Created token with 2-second expiration")
    print(f"Is expired: {is_token_expired(short_lived_token)}")

    print("Waiting 3 seconds...")
    sleep(3)

    print(f"Is expired: {is_token_expired(short_lived_token)}")

    try:
        verify_token(short_lived_token, expected_type="access")
        print("✗ Should have failed!\n")
    except TokenExpiredError as e:
        print(f"✓ Correctly detected expiration: {e}\n")


def demo_invalid_token():
    """Demonstrate handling of invalid tokens."""
    print("=" * 70)
    print("6. INVALID TOKEN HANDLING")
    print("=" * 70)

    invalid_tokens = [
        ("malformed.token", "Malformed token"),
        ("", "Empty token"),
        ("header.payload.badsignature", "Invalid signature"),
    ]

    for token, description in invalid_tokens:
        print(f"Testing: {description}")
        try:
            verify_token(token, expected_type="access")
            print("✗ Should have failed!")
        except TokenInvalidError as e:
            print(f"✓ Correctly rejected: {type(e).__name__}")
        print()


def demo_token_refresh_flow():
    """Demonstrate typical token refresh flow."""
    print("=" * 70)
    print("7. TOKEN REFRESH FLOW")
    print("=" * 70)

    user_id = uuid4()

    print("Step 1: Create initial tokens")
    old_access_token = create_access_token(user_id, expires_delta=timedelta(seconds=2))
    refresh_token = create_refresh_token(user_id)
    print(f"  Access token: {old_access_token[:30]}...")
    print(f"  Refresh token: {refresh_token[:30]}...\n")

    print("Step 2: Wait for access token to expire")
    sleep(3)
    print(f"  Access token expired: {is_token_expired(old_access_token)}")
    print(f"  Refresh token expired: {is_token_expired(refresh_token)}\n")

    print("Step 3: Use refresh token to get new access token")
    try:
        refresh_payload = verify_token(refresh_token, expected_type="refresh")
        new_access_token = create_access_token(refresh_payload.user_id)
        print(f"  ✓ New access token created: {new_access_token[:30]}...")
        print(f"  ✓ New token expired: {is_token_expired(new_access_token)}\n")
    except (TokenExpiredError, TokenInvalidError) as e:
        print(f"  ✗ Failed to refresh: {e}\n")


def demo_custom_expiration():
    """Demonstrate custom expiration times."""
    print("=" * 70)
    print("8. CUSTOM EXPIRATION TIMES")
    print("=" * 70)

    user_id = uuid4()

    tokens = [
        (timedelta(minutes=5), "5 minutes"),
        (timedelta(hours=2), "2 hours"),
        (timedelta(days=1), "1 day"),
        (timedelta(days=30), "30 days"),
    ]

    for delta, description in tokens:
        token = create_access_token(user_id, expires_delta=delta)
        expiration = get_token_expiration(token)
        print(f"Token with {description} expiration:")
        print(f"  Expires at: {expiration}")
        print(f"  Is expired: {is_token_expired(token)}\n")


def main():
    """Run all demonstrations."""
    print("\n")
    print("█" * 70)
    print("█" + " " * 68 + "█")
    print("█" + "  JWT UTILITIES DEMONSTRATION".center(68) + "█")
    print("█" + " " * 68 + "█")
    print("█" * 70)
    print("\n")

    try:
        demo_basic_token_creation()
        demo_custom_claims()
        demo_token_verification()
        demo_wrong_token_type()
        demo_expired_token()
        demo_invalid_token()
        demo_token_refresh_flow()
        demo_custom_expiration()

        print("=" * 70)
        print("DEMONSTRATION COMPLETE")
        print("=" * 70)
        print("\nAll JWT utility features demonstrated successfully!")
        print("Check backend/auth/core/README.md for detailed documentation.\n")

    except Exception as e:
        print(f"\n✗ Demo failed with error: {e}\n")
        raise


if __name__ == "__main__":
    main()
