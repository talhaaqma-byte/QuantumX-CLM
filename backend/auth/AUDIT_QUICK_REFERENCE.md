# Audit Service Quick Reference

## Setup

```python
from backend.auth.services import AuditService
from backend.auth.schemas.audit import AuthEventType, ActionResult

# Initialize (typically via dependency injection)
audit = AuditService(db_session)
```

## Common Patterns

### Login Events

```python
# Success
await audit.log_login_success(
    user_id=user.id,
    username=user.username,
    ip_address=request.client.host,
    user_agent=request.headers.get("user-agent"),
    session_id=session_id,
    mfa_used=True
)

# Failure
await audit.log_login_failure(
    username=username,
    ip_address=request.client.host,
    reason="Invalid credentials"
)
```

### Token Events

```python
# Token issued
await audit.log_token_issued(
    user_id=user.id,
    username=user.username,
    token_type="access",
    ip_address=request.client.host,
    expires_at=expires_at
)

# Token refresh
await audit.log_token_refresh(
    user_id=user.id,
    username=user.username,
    ip_address=request.client.host
)

# Validation failed
await audit.log_token_validation_failed(
    ip_address=request.client.host,
    reason="Token expired"
)
```

### OAuth Events

```python
await audit.log_oauth_event(
    event_type=AuthEventType.OAUTH_TOKEN_EXCHANGE,
    action="token_exchange",
    action_result=ActionResult.SUCCESS,
    client_id=client.id,
    user_id=user.id,
    username=user.username,
    ip_address=request.client.host,
    scope="read write"
)
```

### Password Events

```python
await audit.log_password_changed(
    user_id=user.id,
    username=user.username,
    forced=False  # True if admin reset
)
```

### MFA Events

```python
# MFA enabled
await audit.log_mfa_event(
    event_type=AuthEventType.MFA_ENABLED,
    user_id=user.id,
    username=user.username,
    action_result=ActionResult.SUCCESS,
    ip_address=request.client.host
)

# MFA challenge success
await audit.log_mfa_event(
    event_type=AuthEventType.MFA_CHALLENGE_SUCCESS,
    user_id=user.id,
    username=user.username,
    action_result=ActionResult.SUCCESS,
    ip_address=request.client.host
)
```

### API Key Events

```python
await audit.log_api_key_event(
    event_type=AuthEventType.API_KEY_CREATED,
    action="api_key_create",
    action_result=ActionResult.SUCCESS,
    user_id=user.id,
    username=user.username,
    api_key_id=api_key.id,
    api_key_name=api_key.name,
    ip_address=request.client.host
)
```

## Event Types Reference

### Authentication
- `AuthEventType.LOGIN_SUCCESS`
- `AuthEventType.LOGIN_FAILURE`
- `AuthEventType.LOGOUT`
- `AuthEventType.TOKEN_ISSUED`
- `AuthEventType.TOKEN_REFRESH`
- `AuthEventType.TOKEN_REVOKED`
- `AuthEventType.TOKEN_VALIDATION_FAILED`

### OAuth
- `AuthEventType.OAUTH_AUTHORIZE`
- `AuthEventType.OAUTH_TOKEN_EXCHANGE`
- `AuthEventType.OAUTH_CODE_GENERATED`
- `AuthEventType.OAUTH_CLIENT_REGISTERED`

### MFA
- `AuthEventType.MFA_ENABLED`
- `AuthEventType.MFA_DISABLED`
- `AuthEventType.MFA_CHALLENGE_SUCCESS`
- `AuthEventType.MFA_CHALLENGE_FAILURE`

### Password
- `AuthEventType.PASSWORD_CHANGED`
- `AuthEventType.PASSWORD_RESET_REQUESTED`
- `AuthEventType.PASSWORD_RESET_COMPLETED`

### API Keys
- `AuthEventType.API_KEY_CREATED`
- `AuthEventType.API_KEY_USED`
- `AuthEventType.API_KEY_REVOKED`

## FastAPI Integration

```python
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from backend.common.deps import get_core_db
from backend.auth.services import AuditService

async def get_audit_service(
    db: AsyncSession = Depends(get_core_db)
) -> AuditService:
    return AuditService(db)

@router.post("/login")
async def login(
    request: Request,
    data: LoginRequest,
    audit: AuditService = Depends(get_audit_service)
):
    try:
        user = await authenticate(data.username, data.password)
        
        await audit.log_login_success(
            user_id=user.id,
            username=user.username,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"token": generate_token(user)}
    except AuthError as e:
        await audit.log_login_failure(
            username=data.username,
            ip_address=request.client.host,
            reason=str(e)
        )
        raise
```

## Custom Events

```python
await audit.log_auth_event(
    event_type="auth.custom.event",
    action="custom_action",
    action_result=ActionResult.SUCCESS,
    user_id=user.id,
    username=user.username,
    ip_address=request.client.host,
    event_data={"custom_field": "value"},
    severity=Severity.INFO
)
```

## Error Handling

```python
try:
    await perform_sensitive_operation()
    await audit.log_auth_event(
        event_type=AuthEventType.OPERATION,
        action="operation",
        action_result=ActionResult.SUCCESS,
        user_id=user.id
    )
except Exception as e:
    await audit.log_auth_event(
        event_type=AuthEventType.OPERATION,
        action="operation",
        action_result=ActionResult.FAILURE,
        user_id=user.id,
        error_message=str(e),
        severity=Severity.ERROR
    )
    raise
```

## Best Practices

1. **Always log both success and failure**
2. **Include context** (IP, user agent, session ID)
3. **Use appropriate severity levels**
4. **Don't log sensitive data** (passwords, tokens)
5. **Use event_data for additional context**
6. **Log before returning/raising** to ensure capture

## Severity Levels

- `Severity.INFO` - Normal operations (login success, logout)
- `Severity.WARNING` - Warning conditions (login failures)
- `Severity.ERROR` - Error conditions
- `Severity.CRITICAL` - Critical conditions

## Action Results

- `ActionResult.SUCCESS` - Completed successfully
- `ActionResult.FAILURE` - Failed
- `ActionResult.PARTIAL` - Partially completed
