# Audit Service for Auth Events

## Overview

The audit service provides comprehensive logging for authentication and authorization events in the QuantumX-CLM platform. It records all auth-related activities to the `audit_log` table in the `clm_core_db` database.

## Architecture

### Components

1. **Event Model** (`backend/auth/models/audit.py`)
   - SQLAlchemy model mapping to `audit_log` table
   - Stores comprehensive event data with context

2. **Event Schemas** (`backend/auth/schemas/audit.py`)
   - Pydantic models for event creation and response
   - Enums for event types, categories, severity, and results
   - Predefined `AuthEventType` enum with all auth event types

3. **Audit Service** (`backend/auth/services/audit_service.py`)
   - Core service for creating audit events
   - Helper methods for common auth events
   - Automatic event ID generation

## Database Schema

The `audit_log` table stores events with the following structure:

```sql
CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    
    -- Actor
    user_id UUID,
    username VARCHAR(255),
    organization_id UUID,
    
    -- Resource
    resource_type VARCHAR(50),
    resource_id UUID,
    resource_name VARCHAR(255),
    
    -- Action
    action VARCHAR(100) NOT NULL,
    action_result VARCHAR(50) NOT NULL,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    
    -- Changes
    changes_before JSONB,
    changes_after JSONB,
    change_summary TEXT,
    
    -- Additional details
    event_data JSONB,
    error_message TEXT,
    
    -- Timestamp
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

## Event Types

### Authentication Events
- `auth.login.success` - Successful login
- `auth.login.failure` - Failed login attempt
- `auth.logout` - User logout
- `auth.token.issued` - Token issued
- `auth.token.refresh` - Token refreshed
- `auth.token.revoked` - Token revoked
- `auth.token.validation_failed` - Token validation failed

### OAuth Events
- `auth.oauth.authorize` - OAuth authorization
- `auth.oauth.token_exchange` - OAuth token exchange
- `auth.oauth.code_generated` - OAuth code generated
- `auth.oauth.client_registered` - OAuth client registered

### MFA Events
- `auth.mfa.enabled` - MFA enabled for user
- `auth.mfa.disabled` - MFA disabled for user
- `auth.mfa.challenge_success` - MFA challenge succeeded
- `auth.mfa.challenge_failure` - MFA challenge failed

### Password Events
- `auth.password.changed` - Password changed
- `auth.password.reset_requested` - Password reset requested
- `auth.password.reset_completed` - Password reset completed

### Email Events
- `auth.email.verification_sent` - Email verification sent
- `auth.email.verified` - Email verified

### Session Events
- `auth.session.created` - Session created
- `auth.session.expired` - Session expired
- `auth.session.revoked` - Session revoked

### API Key Events
- `auth.api_key.created` - API key created
- `auth.api_key.used` - API key used
- `auth.api_key.revoked` - API key revoked

### User Account Events
- `auth.user.created` - User created
- `auth.user.updated` - User updated
- `auth.user.deleted` - User deleted
- `auth.user.locked` - User locked
- `auth.user.unlocked` - User unlocked
- `auth.user.suspended` - User suspended

### Role/Permission Events
- `auth.role.assigned` - Role assigned to user
- `auth.role.revoked` - Role revoked from user
- `auth.permission.granted` - Permission granted
- `auth.permission.denied` - Permission denied

## Usage Examples

### Basic Setup

```python
from sqlalchemy.ext.asyncio import AsyncSession
from backend.auth.services import AuditService
from backend.auth.schemas.audit import AuthEventType, ActionResult

# Initialize service with database session
audit = AuditService(db_session)
```

### Logging a Successful Login

```python
await audit.log_login_success(
    user_id=user.id,
    username=user.username,
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0...",
    session_id="sess_abc123",
    mfa_used=True
)
```

### Logging a Failed Login

```python
await audit.log_login_failure(
    username="john.doe",
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0...",
    reason="Invalid password"
)
```

### Logging a Logout

```python
await audit.log_logout(
    user_id=user.id,
    username=user.username,
    session_id="sess_abc123",
    ip_address="192.168.1.100"
)
```

### Logging Token Events

```python
# Token issued
await audit.log_token_issued(
    user_id=user.id,
    username=user.username,
    token_type="access",
    ip_address="192.168.1.100",
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=60)
)

# Token refresh
await audit.log_token_refresh(
    user_id=user.id,
    username=user.username,
    ip_address="192.168.1.100"
)

# Token validation failed
await audit.log_token_validation_failed(
    ip_address="192.168.1.100",
    reason="Token expired"
)
```

### Logging OAuth Events

```python
await audit.log_oauth_event(
    event_type=AuthEventType.OAUTH_TOKEN_EXCHANGE,
    action="token_exchange",
    action_result=ActionResult.SUCCESS,
    client_id="client_123",
    user_id=user.id,
    username=user.username,
    ip_address="192.168.1.100",
    scope="read write"
)
```

### Logging Password Changes

```python
await audit.log_password_changed(
    user_id=user.id,
    username=user.username,
    forced=False
)
```

### Logging MFA Events

```python
# MFA enabled
await audit.log_mfa_event(
    event_type=AuthEventType.MFA_ENABLED,
    user_id=user.id,
    username=user.username,
    action_result=ActionResult.SUCCESS,
    ip_address="192.168.1.100"
)

# MFA challenge success
await audit.log_mfa_event(
    event_type=AuthEventType.MFA_CHALLENGE_SUCCESS,
    user_id=user.id,
    username=user.username,
    action_result=ActionResult.SUCCESS,
    ip_address="192.168.1.100"
)
```

### Logging API Key Events

```python
await audit.log_api_key_event(
    event_type=AuthEventType.API_KEY_CREATED,
    action="api_key_create",
    action_result=ActionResult.SUCCESS,
    user_id=user.id,
    username=user.username,
    api_key_id=api_key.id,
    api_key_name="Production API Key",
    ip_address="192.168.1.100"
)
```

### Custom Auth Events

For events not covered by helper methods:

```python
from backend.auth.schemas.audit import (
    AuditEventCreate,
    EventCategory,
    Severity,
    ActionResult
)

event = AuditEventCreate(
    event_type="auth.custom.event",
    event_category=EventCategory.AUTHENTICATION,
    severity=Severity.INFO,
    action="custom_action",
    action_result=ActionResult.SUCCESS,
    user_id=user_id,
    username=username,
    ip_address="192.168.1.100",
    event_data={"custom_field": "custom_value"}
)

await audit.create_event(event)
```

## Integration with FastAPI Endpoints

### Using Dependency Injection

```python
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from backend.common.deps import get_core_db
from backend.auth.services import AuditService

router = APIRouter()

async def get_audit_service(
    db: AsyncSession = Depends(get_core_db)
) -> AuditService:
    return AuditService(db)

@router.post("/login")
async def login(
    request: LoginRequest,
    audit: AuditService = Depends(get_audit_service)
):
    # Perform authentication
    try:
        user = await authenticate_user(request.username, request.password)
        
        # Log success
        await audit.log_login_success(
            user_id=user.id,
            username=user.username,
            ip_address=request.state.client_host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"access_token": token}
    except AuthenticationError as e:
        # Log failure
        await audit.log_login_failure(
            username=request.username,
            ip_address=request.state.client_host,
            reason=str(e)
        )
        raise
```

### Extracting Context Information

```python
from fastapi import Request

async def get_request_context(request: Request) -> dict:
    """Extract context information from the request."""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "request_id": request.headers.get("x-request-id"),
    }

@router.post("/endpoint")
async def endpoint(
    request: Request,
    audit: AuditService = Depends(get_audit_service)
):
    context = await get_request_context(request)
    
    await audit.log_auth_event(
        event_type=AuthEventType.SOME_EVENT,
        action="action",
        action_result=ActionResult.SUCCESS,
        **context
    )
```

## Event Categories and Severity

### Event Categories
- `authentication` - Authentication events (login, logout, tokens)
- `authorization` - Authorization events (OAuth, permissions)
- `certificate` - Certificate-related events
- `policy` - Policy-related events
- `workflow` - Workflow-related events
- `user_management` - User management events
- `system` - System events

### Severity Levels
- `info` - Normal operations
- `warning` - Warning conditions (e.g., failed login attempts)
- `error` - Error conditions
- `critical` - Critical conditions requiring immediate attention

### Action Results
- `success` - Action completed successfully
- `failure` - Action failed
- `partial` - Action partially completed

## Best Practices

### 1. Always Log Security-Critical Events
```python
# Always log authentication attempts
await audit.log_login_failure(username=username, reason="Invalid credentials")
```

### 2. Include Context Information
```python
# Include IP address, user agent, and session ID when available
await audit.log_login_success(
    user_id=user.id,
    username=user.username,
    ip_address=ip,
    user_agent=user_agent,
    session_id=session_id
)
```

### 3. Use Appropriate Severity Levels
```python
# Failed login = WARNING
await audit.log_login_failure(username=username)  # severity=WARNING

# Successful login = INFO
await audit.log_login_success(user_id=user.id, username=username)  # severity=INFO
```

### 4. Log Both Success and Failure
```python
try:
    result = await perform_operation()
    await audit.log_auth_event(
        event_type=AuthEventType.OPERATION,
        action="operation",
        action_result=ActionResult.SUCCESS,
        user_id=user_id
    )
except Exception as e:
    await audit.log_auth_event(
        event_type=AuthEventType.OPERATION,
        action="operation",
        action_result=ActionResult.FAILURE,
        user_id=user_id,
        error_message=str(e)
    )
    raise
```

### 5. Don't Log Sensitive Data
```python
# DON'T log passwords, tokens, or secrets
await audit.log_password_changed(
    user_id=user.id,
    username=user.username,
    # No password included!
)

# DO log metadata
await audit.log_token_issued(
    user_id=user.id,
    username=user.username,
    token_type="access",
    expires_at=expires_at
    # No actual token value!
)
```

### 6. Use Event Data for Additional Context
```python
await audit.log_auth_event(
    event_type=AuthEventType.LOGIN_SUCCESS,
    action="login",
    action_result=ActionResult.SUCCESS,
    user_id=user.id,
    username=user.username,
    event_data={
        "mfa_used": True,
        "login_method": "password",
        "device_type": "mobile"
    }
)
```

## Error Handling

The audit service handles errors gracefully and logs them:

```python
try:
    await audit.log_login_success(user_id=user.id, username=user.username)
except Exception as e:
    # Audit service logs errors internally
    # Application continues to function even if audit logging fails
    logger.error(f"Failed to create audit event: {e}")
```

## Performance Considerations

1. **Async Operations**: All audit operations are async and non-blocking
2. **Database Connection**: Uses existing async session, no additional connections
3. **Minimal Overhead**: Event creation is fast and lightweight
4. **No Enforcement**: Audit logging does not block operations if it fails

## Querying Audit Logs

While not part of this implementation, audit logs can be queried:

```sql
-- Find all failed login attempts
SELECT * FROM audit_log 
WHERE event_type = 'auth.login.failure' 
ORDER BY event_timestamp DESC;

-- Find all events for a specific user
SELECT * FROM audit_log 
WHERE user_id = '...' 
ORDER BY event_timestamp DESC;

-- Find all critical events
SELECT * FROM audit_log 
WHERE severity = 'critical' 
ORDER BY event_timestamp DESC;

-- Find all OAuth events
SELECT * FROM audit_log 
WHERE event_category = 'authorization' 
ORDER BY event_timestamp DESC;
```

## Testing

Example test for audit service:

```python
import pytest
from backend.auth.services import AuditService
from backend.auth.schemas.audit import AuthEventType, ActionResult

@pytest.mark.asyncio
async def test_log_login_success(db_session):
    audit = AuditService(db_session)
    
    event = await audit.log_login_success(
        user_id=uuid4(),
        username="test_user",
        ip_address="192.168.1.1",
        mfa_used=True
    )
    
    assert event.event_type == AuthEventType.LOGIN_SUCCESS.value
    assert event.action_result == ActionResult.SUCCESS.value
    assert event.username == "test_user"
    assert event.event_data["mfa_used"] is True
```

## Future Enhancements

Potential future improvements:

1. **Async Event Queue**: Use message queue for high-volume environments
2. **Event Retention Policy**: Automatic archival of old events
3. **Real-time Alerting**: Trigger alerts on suspicious patterns
4. **Event Analytics**: Dashboard for security monitoring
5. **Compliance Reports**: Generate compliance reports from audit logs
6. **Event Streaming**: Stream events to SIEM systems
