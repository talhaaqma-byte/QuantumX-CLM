from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CERTIFICATE = "certificate"
    POLICY = "policy"
    WORKFLOW = "workflow"
    USER_MANAGEMENT = "user_management"
    SYSTEM = "system"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ActionResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


class AuthEventType(str, Enum):
    """Auth-specific event types."""

    # Authentication events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    TOKEN_ISSUED = "auth.token.issued"
    TOKEN_REFRESH = "auth.token.refresh"
    TOKEN_REVOKED = "auth.token.revoked"
    TOKEN_VALIDATION_FAILED = "auth.token.validation_failed"

    # OAuth events
    OAUTH_AUTHORIZE = "auth.oauth.authorize"
    OAUTH_TOKEN_EXCHANGE = "auth.oauth.token_exchange"
    OAUTH_CODE_GENERATED = "auth.oauth.code_generated"
    OAUTH_CLIENT_REGISTERED = "auth.oauth.client_registered"

    # MFA events
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    MFA_CHALLENGE_SUCCESS = "auth.mfa.challenge_success"
    MFA_CHALLENGE_FAILURE = "auth.mfa.challenge_failure"

    # Password events
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"

    # Email verification
    EMAIL_VERIFICATION_SENT = "auth.email.verification_sent"
    EMAIL_VERIFIED = "auth.email.verified"

    # Session events
    SESSION_CREATED = "auth.session.created"
    SESSION_EXPIRED = "auth.session.expired"
    SESSION_REVOKED = "auth.session.revoked"

    # API key events
    API_KEY_CREATED = "auth.api_key.created"
    API_KEY_USED = "auth.api_key.used"
    API_KEY_REVOKED = "auth.api_key.revoked"

    # User account events
    USER_CREATED = "auth.user.created"
    USER_UPDATED = "auth.user.updated"
    USER_DELETED = "auth.user.deleted"
    USER_LOCKED = "auth.user.locked"
    USER_UNLOCKED = "auth.user.unlocked"
    USER_SUSPENDED = "auth.user.suspended"

    # Role/Permission events
    ROLE_ASSIGNED = "auth.role.assigned"
    ROLE_REVOKED = "auth.role.revoked"
    PERMISSION_GRANTED = "auth.permission.granted"
    PERMISSION_DENIED = "auth.permission.denied"


class AuditEventCreate(BaseModel):
    """Schema for creating an audit event."""

    event_type: str = Field(..., description="Type of event (e.g., auth.login.success)")
    event_category: EventCategory = Field(
        ..., description="Category of the event"
    )
    severity: Severity = Field(default=Severity.INFO, description="Event severity")
    action: str = Field(..., description="Action performed (e.g., login, logout)")
    action_result: ActionResult = Field(
        ..., description="Result of the action"
    )

    # Actor information
    user_id: Optional[UUID] = Field(None, description="User ID who performed the action")
    username: Optional[str] = Field(None, description="Username who performed the action")
    organization_id: Optional[UUID] = Field(None, description="Organization context")

    # Resource information
    resource_type: Optional[str] = Field(None, description="Type of resource affected")
    resource_id: Optional[UUID] = Field(None, description="ID of resource affected")
    resource_name: Optional[str] = Field(None, description="Name of resource affected")

    # Context information
    ip_address: Optional[str] = Field(None, description="IP address of the actor")
    user_agent: Optional[str] = Field(None, description="User agent string")
    session_id: Optional[str] = Field(None, description="Session ID")
    request_id: Optional[str] = Field(None, description="Request ID for tracing")

    # Change tracking
    changes_before: Optional[dict[str, Any]] = Field(
        None, description="State before the change"
    )
    changes_after: Optional[dict[str, Any]] = Field(
        None, description="State after the change"
    )
    change_summary: Optional[str] = Field(None, description="Summary of changes")

    # Additional data
    event_data: Optional[dict[str, Any]] = Field(
        None, description="Additional event-specific data"
    )
    error_message: Optional[str] = Field(None, description="Error message if applicable")


class AuditEventResponse(BaseModel):
    """Schema for audit event response."""

    id: UUID
    event_id: str
    event_type: str
    event_category: str
    severity: str
    action: str
    action_result: str

    user_id: Optional[UUID] = None
    username: Optional[str] = None
    organization_id: Optional[UUID] = None

    resource_type: Optional[str] = None
    resource_id: Optional[UUID] = None
    resource_name: Optional[str] = None

    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

    changes_before: Optional[dict[str, Any]] = None
    changes_after: Optional[dict[str, Any]] = None
    change_summary: Optional[str] = None

    event_data: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None

    event_timestamp: datetime

    model_config = {"from_attributes": True}
