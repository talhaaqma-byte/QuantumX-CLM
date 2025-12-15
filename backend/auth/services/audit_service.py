"""
Audit service for auth-related events.

This service provides helpers for logging authentication and authorization events
to the audit_log table. It handles event generation, context capture, and database
persistence.

Example usage:
    from backend.auth.services.audit_service import AuditService
    from backend.auth.schemas.audit import AuthEventType, EventCategory, ActionResult

    audit = AuditService(db_session)
    
    # Log a successful login
    await audit.log_auth_event(
        event_type=AuthEventType.LOGIN_SUCCESS,
        user_id=user.id,
        username=user.username,
        action="login",
        action_result=ActionResult.SUCCESS,
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0...",
    )
    
    # Log a failed login attempt
    await audit.log_login_failure(
        username="john.doe",
        ip_address="192.168.1.1",
        reason="Invalid password"
    )
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.models.audit import AuditLog
from backend.auth.schemas.audit import (
    ActionResult,
    AuditEventCreate,
    AuditEventResponse,
    AuthEventType,
    EventCategory,
    Severity,
)

logger = logging.getLogger(__name__)


class AuditService:
    """Service for managing auth audit events."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        random_suffix = secrets.token_hex(8)
        return f"evt_{timestamp}_{random_suffix}"

    async def create_event(self, event_data: AuditEventCreate) -> AuditEventResponse:
        """
        Create an audit event in the database.

        Args:
            event_data: Audit event data

        Returns:
            Created audit event

        Example:
            event = AuditEventCreate(
                event_type="auth.login.success",
                event_category=EventCategory.AUTHENTICATION,
                action="login",
                action_result=ActionResult.SUCCESS,
                user_id=user_id,
                username="john.doe"
            )
            result = await audit_service.create_event(event)
        """
        event_id = self._generate_event_id()

        audit_log = AuditLog(
            event_id=event_id,
            event_type=event_data.event_type,
            event_category=event_data.event_category.value,
            severity=event_data.severity.value,
            action=event_data.action,
            action_result=event_data.action_result.value,
            user_id=event_data.user_id,
            username=event_data.username,
            organization_id=event_data.organization_id,
            resource_type=event_data.resource_type,
            resource_id=event_data.resource_id,
            resource_name=event_data.resource_name,
            ip_address=event_data.ip_address,
            user_agent=event_data.user_agent,
            session_id=event_data.session_id,
            request_id=event_data.request_id,
            changes_before=event_data.changes_before,
            changes_after=event_data.changes_after,
            change_summary=event_data.change_summary,
            event_data=event_data.event_data,
            error_message=event_data.error_message,
        )

        self.db.add(audit_log)
        await self.db.commit()
        await self.db.refresh(audit_log)

        logger.info(
            f"Audit event created: {event_id} - {event_data.event_type} - {event_data.action_result.value}",
            extra={
                "event_id": event_id,
                "event_type": event_data.event_type,
                "user_id": str(event_data.user_id) if event_data.user_id else None,
                "action_result": event_data.action_result.value,
            },
        )

        return AuditEventResponse.model_validate(audit_log)

    async def log_auth_event(
        self,
        event_type: str | AuthEventType,
        action: str,
        action_result: ActionResult,
        user_id: Optional[UUID] = None,
        username: Optional[str] = None,
        organization_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        resource_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        event_data: Optional[dict[str, Any]] = None,
        error_message: Optional[str] = None,
        severity: Severity = Severity.INFO,
    ) -> AuditEventResponse:
        """
        Log a general auth event.

        Args:
            event_type: Type of event (use AuthEventType enum)
            action: Action performed
            action_result: Result of the action
            user_id: User ID
            username: Username
            organization_id: Organization ID
            resource_type: Resource type
            resource_id: Resource ID
            resource_name: Resource name
            ip_address: IP address
            user_agent: User agent string
            session_id: Session ID
            request_id: Request ID for tracing
            event_data: Additional event data
            error_message: Error message if applicable
            severity: Event severity

        Returns:
            Created audit event
        """
        if isinstance(event_type, AuthEventType):
            event_type = event_type.value

        event = AuditEventCreate(
            event_type=event_type,
            event_category=EventCategory.AUTHENTICATION,
            severity=severity,
            action=action,
            action_result=action_result,
            user_id=user_id,
            username=username,
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            event_data=event_data,
            error_message=error_message,
        )

        return await self.create_event(event)

    async def log_login_success(
        self,
        user_id: UUID,
        username: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        mfa_used: bool = False,
    ) -> AuditEventResponse:
        """
        Log a successful login event.

        Args:
            user_id: User ID
            username: Username
            ip_address: IP address
            user_agent: User agent string
            session_id: Session ID
            mfa_used: Whether MFA was used

        Returns:
            Created audit event
        """
        return await self.log_auth_event(
            event_type=AuthEventType.LOGIN_SUCCESS,
            action="login",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            event_data={"mfa_used": mfa_used},
            severity=Severity.INFO,
        )

    async def log_login_failure(
        self,
        username: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log a failed login attempt.

        Args:
            username: Username
            ip_address: IP address
            user_agent: User agent string
            reason: Reason for failure

        Returns:
            Created audit event
        """
        return await self.log_auth_event(
            event_type=AuthEventType.LOGIN_FAILURE,
            action="login",
            action_result=ActionResult.FAILURE,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            error_message=reason,
            severity=Severity.WARNING,
        )

    async def log_logout(
        self,
        user_id: UUID,
        username: str,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log a logout event.

        Args:
            user_id: User ID
            username: Username
            session_id: Session ID
            ip_address: IP address

        Returns:
            Created audit event
        """
        return await self.log_auth_event(
            event_type=AuthEventType.LOGOUT,
            action="logout",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username=username,
            session_id=session_id,
            ip_address=ip_address,
            severity=Severity.INFO,
        )

    async def log_token_issued(
        self,
        user_id: UUID,
        username: str,
        token_type: str,
        ip_address: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> AuditEventResponse:
        """
        Log a token issuance event.

        Args:
            user_id: User ID
            username: Username
            token_type: Type of token (access, refresh)
            ip_address: IP address
            expires_at: Token expiration time

        Returns:
            Created audit event
        """
        event_data = {"token_type": token_type}
        if expires_at:
            event_data["expires_at"] = expires_at.isoformat()

        return await self.log_auth_event(
            event_type=AuthEventType.TOKEN_ISSUED,
            action="token_issued",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            event_data=event_data,
            severity=Severity.INFO,
        )

    async def log_token_refresh(
        self,
        user_id: UUID,
        username: str,
        ip_address: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log a token refresh event.

        Args:
            user_id: User ID
            username: Username
            ip_address: IP address

        Returns:
            Created audit event
        """
        return await self.log_auth_event(
            event_type=AuthEventType.TOKEN_REFRESH,
            action="token_refresh",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            severity=Severity.INFO,
        )

    async def log_token_validation_failed(
        self,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log a token validation failure.

        Args:
            ip_address: IP address
            reason: Reason for failure

        Returns:
            Created audit event
        """
        return await self.log_auth_event(
            event_type=AuthEventType.TOKEN_VALIDATION_FAILED,
            action="token_validation",
            action_result=ActionResult.FAILURE,
            ip_address=ip_address,
            error_message=reason,
            severity=Severity.WARNING,
        )

    async def log_oauth_event(
        self,
        event_type: AuthEventType,
        action: str,
        action_result: ActionResult,
        client_id: str,
        user_id: Optional[UUID] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        scope: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log an OAuth event.

        Args:
            event_type: OAuth event type
            action: Action performed
            action_result: Result of the action
            client_id: OAuth client ID
            user_id: User ID
            username: Username
            ip_address: IP address
            scope: OAuth scope
            error_message: Error message if applicable

        Returns:
            Created audit event
        """
        event_data = {"client_id": client_id}
        if scope:
            event_data["scope"] = scope

        event = AuditEventCreate(
            event_type=event_type.value,
            event_category=EventCategory.AUTHORIZATION,
            severity=Severity.INFO if action_result == ActionResult.SUCCESS else Severity.WARNING,
            action=action,
            action_result=action_result,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            event_data=event_data,
            error_message=error_message,
        )

        return await self.create_event(event)

    async def log_password_changed(
        self,
        user_id: UUID,
        username: str,
        changed_by_user_id: Optional[UUID] = None,
        forced: bool = False,
    ) -> AuditEventResponse:
        """
        Log a password change event.

        Args:
            user_id: User ID whose password was changed
            username: Username whose password was changed
            changed_by_user_id: User ID who changed the password (if admin)
            forced: Whether the change was forced (password reset)

        Returns:
            Created audit event
        """
        event_data = {
            "forced": forced,
            "self_service": changed_by_user_id is None or changed_by_user_id == user_id,
        }

        return await self.log_auth_event(
            event_type=AuthEventType.PASSWORD_CHANGED,
            action="password_change",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username=username,
            event_data=event_data,
            severity=Severity.INFO,
        )

    async def log_mfa_event(
        self,
        event_type: AuthEventType,
        user_id: UUID,
        username: str,
        action_result: ActionResult,
        ip_address: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log an MFA-related event.

        Args:
            event_type: MFA event type
            user_id: User ID
            username: Username
            action_result: Result of the action
            ip_address: IP address

        Returns:
            Created audit event
        """
        action_map = {
            AuthEventType.MFA_ENABLED: "mfa_enable",
            AuthEventType.MFA_DISABLED: "mfa_disable",
            AuthEventType.MFA_CHALLENGE_SUCCESS: "mfa_challenge",
            AuthEventType.MFA_CHALLENGE_FAILURE: "mfa_challenge",
        }

        return await self.log_auth_event(
            event_type=event_type,
            action=action_map.get(event_type, "mfa_action"),
            action_result=action_result,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            severity=Severity.INFO,
        )

    async def log_api_key_event(
        self,
        event_type: AuthEventType,
        action: str,
        action_result: ActionResult,
        user_id: UUID,
        username: str,
        api_key_id: Optional[UUID] = None,
        api_key_name: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuditEventResponse:
        """
        Log an API key event.

        Args:
            event_type: API key event type
            action: Action performed
            action_result: Result of the action
            user_id: User ID
            username: Username
            api_key_id: API key ID
            api_key_name: API key name
            ip_address: IP address

        Returns:
            Created audit event
        """
        return await self.log_auth_event(
            event_type=event_type,
            action=action,
            action_result=action_result,
            user_id=user_id,
            username=username,
            resource_type="api_key",
            resource_id=api_key_id,
            resource_name=api_key_name,
            ip_address=ip_address,
            severity=Severity.INFO,
        )
