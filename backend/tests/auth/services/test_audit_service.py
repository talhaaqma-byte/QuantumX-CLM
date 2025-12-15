"""Tests for auth audit service."""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from backend.auth.models.audit import AuditLog
from backend.auth.schemas.audit import (
    ActionResult,
    AuditEventCreate,
    AuthEventType,
    EventCategory,
    Severity,
)
from backend.auth.services.audit_service import AuditService


@pytest.fixture
def audit_service(db_session):
    """Create audit service instance."""
    return AuditService(db_session)


@pytest.mark.asyncio
class TestAuditService:
    """Test audit service functionality."""

    async def test_generate_event_id(self, audit_service):
        """Test event ID generation."""
        event_id_1 = audit_service._generate_event_id()
        event_id_2 = audit_service._generate_event_id()

        assert event_id_1.startswith("evt_")
        assert event_id_2.startswith("evt_")
        assert event_id_1 != event_id_2

    async def test_create_event(self, audit_service, db_session):
        """Test creating a basic audit event."""
        event_data = AuditEventCreate(
            event_type="auth.test.event",
            event_category=EventCategory.AUTHENTICATION,
            severity=Severity.INFO,
            action="test_action",
            action_result=ActionResult.SUCCESS,
            username="test_user",
        )

        result = await audit_service.create_event(event_data)

        assert result.id is not None
        assert result.event_id.startswith("evt_")
        assert result.event_type == "auth.test.event"
        assert result.event_category == "authentication"
        assert result.severity == "info"
        assert result.action == "test_action"
        assert result.action_result == "success"
        assert result.username == "test_user"

    async def test_create_event_with_user_id(self, audit_service, db_session):
        """Test creating event with user ID."""
        user_id = uuid4()
        event_data = AuditEventCreate(
            event_type="auth.test.event",
            event_category=EventCategory.AUTHENTICATION,
            action="test",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username="test_user",
        )

        result = await audit_service.create_event(event_data)

        assert result.user_id == user_id
        assert result.username == "test_user"

    async def test_create_event_with_context(self, audit_service, db_session):
        """Test creating event with context information."""
        event_data = AuditEventCreate(
            event_type="auth.test.event",
            event_category=EventCategory.AUTHENTICATION,
            action="test",
            action_result=ActionResult.SUCCESS,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            session_id="sess_123",
            request_id="req_456",
        )

        result = await audit_service.create_event(event_data)

        assert result.ip_address == "192.168.1.100"
        assert result.user_agent == "Mozilla/5.0"
        assert result.session_id == "sess_123"
        assert result.request_id == "req_456"

    async def test_create_event_with_resource(self, audit_service, db_session):
        """Test creating event with resource information."""
        resource_id = uuid4()
        event_data = AuditEventCreate(
            event_type="auth.test.event",
            event_category=EventCategory.AUTHENTICATION,
            action="test",
            action_result=ActionResult.SUCCESS,
            resource_type="user",
            resource_id=resource_id,
            resource_name="John Doe",
        )

        result = await audit_service.create_event(event_data)

        assert result.resource_type == "user"
        assert result.resource_id == resource_id
        assert result.resource_name == "John Doe"

    async def test_create_event_with_event_data(self, audit_service, db_session):
        """Test creating event with additional event data."""
        event_data = AuditEventCreate(
            event_type="auth.test.event",
            event_category=EventCategory.AUTHENTICATION,
            action="test",
            action_result=ActionResult.SUCCESS,
            event_data={"key1": "value1", "key2": 123},
        )

        result = await audit_service.create_event(event_data)

        assert result.event_data == {"key1": "value1", "key2": 123}

    async def test_create_event_with_error(self, audit_service, db_session):
        """Test creating event with error message."""
        event_data = AuditEventCreate(
            event_type="auth.test.event",
            event_category=EventCategory.AUTHENTICATION,
            action="test",
            action_result=ActionResult.FAILURE,
            error_message="Something went wrong",
        )

        result = await audit_service.create_event(event_data)

        assert result.action_result == "failure"
        assert result.error_message == "Something went wrong"

    async def test_log_login_success(self, audit_service, db_session):
        """Test logging successful login."""
        user_id = uuid4()
        result = await audit_service.log_login_success(
            user_id=user_id,
            username="john.doe",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            session_id="sess_123",
            mfa_used=True,
        )

        assert result.event_type == AuthEventType.LOGIN_SUCCESS.value
        assert result.action == "login"
        assert result.action_result == "success"
        assert result.user_id == user_id
        assert result.username == "john.doe"
        assert result.ip_address == "192.168.1.100"
        assert result.event_data["mfa_used"] is True

    async def test_log_login_success_without_mfa(self, audit_service, db_session):
        """Test logging successful login without MFA."""
        user_id = uuid4()
        result = await audit_service.log_login_success(
            user_id=user_id,
            username="john.doe",
            ip_address="192.168.1.100",
        )

        assert result.event_data["mfa_used"] is False

    async def test_log_login_failure(self, audit_service, db_session):
        """Test logging failed login."""
        result = await audit_service.log_login_failure(
            username="john.doe",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            reason="Invalid password",
        )

        assert result.event_type == AuthEventType.LOGIN_FAILURE.value
        assert result.action == "login"
        assert result.action_result == "failure"
        assert result.username == "john.doe"
        assert result.severity == "warning"
        assert result.error_message == "Invalid password"

    async def test_log_logout(self, audit_service, db_session):
        """Test logging logout."""
        user_id = uuid4()
        result = await audit_service.log_logout(
            user_id=user_id,
            username="john.doe",
            session_id="sess_123",
            ip_address="192.168.1.100",
        )

        assert result.event_type == AuthEventType.LOGOUT.value
        assert result.action == "logout"
        assert result.action_result == "success"
        assert result.user_id == user_id
        assert result.session_id == "sess_123"

    async def test_log_token_issued(self, audit_service, db_session):
        """Test logging token issuance."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        result = await audit_service.log_token_issued(
            user_id=user_id,
            username="john.doe",
            token_type="access",
            ip_address="192.168.1.100",
            expires_at=expires_at,
        )

        assert result.event_type == AuthEventType.TOKEN_ISSUED.value
        assert result.action == "token_issued"
        assert result.action_result == "success"
        assert result.event_data["token_type"] == "access"
        assert "expires_at" in result.event_data

    async def test_log_token_refresh(self, audit_service, db_session):
        """Test logging token refresh."""
        user_id = uuid4()
        result = await audit_service.log_token_refresh(
            user_id=user_id,
            username="john.doe",
            ip_address="192.168.1.100",
        )

        assert result.event_type == AuthEventType.TOKEN_REFRESH.value
        assert result.action == "token_refresh"
        assert result.action_result == "success"

    async def test_log_token_validation_failed(self, audit_service, db_session):
        """Test logging token validation failure."""
        result = await audit_service.log_token_validation_failed(
            ip_address="192.168.1.100",
            reason="Token expired",
        )

        assert result.event_type == AuthEventType.TOKEN_VALIDATION_FAILED.value
        assert result.action == "token_validation"
        assert result.action_result == "failure"
        assert result.severity == "warning"
        assert result.error_message == "Token expired"

    async def test_log_oauth_event(self, audit_service, db_session):
        """Test logging OAuth event."""
        user_id = uuid4()
        result = await audit_service.log_oauth_event(
            event_type=AuthEventType.OAUTH_TOKEN_EXCHANGE,
            action="token_exchange",
            action_result=ActionResult.SUCCESS,
            client_id="client_123",
            user_id=user_id,
            username="john.doe",
            ip_address="192.168.1.100",
            scope="read write",
        )

        assert result.event_type == AuthEventType.OAUTH_TOKEN_EXCHANGE.value
        assert result.event_category == "authorization"
        assert result.event_data["client_id"] == "client_123"
        assert result.event_data["scope"] == "read write"

    async def test_log_password_changed(self, audit_service, db_session):
        """Test logging password change."""
        user_id = uuid4()
        result = await audit_service.log_password_changed(
            user_id=user_id,
            username="john.doe",
            forced=False,
        )

        assert result.event_type == AuthEventType.PASSWORD_CHANGED.value
        assert result.action == "password_change"
        assert result.action_result == "success"
        assert result.event_data["forced"] is False
        assert result.event_data["self_service"] is True

    async def test_log_password_changed_by_admin(self, audit_service, db_session):
        """Test logging password change by admin."""
        user_id = uuid4()
        admin_id = uuid4()
        result = await audit_service.log_password_changed(
            user_id=user_id,
            username="john.doe",
            changed_by_user_id=admin_id,
            forced=True,
        )

        assert result.event_data["forced"] is True
        assert result.event_data["self_service"] is False

    async def test_log_mfa_enabled(self, audit_service, db_session):
        """Test logging MFA enabled."""
        user_id = uuid4()
        result = await audit_service.log_mfa_event(
            event_type=AuthEventType.MFA_ENABLED,
            user_id=user_id,
            username="john.doe",
            action_result=ActionResult.SUCCESS,
            ip_address="192.168.1.100",
        )

        assert result.event_type == AuthEventType.MFA_ENABLED.value
        assert result.action == "mfa_enable"
        assert result.action_result == "success"

    async def test_log_mfa_challenge_success(self, audit_service, db_session):
        """Test logging successful MFA challenge."""
        user_id = uuid4()
        result = await audit_service.log_mfa_event(
            event_type=AuthEventType.MFA_CHALLENGE_SUCCESS,
            user_id=user_id,
            username="john.doe",
            action_result=ActionResult.SUCCESS,
            ip_address="192.168.1.100",
        )

        assert result.event_type == AuthEventType.MFA_CHALLENGE_SUCCESS.value
        assert result.action == "mfa_challenge"

    async def test_log_api_key_event(self, audit_service, db_session):
        """Test logging API key event."""
        user_id = uuid4()
        api_key_id = uuid4()
        result = await audit_service.log_api_key_event(
            event_type=AuthEventType.API_KEY_CREATED,
            action="api_key_create",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username="john.doe",
            api_key_id=api_key_id,
            api_key_name="Production API Key",
            ip_address="192.168.1.100",
        )

        assert result.event_type == AuthEventType.API_KEY_CREATED.value
        assert result.resource_type == "api_key"
        assert result.resource_id == api_key_id
        assert result.resource_name == "Production API Key"

    async def test_log_auth_event_with_enum(self, audit_service, db_session):
        """Test logging with AuthEventType enum."""
        user_id = uuid4()
        result = await audit_service.log_auth_event(
            event_type=AuthEventType.LOGIN_SUCCESS,
            action="login",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username="john.doe",
        )

        assert result.event_type == "auth.login.success"

    async def test_log_auth_event_with_string(self, audit_service, db_session):
        """Test logging with string event type."""
        user_id = uuid4()
        result = await audit_service.log_auth_event(
            event_type="auth.custom.event",
            action="custom",
            action_result=ActionResult.SUCCESS,
            user_id=user_id,
            username="john.doe",
        )

        assert result.event_type == "auth.custom.event"

    async def test_event_persists_in_database(self, audit_service, db_session):
        """Test that events persist in database."""
        user_id = uuid4()
        result = await audit_service.log_login_success(
            user_id=user_id,
            username="john.doe",
        )

        # Query the database
        from sqlalchemy import select
        stmt = select(AuditLog).where(AuditLog.id == result.id)
        db_result = await db_session.execute(stmt)
        audit_log = db_result.scalar_one_or_none()

        assert audit_log is not None
        assert audit_log.event_id == result.event_id
        assert audit_log.user_id == user_id
        assert audit_log.username == "john.doe"

    async def test_multiple_events_unique_ids(self, audit_service, db_session):
        """Test that multiple events have unique IDs."""
        user_id = uuid4()
        
        result1 = await audit_service.log_login_success(
            user_id=user_id,
            username="john.doe",
        )
        
        result2 = await audit_service.log_login_success(
            user_id=user_id,
            username="john.doe",
        )

        assert result1.event_id != result2.event_id
        assert result1.id != result2.id
