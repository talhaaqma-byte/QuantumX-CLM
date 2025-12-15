-- =====================================================================
-- CLM Core Database - Initial Schema
-- =====================================================================
-- Database: clm_core_db
-- Purpose: Store application data, users, workflows, policies, and audit logs
-- Security: No direct access to sensitive cryptographic material
-- =====================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- USERS TABLE
-- =====================================================================
-- Stores user accounts and authentication data
-- =====================================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    
    -- Authentication
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(255) NOT NULL,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    must_change_password BOOLEAN DEFAULT FALSE,
    
    -- Profile
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    display_name VARCHAR(255),
    phone_number VARCHAR(50),
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'inactive', 'locked', 'suspended'
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    
    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    mfa_backup_codes TEXT[],
    
    -- Session management
    failed_login_attempts INTEGER DEFAULT 0,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    last_activity_at TIMESTAMP WITH TIME ZONE,
    
    -- API access
    api_access_enabled BOOLEAN DEFAULT FALSE,
    
    -- Audit fields
    created_by_user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_user_status CHECK (status IN ('active', 'inactive', 'locked', 'suspended')),
    CONSTRAINT chk_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_username ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_last_activity ON users(last_activity_at) WHERE deleted_at IS NULL;

COMMENT ON TABLE users IS 'User accounts and authentication information';

-- =====================================================================
-- ROLES TABLE
-- =====================================================================
-- Defines system roles for access control
-- =====================================================================

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    
    -- Permissions (stored as JSON for flexibility)
    permissions JSONB NOT NULL DEFAULT '{}',
    
    -- Role hierarchy
    parent_role_id UUID,
    is_system_role BOOLEAN DEFAULT FALSE, -- System roles cannot be deleted
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit fields
    created_by_user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT fk_parent_role FOREIGN KEY (parent_role_id) REFERENCES roles(id)
);

CREATE INDEX idx_roles_code ON roles(role_code) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_active ON roles(is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_parent ON roles(parent_role_id);

COMMENT ON TABLE roles IS 'System roles with associated permissions';
COMMENT ON COLUMN roles.permissions IS 'JSON object defining permissions: {"certificates": ["read", "create"], "policies": ["read"]}';

-- =====================================================================
-- USER ROLES TABLE
-- =====================================================================
-- Many-to-many relationship between users and roles
-- =====================================================================

CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    
    -- Temporal assignment (optional)
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE,
    
    -- Audit fields
    assigned_by_user_id UUID,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by_user_id UUID,
    
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT uq_user_role UNIQUE (user_id, role_id),
    CONSTRAINT chk_valid_period CHECK (valid_from < valid_until OR valid_until IS NULL)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_user_roles_role ON user_roles(role_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_user_roles_valid ON user_roles(valid_from, valid_until) WHERE revoked_at IS NULL;

COMMENT ON TABLE user_roles IS 'Assignment of roles to users with optional temporal validity';

-- =====================================================================
-- ORGANIZATIONS TABLE
-- =====================================================================
-- Multi-tenancy support for organizations
-- =====================================================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_name VARCHAR(255) NOT NULL,
    org_code VARCHAR(50) UNIQUE NOT NULL,
    
    -- Organization details
    description TEXT,
    website VARCHAR(255),
    industry VARCHAR(100),
    
    -- Contact information
    primary_contact_user_id UUID,
    billing_email VARCHAR(255),
    support_email VARCHAR(255),
    
    -- Settings
    settings JSONB DEFAULT '{}',
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'inactive'
    
    -- Subscription/License
    license_type VARCHAR(50),
    license_expires_at TIMESTAMP WITH TIME ZONE,
    max_users INTEGER,
    max_certificates INTEGER,
    
    -- Audit fields
    created_by_user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_org_status CHECK (status IN ('active', 'suspended', 'inactive')),
    CONSTRAINT fk_primary_contact FOREIGN KEY (primary_contact_user_id) REFERENCES users(id)
);

CREATE INDEX idx_organizations_code ON organizations(org_code) WHERE deleted_at IS NULL;
CREATE INDEX idx_organizations_status ON organizations(status) WHERE deleted_at IS NULL;

COMMENT ON TABLE organizations IS 'Multi-tenant organization management';

-- =====================================================================
-- USER ORGANIZATIONS TABLE
-- =====================================================================
-- Many-to-many relationship between users and organizations
-- =====================================================================

CREATE TABLE user_organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE,
    
    -- Audit fields
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT fk_user_org_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_org_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT uq_user_org UNIQUE (user_id, organization_id)
);

CREATE INDEX idx_user_orgs_user ON user_organizations(user_id) WHERE left_at IS NULL;
CREATE INDEX idx_user_orgs_org ON user_organizations(organization_id) WHERE left_at IS NULL;

COMMENT ON TABLE user_organizations IS 'User membership in organizations';

-- =====================================================================
-- POLICIES TABLE
-- =====================================================================
-- Certificate and security policies
-- =====================================================================

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(255) NOT NULL,
    policy_code VARCHAR(50) UNIQUE NOT NULL,
    policy_type VARCHAR(50) NOT NULL, -- 'certificate', 'key_management', 'access_control', 'compliance'
    
    -- Policy definition
    description TEXT,
    policy_rules JSONB NOT NULL,
    
    -- Scope
    organization_id UUID,
    applies_to_cert_types VARCHAR(50)[], -- Array of certificate types this policy applies to
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'draft', -- 'draft', 'active', 'inactive', 'archived'
    version INTEGER NOT NULL DEFAULT 1,
    
    -- Enforcement
    enforcement_level VARCHAR(50) NOT NULL DEFAULT 'mandatory', -- 'mandatory', 'advisory', 'audit_only'
    
    -- Validity
    effective_from TIMESTAMP WITH TIME ZONE,
    effective_until TIMESTAMP WITH TIME ZONE,
    
    -- Compliance
    compliance_frameworks VARCHAR(100)[], -- e.g., ['SOC2', 'ISO27001', 'PCI-DSS']
    
    -- Audit fields
    created_by_user_id UUID NOT NULL,
    approved_by_user_id UUID,
    approved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_policy_type CHECK (policy_type IN ('certificate', 'key_management', 'access_control', 'compliance', 'issuance')),
    CONSTRAINT chk_policy_status CHECK (status IN ('draft', 'active', 'inactive', 'archived')),
    CONSTRAINT chk_enforcement CHECK (enforcement_level IN ('mandatory', 'advisory', 'audit_only')),
    CONSTRAINT fk_policy_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_policy_creator FOREIGN KEY (created_by_user_id) REFERENCES users(id),
    CONSTRAINT fk_policy_approver FOREIGN KEY (approved_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_policies_code ON policies(policy_code) WHERE deleted_at IS NULL;
CREATE INDEX idx_policies_type ON policies(policy_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_policies_status ON policies(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_policies_org ON policies(organization_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE policies IS 'Certificate and security policies with rule definitions';
COMMENT ON COLUMN policies.policy_rules IS 'JSON defining policy rules: {"max_validity_days": 365, "min_key_size": 2048, "allowed_algorithms": ["RSA", "ECDSA"]}';

-- =====================================================================
-- WORKFLOWS TABLE
-- =====================================================================
-- Workflow definitions for certificate lifecycle
-- =====================================================================

CREATE TABLE workflows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_name VARCHAR(255) NOT NULL,
    workflow_code VARCHAR(50) UNIQUE NOT NULL,
    workflow_type VARCHAR(50) NOT NULL, -- 'certificate_request', 'renewal', 'revocation', 'key_rotation'
    
    -- Workflow definition
    description TEXT,
    workflow_definition JSONB NOT NULL,
    
    -- Configuration
    organization_id UUID,
    auto_approve_conditions JSONB,
    requires_approval BOOLEAN DEFAULT TRUE,
    approval_chain JSONB, -- Ordered list of approval steps
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'draft', -- 'draft', 'active', 'inactive', 'archived'
    version INTEGER NOT NULL DEFAULT 1,
    
    -- Audit fields
    created_by_user_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_workflow_type CHECK (workflow_type IN ('certificate_request', 'renewal', 'revocation', 'key_rotation', 'import', 'export')),
    CONSTRAINT chk_workflow_status CHECK (status IN ('draft', 'active', 'inactive', 'archived')),
    CONSTRAINT fk_workflow_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_workflow_creator FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_workflows_code ON workflows(workflow_code) WHERE deleted_at IS NULL;
CREATE INDEX idx_workflows_type ON workflows(workflow_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_workflows_status ON workflows(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_workflows_org ON workflows(organization_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE workflows IS 'Workflow definitions for certificate lifecycle management';
COMMENT ON COLUMN workflows.workflow_definition IS 'JSON defining workflow steps: {"steps": [{"step_id": 1, "type": "approval", "approvers": [...]}]}';

-- =====================================================================
-- WORKFLOW INSTANCES TABLE
-- =====================================================================
-- Running instances of workflows
-- =====================================================================

CREATE TABLE workflow_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_id UUID NOT NULL,
    instance_code VARCHAR(100) UNIQUE NOT NULL,
    
    -- Instance details
    workflow_type VARCHAR(50) NOT NULL,
    current_step INTEGER NOT NULL DEFAULT 1,
    current_step_name VARCHAR(255),
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'initiated', -- 'initiated', 'in_progress', 'pending_approval', 'approved', 'rejected', 'completed', 'failed', 'cancelled'
    
    -- Context
    context_data JSONB, -- Data passed through the workflow
    input_data JSONB, -- Original input data
    output_data JSONB, -- Final output data
    
    -- References to clm_secure_db
    certificate_id UUID, -- Certificate being processed (UUID reference only)
    certificate_request_id UUID, -- CSR being processed (UUID reference only)
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Ownership
    initiated_by_user_id UUID NOT NULL,
    organization_id UUID,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_workflow FOREIGN KEY (workflow_id) REFERENCES workflows(id),
    CONSTRAINT fk_workflow_initiator FOREIGN KEY (initiated_by_user_id) REFERENCES users(id),
    CONSTRAINT fk_workflow_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT chk_workflow_instance_status CHECK (status IN ('initiated', 'in_progress', 'pending_approval', 'approved', 'rejected', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX idx_workflow_instances_workflow ON workflow_instances(workflow_id);
CREATE INDEX idx_workflow_instances_status ON workflow_instances(status);
CREATE INDEX idx_workflow_instances_initiator ON workflow_instances(initiated_by_user_id);
CREATE INDEX idx_workflow_instances_cert ON workflow_instances(certificate_id);
CREATE INDEX idx_workflow_instances_org ON workflow_instances(organization_id);

COMMENT ON TABLE workflow_instances IS 'Active and historical workflow execution instances';

-- =====================================================================
-- WORKFLOW STEPS TABLE
-- =====================================================================
-- Individual steps in workflow execution
-- =====================================================================

CREATE TABLE workflow_steps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_instance_id UUID NOT NULL,
    step_number INTEGER NOT NULL,
    step_name VARCHAR(255) NOT NULL,
    step_type VARCHAR(50) NOT NULL, -- 'approval', 'validation', 'action', 'notification'
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'in_progress', 'completed', 'failed', 'skipped'
    
    -- Execution
    assigned_to_user_id UUID,
    assigned_to_role_id UUID,
    executed_by_user_id UUID,
    
    -- Data
    step_input JSONB,
    step_output JSONB,
    error_message TEXT,
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_workflow_instance FOREIGN KEY (workflow_instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE,
    CONSTRAINT fk_assigned_user FOREIGN KEY (assigned_to_user_id) REFERENCES users(id),
    CONSTRAINT fk_assigned_role FOREIGN KEY (assigned_to_role_id) REFERENCES roles(id),
    CONSTRAINT fk_executed_user FOREIGN KEY (executed_by_user_id) REFERENCES users(id),
    CONSTRAINT chk_step_type CHECK (step_type IN ('approval', 'validation', 'action', 'notification', 'decision')),
    CONSTRAINT chk_step_status CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'skipped'))
);

CREATE INDEX idx_workflow_steps_instance ON workflow_steps(workflow_instance_id);
CREATE INDEX idx_workflow_steps_status ON workflow_steps(status);
CREATE INDEX idx_workflow_steps_assigned_user ON workflow_steps(assigned_to_user_id) WHERE status IN ('pending', 'in_progress');
CREATE INDEX idx_workflow_steps_assigned_role ON workflow_steps(assigned_to_role_id) WHERE status IN ('pending', 'in_progress');

COMMENT ON TABLE workflow_steps IS 'Individual steps in workflow execution with assignment and tracking';

-- =====================================================================
-- NOTIFICATIONS TABLE
-- =====================================================================
-- System notifications for users
-- =====================================================================

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    notification_type VARCHAR(50) NOT NULL, -- 'certificate_expiring', 'approval_required', 'workflow_completed', 'policy_violation'
    
    -- Target
    user_id UUID NOT NULL,
    organization_id UUID,
    
    -- Content
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    notification_data JSONB,
    
    -- Priority
    priority VARCHAR(20) NOT NULL DEFAULT 'normal', -- 'low', 'normal', 'high', 'critical'
    
    -- Status
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP WITH TIME ZONE,
    
    -- Delivery
    delivery_channels VARCHAR(50)[] DEFAULT ARRAY['in_app'], -- 'in_app', 'email', 'sms', 'webhook'
    email_sent BOOLEAN DEFAULT FALSE,
    email_sent_at TIMESTAMP WITH TIME ZONE,
    
    -- Links
    action_url VARCHAR(500),
    related_resource_type VARCHAR(50), -- 'certificate', 'workflow', 'policy'
    related_resource_id UUID,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT fk_notification_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_notification_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT chk_notification_priority CHECK (priority IN ('low', 'normal', 'high', 'critical'))
);

CREATE INDEX idx_notifications_user ON notifications(user_id) WHERE is_read = FALSE;
CREATE INDEX idx_notifications_priority ON notifications(priority, created_at DESC) WHERE is_read = FALSE;
CREATE INDEX idx_notifications_resource ON notifications(related_resource_type, related_resource_id);
CREATE INDEX idx_notifications_created ON notifications(created_at DESC);

COMMENT ON TABLE notifications IS 'User notifications for certificate and workflow events';

-- =====================================================================
-- AUDIT LOG TABLE
-- =====================================================================
-- Comprehensive audit log for all system operations
-- =====================================================================

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL, -- 'authentication', 'authorization', 'certificate', 'policy', 'workflow', 'user_management'
    severity VARCHAR(20) NOT NULL, -- 'info', 'warning', 'error', 'critical'
    
    -- Actor
    user_id UUID,
    username VARCHAR(255),
    organization_id UUID,
    
    -- Resource
    resource_type VARCHAR(50), -- 'user', 'role', 'policy', 'workflow', 'certificate_reference'
    resource_id UUID,
    resource_name VARCHAR(255),
    
    -- Action
    action VARCHAR(100) NOT NULL, -- 'created', 'updated', 'deleted', 'accessed', 'approved', 'rejected'
    action_result VARCHAR(50) NOT NULL, -- 'success', 'failure', 'partial'
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    
    -- Changes
    changes_before JSONB, -- State before change
    changes_after JSONB, -- State after change
    change_summary TEXT,
    
    -- Additional details
    event_data JSONB,
    error_message TEXT,
    
    -- Timestamp
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_audit_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT chk_audit_category CHECK (event_category IN ('authentication', 'authorization', 'certificate', 'policy', 'workflow', 'user_management', 'system')),
    CONSTRAINT chk_audit_severity CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    CONSTRAINT chk_audit_result CHECK (action_result IN ('success', 'failure', 'partial'))
);

CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_category ON audit_log(event_category);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(event_timestamp DESC);
CREATE INDEX idx_audit_log_severity ON audit_log(severity) WHERE severity IN ('error', 'critical');
CREATE INDEX idx_audit_log_org ON audit_log(organization_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);

COMMENT ON TABLE audit_log IS 'Comprehensive audit trail for all system operations';

-- =====================================================================
-- API KEYS TABLE
-- =====================================================================
-- API keys for programmatic access
-- =====================================================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    key_prefix VARCHAR(20) NOT NULL, -- First few chars for identification
    
    -- Ownership
    user_id UUID NOT NULL,
    organization_id UUID,
    
    -- Permissions
    scopes VARCHAR(100)[], -- API scopes this key has access to
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Usage
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_ip INET,
    usage_count INTEGER DEFAULT 0,
    
    -- Expiration
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by_user_id UUID,
    
    CONSTRAINT fk_api_key_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_api_key_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_api_key_revoker FOREIGN KEY (revoked_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id) WHERE is_active = TRUE AND revoked_at IS NULL;
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE is_active = TRUE;

COMMENT ON TABLE api_keys IS 'API keys for programmatic access to the platform';

-- =====================================================================
-- SESSIONS TABLE
-- =====================================================================
-- User session management
-- =====================================================================

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    
    -- Session data
    session_data JSONB,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    invalidated_at TIMESTAMP WITH TIME ZONE,
    invalidation_reason VARCHAR(255),
    
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user ON sessions(user_id) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_expires ON sessions(expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_session_id ON sessions(session_id) WHERE is_active = TRUE;

COMMENT ON TABLE sessions IS 'Active user sessions for authentication';

-- =====================================================================
-- CERTIFICATE METADATA TABLE
-- =====================================================================
-- Non-sensitive certificate metadata in core database
-- =====================================================================

CREATE TABLE certificate_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID UNIQUE NOT NULL, -- References certificates.id in clm_secure_db
    
    -- Basic information (duplicated for query performance)
    common_name VARCHAR(255) NOT NULL,
    certificate_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    
    -- Dates
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Ownership
    owner_user_id UUID NOT NULL,
    organization_id UUID,
    
    -- Tags and categorization
    tags VARCHAR(100)[],
    category VARCHAR(100),
    environment VARCHAR(50), -- 'production', 'staging', 'development', 'testing'
    
    -- Custom metadata
    custom_fields JSONB,
    notes TEXT,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT fk_cert_metadata_owner FOREIGN KEY (owner_user_id) REFERENCES users(id),
    CONSTRAINT fk_cert_metadata_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT chk_cert_metadata_type CHECK (certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')),
    CONSTRAINT chk_cert_metadata_status CHECK (status IN ('pending', 'active', 'expiring', 'expired', 'revoked', 'suspended'))
);

CREATE INDEX idx_cert_metadata_cert_id ON certificate_metadata(certificate_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_metadata_owner ON certificate_metadata(owner_user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_metadata_org ON certificate_metadata(organization_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_metadata_status ON certificate_metadata(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_metadata_expiry ON certificate_metadata(not_after) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_metadata_tags ON certificate_metadata USING GIN(tags);
CREATE INDEX idx_cert_metadata_environment ON certificate_metadata(environment) WHERE deleted_at IS NULL;

COMMENT ON TABLE certificate_metadata IS 'Non-sensitive certificate metadata for querying and organization (certificate data stored in clm_secure_db)';

-- =====================================================================
-- TRIGGERS FOR UPDATED_AT
-- =====================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_workflows_updated_at
    BEFORE UPDATE ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_workflow_instances_updated_at
    BEFORE UPDATE ON workflow_instances
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_certificate_metadata_updated_at
    BEFORE UPDATE ON certificate_metadata
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =====================================================================
-- VIEWS
-- =====================================================================

-- View for active users with their roles
CREATE VIEW active_users_with_roles AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.display_name,
    u.status,
    u.last_login_at,
    u.mfa_enabled,
    ARRAY_AGG(r.role_name) FILTER (WHERE r.role_name IS NOT NULL) AS roles,
    ARRAY_AGG(r.role_code) FILTER (WHERE r.role_code IS NOT NULL) AS role_codes
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.revoked_at IS NULL
LEFT JOIN roles r ON ur.role_id = r.id AND r.deleted_at IS NULL
WHERE u.deleted_at IS NULL AND u.status = 'active'
GROUP BY u.id, u.username, u.email, u.display_name, u.status, u.last_login_at, u.mfa_enabled;

COMMENT ON VIEW active_users_with_roles IS 'Active users with their assigned roles';

-- View for pending approvals
CREATE VIEW pending_approvals AS
SELECT 
    ws.id AS step_id,
    wi.id AS workflow_instance_id,
    wi.instance_code,
    w.workflow_name,
    w.workflow_type,
    ws.step_name,
    ws.assigned_to_user_id,
    ws.assigned_to_role_id,
    wi.initiated_by_user_id,
    wi.started_at,
    ws.created_at AS step_created_at
FROM workflow_steps ws
JOIN workflow_instances wi ON ws.workflow_instance_id = wi.id
JOIN workflows w ON wi.workflow_id = w.id
WHERE ws.status = 'pending' 
    AND ws.step_type = 'approval'
    AND wi.status IN ('in_progress', 'pending_approval');

COMMENT ON VIEW pending_approvals IS 'All pending approval steps across workflows';

-- View for certificate summary (joining with metadata)
CREATE VIEW certificate_summary AS
SELECT 
    cm.certificate_id,
    cm.common_name,
    cm.certificate_type,
    cm.status,
    cm.not_before,
    cm.not_after,
    EXTRACT(DAY FROM (cm.not_after - CURRENT_TIMESTAMP)) AS days_until_expiry,
    u.username AS owner_username,
    u.email AS owner_email,
    o.org_name AS organization_name,
    cm.environment,
    cm.tags,
    cm.created_at
FROM certificate_metadata cm
JOIN users u ON cm.owner_user_id = u.id
LEFT JOIN organizations o ON cm.organization_id = o.id
WHERE cm.deleted_at IS NULL;

COMMENT ON VIEW certificate_summary IS 'Summary view of certificates with owner and organization details';

-- =====================================================================
-- INITIAL SEED DATA
-- =====================================================================

-- Create default system roles
INSERT INTO roles (role_name, role_code, description, permissions, is_system_role, created_at) VALUES
('System Administrator', 'SYSTEM_ADMIN', 'Full system access with all permissions', 
 '{"users": ["create", "read", "update", "delete"], "roles": ["create", "read", "update", "delete"], "certificates": ["create", "read", "update", "delete", "revoke", "export"], "policies": ["create", "read", "update", "delete"], "workflows": ["create", "read", "update", "delete"], "organizations": ["create", "read", "update", "delete"], "audit": ["read"]}',
 TRUE, CURRENT_TIMESTAMP),

('Certificate Administrator', 'CERT_ADMIN', 'Manage certificates and certificate policies',
 '{"certificates": ["create", "read", "update", "delete", "revoke"], "policies": ["read", "update"], "workflows": ["read", "execute"], "audit": ["read"]}',
 TRUE, CURRENT_TIMESTAMP),

('Certificate Operator', 'CERT_OPERATOR', 'Request and manage certificates',
 '{"certificates": ["create", "read", "update"], "workflows": ["read", "execute"], "policies": ["read"]}',
 TRUE, CURRENT_TIMESTAMP),

('Approver', 'APPROVER', 'Approve certificate requests and workflow actions',
 '{"certificates": ["read"], "workflows": ["read", "approve"], "policies": ["read"]}',
 TRUE, CURRENT_TIMESTAMP),

('Auditor', 'AUDITOR', 'Read-only access to audit logs and certificates',
 '{"certificates": ["read"], "policies": ["read"], "workflows": ["read"], "audit": ["read"], "users": ["read"]}',
 TRUE, CURRENT_TIMESTAMP),

('User', 'USER', 'Basic user access',
 '{"certificates": ["read"], "workflows": ["read"], "policies": ["read"]}',
 TRUE, CURRENT_TIMESTAMP);

-- =====================================================================
-- END OF CORE SCHEMA
-- =====================================================================
