-- =====================================================================
-- CLM Secure Database - Initial Schema
-- =====================================================================
-- Database: clm_secure_db
-- Purpose: Store sensitive certificate and cryptographic data
-- Security: This database should have restricted access and encryption at rest
-- =====================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- ENCRYPTION KEYS TABLE
-- =====================================================================
-- Stores encryption keys and key management metadata
-- =====================================================================

CREATE TABLE encryption_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(255) UNIQUE NOT NULL,
    key_type VARCHAR(50) NOT NULL, -- 'master', 'data', 'session'
    algorithm VARCHAR(50) NOT NULL, -- 'AES-256-GCM', 'RSA-4096', etc.
    key_status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'rotating', 'retired', 'revoked'
    encrypted_key_material BYTEA NOT NULL,
    key_wrap_algorithm VARCHAR(50) NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    rotation_schedule_days INTEGER,
    last_rotated_at TIMESTAMP WITH TIME ZONE,
    next_rotation_at TIMESTAMP WITH TIME ZONE,
    created_by_user_id UUID NOT NULL, -- References users table in clm_core_db
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_key_type CHECK (key_type IN ('master', 'data', 'session', 'hmac')),
    CONSTRAINT chk_key_status CHECK (key_status IN ('active', 'rotating', 'retired', 'revoked'))
);

CREATE INDEX idx_encryption_keys_status ON encryption_keys(key_status) WHERE deleted_at IS NULL;
CREATE INDEX idx_encryption_keys_type ON encryption_keys(key_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_encryption_keys_next_rotation ON encryption_keys(next_rotation_at) WHERE deleted_at IS NULL AND key_status = 'active';

COMMENT ON TABLE encryption_keys IS 'Manages encryption keys for certificate and data protection';
COMMENT ON COLUMN encryption_keys.key_wrap_algorithm IS 'Algorithm used to wrap/encrypt the key material itself';

-- =====================================================================
-- CERTIFICATES TABLE
-- =====================================================================
-- Stores X.509 certificates and their metadata
-- =====================================================================

CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id VARCHAR(255) UNIQUE NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    certificate_type VARCHAR(50) NOT NULL, -- 'root', 'intermediate', 'leaf', 'client', 'server'
    
    -- Certificate data
    pem_encoded_cert TEXT NOT NULL,
    der_encoded_cert BYTEA NOT NULL,
    certificate_chain TEXT[], -- Array of PEM-encoded certificates in chain
    
    -- Identifiers
    serial_number VARCHAR(255) NOT NULL,
    thumbprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
    thumbprint_sha1 VARCHAR(40),
    subject_key_identifier VARCHAR(255),
    authority_key_identifier VARCHAR(255),
    
    -- Certificate details
    issuer_dn TEXT NOT NULL,
    subject_dn TEXT NOT NULL,
    subject_alternative_names JSONB, -- Array of SANs with types
    key_algorithm VARCHAR(50) NOT NULL, -- 'RSA', 'ECDSA', 'Ed25519'
    key_size INTEGER, -- Bit length for RSA, curve name stored separately
    signature_algorithm VARCHAR(100) NOT NULL,
    
    -- Validity
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'pending', 'active', 'expiring', 'expired', 'revoked', 'suspended'
    revocation_reason VARCHAR(100),
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Encryption metadata
    encryption_key_id UUID, -- References encryption_keys table
    is_encrypted BOOLEAN DEFAULT FALSE,
    encryption_algorithm VARCHAR(50),
    
    -- References (to clm_core_db)
    owner_user_id UUID NOT NULL, -- User who owns/manages this certificate
    policy_id UUID, -- Policy governing this certificate
    workflow_id UUID, -- Workflow that created/approved this certificate
    
    -- Audit fields
    created_by_user_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_cert_type CHECK (certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')),
    CONSTRAINT chk_cert_status CHECK (status IN ('pending', 'active', 'expiring', 'expired', 'revoked', 'suspended')),
    CONSTRAINT chk_validity_dates CHECK (not_before < not_after),
    CONSTRAINT fk_encryption_key FOREIGN KEY (encryption_key_id) REFERENCES encryption_keys(id)
);

CREATE INDEX idx_certificates_status ON certificates(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_type ON certificates(certificate_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_owner ON certificates(owner_user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_policy ON certificates(policy_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_expiry ON certificates(not_after) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_serial ON certificates(serial_number);
CREATE INDEX idx_certificates_common_name ON certificates(common_name) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_workflow ON certificates(workflow_id) WHERE deleted_at IS NULL;

COMMENT ON TABLE certificates IS 'Stores X.509 certificates and associated metadata';
COMMENT ON COLUMN certificates.subject_alternative_names IS 'JSON array of SANs: [{"type": "DNS", "value": "example.com"}, ...]';

-- =====================================================================
-- PRIVATE KEYS TABLE
-- =====================================================================
-- Stores private keys with encryption
-- =====================================================================

CREATE TABLE private_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID NOT NULL UNIQUE, -- One-to-one with certificates
    
    -- Key data (always encrypted)
    encrypted_key_material BYTEA NOT NULL,
    encryption_key_id UUID NOT NULL,
    encryption_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    encryption_iv BYTEA NOT NULL,
    encryption_auth_tag BYTEA,
    
    -- Key metadata
    key_algorithm VARCHAR(50) NOT NULL, -- 'RSA', 'ECDSA', 'Ed25519'
    key_size INTEGER, -- Bit length
    curve_name VARCHAR(50), -- For ECDSA: 'P-256', 'P-384', 'P-521', 'secp256k1'
    
    -- Key format
    key_format VARCHAR(50) NOT NULL DEFAULT 'PKCS8', -- 'PKCS8', 'PKCS1', 'SEC1'
    is_exportable BOOLEAN DEFAULT FALSE,
    
    -- HSM/Key storage
    is_hsm_backed BOOLEAN DEFAULT FALSE,
    hsm_key_id VARCHAR(255),
    hsm_slot_id VARCHAR(255),
    
    -- Access control
    access_policy JSONB, -- JSON defining who can access this key and how
    last_accessed_at TIMESTAMP WITH TIME ZONE,
    access_count INTEGER DEFAULT 0,
    
    -- Audit fields
    created_by_user_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT fk_certificate FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    CONSTRAINT fk_encryption_key FOREIGN KEY (encryption_key_id) REFERENCES encryption_keys(id),
    CONSTRAINT chk_key_algorithm CHECK (key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'Ed448')),
    CONSTRAINT chk_hsm_consistency CHECK (
        (is_hsm_backed = TRUE AND hsm_key_id IS NOT NULL) OR
        (is_hsm_backed = FALSE)
    )
);

CREATE INDEX idx_private_keys_cert ON private_keys(certificate_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_private_keys_encryption_key ON private_keys(encryption_key_id);
CREATE INDEX idx_private_keys_hsm ON private_keys(hsm_key_id) WHERE is_hsm_backed = TRUE AND deleted_at IS NULL;
CREATE INDEX idx_private_keys_last_accessed ON private_keys(last_accessed_at) WHERE deleted_at IS NULL;

COMMENT ON TABLE private_keys IS 'Stores encrypted private keys for certificates';
COMMENT ON COLUMN private_keys.access_policy IS 'JSON defining access controls: {"allowed_operations": ["sign", "decrypt"], "allowed_user_ids": [...]}';

-- =====================================================================
-- CERTIFICATE SIGNING REQUESTS (CSRs)
-- =====================================================================
-- Stores CSR data for certificate requests
-- =====================================================================

CREATE TABLE certificate_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(255) UNIQUE NOT NULL,
    
    -- CSR data
    pem_encoded_csr TEXT NOT NULL,
    der_encoded_csr BYTEA NOT NULL,
    
    -- Request details
    common_name VARCHAR(255) NOT NULL,
    subject_dn TEXT NOT NULL,
    subject_alternative_names JSONB,
    key_algorithm VARCHAR(50) NOT NULL,
    key_size INTEGER,
    requested_validity_days INTEGER NOT NULL,
    certificate_type VARCHAR(50) NOT NULL,
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'fulfilled', 'expired'
    rejection_reason TEXT,
    
    -- Result
    issued_certificate_id UUID, -- References certificates table
    
    -- References (to clm_core_db)
    requester_user_id UUID NOT NULL,
    approver_user_id UUID,
    policy_id UUID,
    workflow_id UUID,
    
    -- Audit fields
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP WITH TIME ZONE,
    fulfilled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT chk_csr_status CHECK (status IN ('pending', 'approved', 'rejected', 'fulfilled', 'expired', 'cancelled')),
    CONSTRAINT chk_csr_cert_type CHECK (certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')),
    CONSTRAINT fk_issued_certificate FOREIGN KEY (issued_certificate_id) REFERENCES certificates(id)
);

CREATE INDEX idx_cert_requests_status ON certificate_requests(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_requests_requester ON certificate_requests(requester_user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_requests_workflow ON certificate_requests(workflow_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_requests_issued_cert ON certificate_requests(issued_certificate_id);

COMMENT ON TABLE certificate_requests IS 'Stores certificate signing requests pending approval';

-- =====================================================================
-- CERTIFICATE REVOCATIONS
-- =====================================================================
-- Stores certificate revocation details
-- =====================================================================

CREATE TABLE certificate_revocations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID NOT NULL,
    
    -- Revocation details
    revocation_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revocation_reason VARCHAR(100) NOT NULL, -- CRL reason codes
    invalidity_date TIMESTAMP WITH TIME ZONE, -- When cert became invalid
    
    -- CRL information
    crl_entry_added BOOLEAN DEFAULT FALSE,
    crl_sequence_number BIGINT,
    ocsp_status_updated BOOLEAN DEFAULT FALSE,
    
    -- References (to clm_core_db)
    revoked_by_user_id UUID NOT NULL,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_revoked_certificate FOREIGN KEY (certificate_id) REFERENCES certificates(id),
    CONSTRAINT chk_revocation_reason CHECK (revocation_reason IN (
        'unspecified',
        'key_compromise',
        'ca_compromise',
        'affiliation_changed',
        'superseded',
        'cessation_of_operation',
        'certificate_hold',
        'remove_from_crl',
        'privilege_withdrawn',
        'aa_compromise'
    ))
);

CREATE INDEX idx_cert_revocations_cert ON certificate_revocations(certificate_id);
CREATE INDEX idx_cert_revocations_date ON certificate_revocations(revocation_date);
CREATE INDEX idx_cert_revocations_reason ON certificate_revocations(revocation_reason);

COMMENT ON TABLE certificate_revocations IS 'Tracks certificate revocation details and CRL/OCSP status';

-- =====================================================================
-- KEY ROTATION HISTORY
-- =====================================================================
-- Tracks encryption key rotation history
-- =====================================================================

CREATE TABLE key_rotation_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    old_key_id UUID NOT NULL,
    new_key_id UUID NOT NULL,
    rotation_type VARCHAR(50) NOT NULL, -- 'scheduled', 'emergency', 'compromise', 'manual'
    rotation_reason TEXT,
    items_re_encrypted INTEGER DEFAULT 0,
    rotation_started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_completed_at TIMESTAMP WITH TIME ZONE,
    rotation_status VARCHAR(50) NOT NULL DEFAULT 'in_progress', -- 'in_progress', 'completed', 'failed', 'rolled_back'
    error_message TEXT,
    
    -- References (to clm_core_db)
    initiated_by_user_id UUID NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_old_key FOREIGN KEY (old_key_id) REFERENCES encryption_keys(id),
    CONSTRAINT fk_new_key FOREIGN KEY (new_key_id) REFERENCES encryption_keys(id),
    CONSTRAINT chk_rotation_type CHECK (rotation_type IN ('scheduled', 'emergency', 'compromise', 'manual')),
    CONSTRAINT chk_rotation_status CHECK (rotation_status IN ('in_progress', 'completed', 'failed', 'rolled_back'))
);

CREATE INDEX idx_key_rotation_old_key ON key_rotation_history(old_key_id);
CREATE INDEX idx_key_rotation_new_key ON key_rotation_history(new_key_id);
CREATE INDEX idx_key_rotation_status ON key_rotation_history(rotation_status);
CREATE INDEX idx_key_rotation_started ON key_rotation_history(rotation_started_at);

COMMENT ON TABLE key_rotation_history IS 'Audit trail for encryption key rotations';

-- =====================================================================
-- SECURE AUDIT LOG
-- =====================================================================
-- Audit log for sensitive operations in secure database
-- =====================================================================

CREATE TABLE secure_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL, -- 'key_access', 'cert_access', 'key_rotation', 'revocation'
    severity VARCHAR(20) NOT NULL, -- 'info', 'warning', 'error', 'critical'
    
    -- Event details
    resource_type VARCHAR(50) NOT NULL, -- 'certificate', 'private_key', 'encryption_key', 'csr'
    resource_id UUID NOT NULL,
    action VARCHAR(100) NOT NULL, -- 'created', 'read', 'updated', 'deleted', 'exported', 'signed', 'encrypted', 'decrypted'
    
    -- Context
    user_id UUID NOT NULL, -- User performing the action
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    
    -- Details
    event_data JSONB,
    result VARCHAR(50) NOT NULL, -- 'success', 'failure', 'partial'
    error_message TEXT,
    
    -- Timestamp
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT chk_secure_event_category CHECK (event_category IN ('key_access', 'cert_access', 'key_rotation', 'revocation', 'csr', 'export')),
    CONSTRAINT chk_secure_severity CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    CONSTRAINT chk_secure_result CHECK (result IN ('success', 'failure', 'partial'))
);

CREATE INDEX idx_secure_audit_event_type ON secure_audit_log(event_type);
CREATE INDEX idx_secure_audit_category ON secure_audit_log(event_category);
CREATE INDEX idx_secure_audit_user ON secure_audit_log(user_id);
CREATE INDEX idx_secure_audit_resource ON secure_audit_log(resource_type, resource_id);
CREATE INDEX idx_secure_audit_timestamp ON secure_audit_log(event_timestamp DESC);
CREATE INDEX idx_secure_audit_severity ON secure_audit_log(severity) WHERE severity IN ('error', 'critical');

COMMENT ON TABLE secure_audit_log IS 'Immutable audit log for all sensitive operations in secure database';

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

CREATE TRIGGER trg_encryption_keys_updated_at
    BEFORE UPDATE ON encryption_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_certificates_updated_at
    BEFORE UPDATE ON certificates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_private_keys_updated_at
    BEFORE UPDATE ON private_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_certificate_requests_updated_at
    BEFORE UPDATE ON certificate_requests
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =====================================================================
-- VIEWS
-- =====================================================================

-- View for active certificates with basic info (no sensitive data)
CREATE VIEW active_certificates AS
SELECT 
    id,
    certificate_id,
    common_name,
    certificate_type,
    serial_number,
    thumbprint_sha256,
    subject_dn,
    issuer_dn,
    not_before,
    not_after,
    status,
    owner_user_id,
    policy_id,
    workflow_id,
    created_at,
    updated_at
FROM certificates
WHERE deleted_at IS NULL AND status IN ('active', 'expiring');

COMMENT ON VIEW active_certificates IS 'View of active certificates without sensitive cryptographic material';

-- View for expiring certificates (within 30 days)
CREATE VIEW expiring_certificates AS
SELECT 
    id,
    certificate_id,
    common_name,
    certificate_type,
    serial_number,
    not_after,
    owner_user_id,
    policy_id,
    EXTRACT(DAY FROM (not_after - CURRENT_TIMESTAMP)) AS days_until_expiry
FROM certificates
WHERE deleted_at IS NULL 
    AND status = 'active'
    AND not_after <= CURRENT_TIMESTAMP + INTERVAL '30 days'
    AND not_after > CURRENT_TIMESTAMP
ORDER BY not_after ASC;

COMMENT ON VIEW expiring_certificates IS 'Certificates expiring within 30 days';

-- =====================================================================
-- ROW LEVEL SECURITY PLACEHOLDERS
-- =====================================================================
-- Note: RLS policies should be configured based on application requirements
-- Enable RLS on sensitive tables:
-- ALTER TABLE private_keys ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE encryption_keys ENABLE ROW LEVEL SECURITY;
-- =====================================================================
