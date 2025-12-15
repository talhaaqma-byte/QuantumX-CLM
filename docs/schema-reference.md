# Database Schema Reference

Complete reference documentation for all tables in the CLM platform databases.

## Table of Contents

### clm_secure_db
- [encryption_keys](#encryption_keys)
- [certificates](#certificates)
- [private_keys](#private_keys)
- [certificate_requests](#certificate_requests)
- [certificate_revocations](#certificate_revocations)
- [key_rotation_history](#key_rotation_history)
- [secure_audit_log](#secure_audit_log)

### clm_core_db
- [users](#users)
- [roles](#roles)
- [user_roles](#user_roles)
- [organizations](#organizations)
- [user_organizations](#user_organizations)
- [policies](#policies)
- [workflows](#workflows)
- [workflow_instances](#workflow_instances)
- [workflow_steps](#workflow_steps)
- [notifications](#notifications)
- [audit_log](#audit_log)
- [api_keys](#api_keys)
- [sessions](#sessions)
- [certificate_metadata](#certificate_metadata)

---

## clm_secure_db Tables

### encryption_keys

Manages encryption keys used throughout the system.

**Purpose**: Store and manage encryption keys with support for rotation and versioning.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| key_id | VARCHAR(255) | NO | - | Unique key identifier |
| key_type | VARCHAR(50) | NO | - | Type: 'master', 'data', 'session', 'hmac' |
| algorithm | VARCHAR(50) | NO | - | Encryption algorithm (e.g., 'AES-256-GCM') |
| key_status | VARCHAR(50) | NO | 'active' | Status: 'active', 'rotating', 'retired', 'revoked' |
| encrypted_key_material | BYTEA | NO | - | Encrypted key data |
| key_wrap_algorithm | VARCHAR(50) | NO | - | Algorithm used to wrap this key |
| key_version | INTEGER | NO | 1 | Version number for rotation |
| rotation_schedule_days | INTEGER | YES | - | Days between rotations |
| last_rotated_at | TIMESTAMP WITH TIME ZONE | YES | - | Last rotation timestamp |
| next_rotation_at | TIMESTAMP WITH TIME ZONE | YES | - | Scheduled next rotation |
| created_by_user_id | UUID | NO | - | User who created the key (references clm_core_db.users) |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_encryption_keys_status` on (key_status) WHERE deleted_at IS NULL
- `idx_encryption_keys_type` on (key_type) WHERE deleted_at IS NULL
- `idx_encryption_keys_next_rotation` on (next_rotation_at) WHERE deleted_at IS NULL AND key_status = 'active'

**Constraints**:
- CHECK: key_type IN ('master', 'data', 'session', 'hmac')
- CHECK: key_status IN ('active', 'rotating', 'retired', 'revoked')
- UNIQUE: key_id

---

### certificates

Stores X.509 certificates and their metadata.

**Purpose**: Central repository for all SSL/TLS certificates managed by the system.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| certificate_id | VARCHAR(255) | NO | - | Unique certificate identifier |
| common_name | VARCHAR(255) | NO | - | Certificate Common Name (CN) |
| certificate_type | VARCHAR(50) | NO | - | Type: 'root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email' |
| pem_encoded_cert | TEXT | NO | - | PEM format certificate |
| der_encoded_cert | BYTEA | NO | - | DER format certificate |
| certificate_chain | TEXT[] | YES | - | Array of PEM certificates in chain |
| serial_number | VARCHAR(255) | NO | - | Certificate serial number |
| thumbprint_sha256 | VARCHAR(64) | NO | - | SHA-256 thumbprint (hex) |
| thumbprint_sha1 | VARCHAR(40) | YES | - | SHA-1 thumbprint (hex, legacy) |
| subject_key_identifier | VARCHAR(255) | YES | - | X.509 Subject Key Identifier |
| authority_key_identifier | VARCHAR(255) | YES | - | X.509 Authority Key Identifier |
| issuer_dn | TEXT | NO | - | Issuer Distinguished Name |
| subject_dn | TEXT | NO | - | Subject Distinguished Name |
| subject_alternative_names | JSONB | YES | - | Array of SANs with types |
| key_algorithm | VARCHAR(50) | NO | - | Algorithm: 'RSA', 'ECDSA', 'Ed25519' |
| key_size | INTEGER | YES | - | Key size in bits (for RSA) |
| signature_algorithm | VARCHAR(100) | NO | - | Signature algorithm used |
| not_before | TIMESTAMP WITH TIME ZONE | NO | - | Certificate valid from |
| not_after | TIMESTAMP WITH TIME ZONE | NO | - | Certificate valid until |
| status | VARCHAR(50) | NO | 'active' | Status: 'pending', 'active', 'expiring', 'expired', 'revoked', 'suspended' |
| revocation_reason | VARCHAR(100) | YES | - | Reason for revocation |
| revoked_at | TIMESTAMP WITH TIME ZONE | YES | - | Revocation timestamp |
| encryption_key_id | UUID | YES | - | Key used to encrypt sensitive fields |
| is_encrypted | BOOLEAN | NO | FALSE | Whether certificate data is encrypted |
| encryption_algorithm | VARCHAR(50) | YES | - | Algorithm if encrypted |
| owner_user_id | UUID | NO | - | Owner (references clm_core_db.users) |
| policy_id | UUID | YES | - | Associated policy (references clm_core_db.policies) |
| workflow_id | UUID | YES | - | Workflow that created this (references clm_core_db.workflows) |
| created_by_user_id | UUID | NO | - | Creator (references clm_core_db.users) |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_certificates_status` on (status) WHERE deleted_at IS NULL
- `idx_certificates_type` on (certificate_type) WHERE deleted_at IS NULL
- `idx_certificates_owner` on (owner_user_id) WHERE deleted_at IS NULL
- `idx_certificates_policy` on (policy_id) WHERE deleted_at IS NULL
- `idx_certificates_expiry` on (not_after) WHERE deleted_at IS NULL
- `idx_certificates_serial` on (serial_number)
- `idx_certificates_common_name` on (common_name) WHERE deleted_at IS NULL
- `idx_certificates_workflow` on (workflow_id) WHERE deleted_at IS NULL

**Constraints**:
- CHECK: certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')
- CHECK: status IN ('pending', 'active', 'expiring', 'expired', 'revoked', 'suspended')
- CHECK: not_before < not_after
- UNIQUE: certificate_id, thumbprint_sha256
- FOREIGN KEY: encryption_key_id → encryption_keys(id)

**Example JSONB format for subject_alternative_names**:
```json
[
  {"type": "DNS", "value": "example.com"},
  {"type": "DNS", "value": "*.example.com"},
  {"type": "IP", "value": "192.168.1.1"},
  {"type": "EMAIL", "value": "admin@example.com"}
]
```

---

### private_keys

Stores encrypted private keys associated with certificates.

**Purpose**: Secure storage of private key material with encryption and access controls.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| certificate_id | UUID | NO | - | Associated certificate (one-to-one) |
| encrypted_key_material | BYTEA | NO | - | Encrypted private key data |
| encryption_key_id | UUID | NO | - | Key used for encryption |
| encryption_algorithm | VARCHAR(50) | NO | 'AES-256-GCM' | Encryption algorithm |
| encryption_iv | BYTEA | NO | - | Initialization vector |
| encryption_auth_tag | BYTEA | YES | - | Authentication tag (for AEAD) |
| key_algorithm | VARCHAR(50) | NO | - | Algorithm: 'RSA', 'ECDSA', 'Ed25519', 'Ed448' |
| key_size | INTEGER | YES | - | Key size in bits |
| curve_name | VARCHAR(50) | YES | - | Curve for ECDSA: 'P-256', 'P-384', 'P-521' |
| key_format | VARCHAR(50) | NO | 'PKCS8' | Format: 'PKCS8', 'PKCS1', 'SEC1' |
| is_exportable | BOOLEAN | NO | FALSE | Whether key can be exported |
| is_hsm_backed | BOOLEAN | NO | FALSE | Whether stored in HSM |
| hsm_key_id | VARCHAR(255) | YES | - | HSM key identifier |
| hsm_slot_id | VARCHAR(255) | YES | - | HSM slot identifier |
| access_policy | JSONB | YES | - | Access control rules |
| last_accessed_at | TIMESTAMP WITH TIME ZONE | YES | - | Last access timestamp |
| access_count | INTEGER | NO | 0 | Number of times accessed |
| created_by_user_id | UUID | NO | - | Creator (references clm_core_db.users) |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_private_keys_cert` on (certificate_id) WHERE deleted_at IS NULL
- `idx_private_keys_encryption_key` on (encryption_key_id)
- `idx_private_keys_hsm` on (hsm_key_id) WHERE is_hsm_backed = TRUE AND deleted_at IS NULL
- `idx_private_keys_last_accessed` on (last_accessed_at) WHERE deleted_at IS NULL

**Constraints**:
- CHECK: key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'Ed448')
- CHECK: (is_hsm_backed = TRUE AND hsm_key_id IS NOT NULL) OR (is_hsm_backed = FALSE)
- UNIQUE: certificate_id
- FOREIGN KEY: certificate_id → certificates(id) ON DELETE CASCADE
- FOREIGN KEY: encryption_key_id → encryption_keys(id)

**Example JSONB format for access_policy**:
```json
{
  "allowed_operations": ["sign", "decrypt"],
  "allowed_user_ids": ["uuid1", "uuid2"],
  "allowed_role_codes": ["CERT_ADMIN"],
  "max_uses_per_day": 100,
  "require_mfa": true
}
```

---

### certificate_requests

Stores Certificate Signing Requests (CSRs).

**Purpose**: Track certificate requests through approval workflows.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| request_id | VARCHAR(255) | NO | - | Unique request identifier |
| pem_encoded_csr | TEXT | NO | - | PEM format CSR |
| der_encoded_csr | BYTEA | NO | - | DER format CSR |
| common_name | VARCHAR(255) | NO | - | Requested Common Name |
| subject_dn | TEXT | NO | - | Subject Distinguished Name |
| subject_alternative_names | JSONB | YES | - | Requested SANs |
| key_algorithm | VARCHAR(50) | NO | - | Key algorithm |
| key_size | INTEGER | YES | - | Key size |
| requested_validity_days | INTEGER | NO | - | Requested validity period |
| certificate_type | VARCHAR(50) | NO | - | Type of certificate requested |
| status | VARCHAR(50) | NO | 'pending' | Status: 'pending', 'approved', 'rejected', 'fulfilled', 'expired', 'cancelled' |
| rejection_reason | TEXT | YES | - | Reason for rejection |
| issued_certificate_id | UUID | YES | - | Resulting certificate |
| requester_user_id | UUID | NO | - | User who made request (references clm_core_db.users) |
| approver_user_id | UUID | YES | - | User who approved (references clm_core_db.users) |
| policy_id | UUID | YES | - | Applied policy (references clm_core_db.policies) |
| workflow_id | UUID | YES | - | Workflow (references clm_core_db.workflows) |
| requested_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Request timestamp |
| approved_at | TIMESTAMP WITH TIME ZONE | YES | - | Approval timestamp |
| fulfilled_at | TIMESTAMP WITH TIME ZONE | YES | - | Fulfillment timestamp |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_cert_requests_status` on (status) WHERE deleted_at IS NULL
- `idx_cert_requests_requester` on (requester_user_id) WHERE deleted_at IS NULL
- `idx_cert_requests_workflow` on (workflow_id) WHERE deleted_at IS NULL
- `idx_cert_requests_issued_cert` on (issued_certificate_id)

**Constraints**:
- CHECK: status IN ('pending', 'approved', 'rejected', 'fulfilled', 'expired', 'cancelled')
- CHECK: certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')
- UNIQUE: request_id
- FOREIGN KEY: issued_certificate_id → certificates(id)

---

### certificate_revocations

Tracks certificate revocation details.

**Purpose**: Maintain revocation records for CRL and OCSP services.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| certificate_id | UUID | NO | - | Revoked certificate |
| revocation_date | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | When revoked |
| revocation_reason | VARCHAR(100) | NO | - | CRL reason code |
| invalidity_date | TIMESTAMP WITH TIME ZONE | YES | - | When certificate became invalid |
| crl_entry_added | BOOLEAN | NO | FALSE | Added to CRL |
| crl_sequence_number | BIGINT | YES | - | CRL sequence number |
| ocsp_status_updated | BOOLEAN | NO | FALSE | OCSP status updated |
| revoked_by_user_id | UUID | NO | - | User who revoked (references clm_core_db.users) |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |

**Indexes**:
- `idx_cert_revocations_cert` on (certificate_id)
- `idx_cert_revocations_date` on (revocation_date)
- `idx_cert_revocations_reason` on (revocation_reason)

**Constraints**:
- CHECK: revocation_reason IN ('unspecified', 'key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation', 'certificate_hold', 'remove_from_crl', 'privilege_withdrawn', 'aa_compromise')
- FOREIGN KEY: certificate_id → certificates(id)

---

### key_rotation_history

Audit trail for encryption key rotations.

**Purpose**: Track key rotation operations for compliance and debugging.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| old_key_id | UUID | NO | - | Previous key |
| new_key_id | UUID | NO | - | New key |
| rotation_type | VARCHAR(50) | NO | - | Type: 'scheduled', 'emergency', 'compromise', 'manual' |
| rotation_reason | TEXT | YES | - | Reason for rotation |
| items_re_encrypted | INTEGER | NO | 0 | Number of items re-encrypted |
| rotation_started_at | TIMESTAMP WITH TIME ZONE | NO | - | Start time |
| rotation_completed_at | TIMESTAMP WITH TIME ZONE | YES | - | Completion time |
| rotation_status | VARCHAR(50) | NO | 'in_progress' | Status: 'in_progress', 'completed', 'failed', 'rolled_back' |
| error_message | TEXT | YES | - | Error details if failed |
| initiated_by_user_id | UUID | NO | - | User who initiated (references clm_core_db.users) |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |

**Indexes**:
- `idx_key_rotation_old_key` on (old_key_id)
- `idx_key_rotation_new_key` on (new_key_id)
- `idx_key_rotation_status` on (rotation_status)
- `idx_key_rotation_started` on (rotation_started_at)

**Constraints**:
- CHECK: rotation_type IN ('scheduled', 'emergency', 'compromise', 'manual')
- CHECK: rotation_status IN ('in_progress', 'completed', 'failed', 'rolled_back')
- FOREIGN KEY: old_key_id → encryption_keys(id)
- FOREIGN KEY: new_key_id → encryption_keys(id)

---

### secure_audit_log

Immutable audit log for sensitive operations.

**Purpose**: Security audit trail for all access to cryptographic materials.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| event_id | VARCHAR(255) | NO | - | Unique event identifier |
| event_type | VARCHAR(100) | NO | - | Type of event |
| event_category | VARCHAR(50) | NO | - | Category: 'key_access', 'cert_access', 'key_rotation', 'revocation', 'csr', 'export' |
| severity | VARCHAR(20) | NO | - | Severity: 'info', 'warning', 'error', 'critical' |
| resource_type | VARCHAR(50) | NO | - | Resource: 'certificate', 'private_key', 'encryption_key', 'csr' |
| resource_id | UUID | NO | - | Resource UUID |
| action | VARCHAR(100) | NO | - | Action: 'created', 'read', 'updated', 'deleted', 'exported', 'signed', 'encrypted', 'decrypted' |
| user_id | UUID | NO | - | Acting user (references clm_core_db.users) |
| ip_address | INET | YES | - | Client IP address |
| user_agent | TEXT | YES | - | Client user agent |
| session_id | VARCHAR(255) | YES | - | Session identifier |
| event_data | JSONB | YES | - | Additional event data |
| result | VARCHAR(50) | NO | - | Result: 'success', 'failure', 'partial' |
| error_message | TEXT | YES | - | Error details if failed |
| event_timestamp | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | When event occurred |

**Indexes**:
- `idx_secure_audit_event_type` on (event_type)
- `idx_secure_audit_category` on (event_category)
- `idx_secure_audit_user` on (user_id)
- `idx_secure_audit_resource` on (resource_type, resource_id)
- `idx_secure_audit_timestamp` on (event_timestamp DESC)
- `idx_secure_audit_severity` on (severity) WHERE severity IN ('error', 'critical')

**Constraints**:
- CHECK: event_category IN ('key_access', 'cert_access', 'key_rotation', 'revocation', 'csr', 'export')
- CHECK: severity IN ('info', 'warning', 'error', 'critical')
- CHECK: result IN ('success', 'failure', 'partial')
- UNIQUE: event_id

---

## clm_core_db Tables

### users

User accounts and authentication data.

**Purpose**: Central user management for authentication and authorization.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| username | VARCHAR(255) | NO | - | Unique username |
| email | VARCHAR(255) | NO | - | Unique email address |
| password_hash | VARCHAR(255) | NO | - | Hashed password |
| password_salt | VARCHAR(255) | NO | - | Password salt |
| password_changed_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last password change |
| must_change_password | BOOLEAN | NO | FALSE | Force password change flag |
| first_name | VARCHAR(255) | YES | - | First name |
| last_name | VARCHAR(255) | YES | - | Last name |
| display_name | VARCHAR(255) | YES | - | Display name |
| phone_number | VARCHAR(50) | YES | - | Phone number |
| status | VARCHAR(50) | NO | 'active' | Status: 'active', 'inactive', 'locked', 'suspended' |
| email_verified | BOOLEAN | NO | FALSE | Email verification status |
| email_verified_at | TIMESTAMP WITH TIME ZONE | YES | - | Email verification timestamp |
| mfa_enabled | BOOLEAN | NO | FALSE | MFA enabled flag |
| mfa_secret | VARCHAR(255) | YES | - | MFA secret (encrypted) |
| mfa_backup_codes | TEXT[] | YES | - | MFA backup codes |
| failed_login_attempts | INTEGER | NO | 0 | Failed login counter |
| last_login_at | TIMESTAMP WITH TIME ZONE | YES | - | Last successful login |
| last_login_ip | INET | YES | - | Last login IP |
| last_activity_at | TIMESTAMP WITH TIME ZONE | YES | - | Last activity timestamp |
| api_access_enabled | BOOLEAN | NO | FALSE | API access flag |
| created_by_user_id | UUID | YES | - | User who created this user |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_users_username` on (username) WHERE deleted_at IS NULL
- `idx_users_email` on (email) WHERE deleted_at IS NULL
- `idx_users_status` on (status) WHERE deleted_at IS NULL
- `idx_users_last_activity` on (last_activity_at) WHERE deleted_at IS NULL

**Constraints**:
- CHECK: status IN ('active', 'inactive', 'locked', 'suspended')
- CHECK: email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
- UNIQUE: username, email

---

### roles

Role definitions for RBAC.

**Purpose**: Define roles and their associated permissions.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| role_name | VARCHAR(100) | NO | - | Human-readable role name |
| role_code | VARCHAR(50) | NO | - | Machine-readable code |
| description | TEXT | YES | - | Role description |
| permissions | JSONB | NO | '{}' | Permission definitions |
| parent_role_id | UUID | YES | - | Parent role for hierarchy |
| is_system_role | BOOLEAN | NO | FALSE | System role flag (cannot delete) |
| is_active | BOOLEAN | NO | TRUE | Active status |
| created_by_user_id | UUID | YES | - | Creator user |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_roles_code` on (role_code) WHERE deleted_at IS NULL
- `idx_roles_active` on (is_active) WHERE deleted_at IS NULL
- `idx_roles_parent` on (parent_role_id)

**Constraints**:
- UNIQUE: role_name, role_code
- FOREIGN KEY: parent_role_id → roles(id)

**Example JSONB format for permissions**:
```json
{
  "certificates": ["create", "read", "update", "delete", "revoke"],
  "policies": ["read", "update"],
  "workflows": ["read", "execute"],
  "users": ["read"],
  "audit": ["read"]
}
```

---

### user_roles

User-role assignments.

**Purpose**: Many-to-many relationship between users and roles.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| user_id | UUID | NO | - | User reference |
| role_id | UUID | NO | - | Role reference |
| valid_from | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Assignment valid from |
| valid_until | TIMESTAMP WITH TIME ZONE | YES | - | Assignment valid until |
| assigned_by_user_id | UUID | YES | - | User who assigned role |
| assigned_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Assignment timestamp |
| revoked_at | TIMESTAMP WITH TIME ZONE | YES | - | Revocation timestamp |
| revoked_by_user_id | UUID | YES | - | User who revoked |

**Indexes**:
- `idx_user_roles_user` on (user_id) WHERE revoked_at IS NULL
- `idx_user_roles_role` on (role_id) WHERE revoked_at IS NULL
- `idx_user_roles_valid` on (valid_from, valid_until) WHERE revoked_at IS NULL

**Constraints**:
- CHECK: valid_from < valid_until OR valid_until IS NULL
- UNIQUE: (user_id, role_id)
- FOREIGN KEY: user_id → users(id) ON DELETE CASCADE
- FOREIGN KEY: role_id → roles(id) ON DELETE CASCADE

---

### organizations

Multi-tenant organization management.

**Purpose**: Support multi-tenancy with organization-level isolation.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| org_name | VARCHAR(255) | NO | - | Organization name |
| org_code | VARCHAR(50) | NO | - | Unique organization code |
| description | TEXT | YES | - | Description |
| website | VARCHAR(255) | YES | - | Organization website |
| industry | VARCHAR(100) | YES | - | Industry sector |
| primary_contact_user_id | UUID | YES | - | Primary contact |
| billing_email | VARCHAR(255) | YES | - | Billing email |
| support_email | VARCHAR(255) | YES | - | Support email |
| settings | JSONB | NO | '{}' | Organization settings |
| status | VARCHAR(50) | NO | 'active' | Status: 'active', 'suspended', 'inactive' |
| license_type | VARCHAR(50) | YES | - | License type |
| license_expires_at | TIMESTAMP WITH TIME ZONE | YES | - | License expiry |
| max_users | INTEGER | YES | - | Maximum users allowed |
| max_certificates | INTEGER | YES | - | Maximum certificates allowed |
| created_by_user_id | UUID | YES | - | Creator user |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_organizations_code` on (org_code) WHERE deleted_at IS NULL
- `idx_organizations_status` on (status) WHERE deleted_at IS NULL

**Constraints**:
- CHECK: status IN ('active', 'suspended', 'inactive')
- UNIQUE: org_code
- FOREIGN KEY: primary_contact_user_id → users(id)

---

### policies

Certificate and security policies.

**Purpose**: Define policies that govern certificate operations.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| policy_name | VARCHAR(255) | NO | - | Policy name |
| policy_code | VARCHAR(50) | NO | - | Unique policy code |
| policy_type | VARCHAR(50) | NO | - | Type: 'certificate', 'key_management', 'access_control', 'compliance', 'issuance' |
| description | TEXT | YES | - | Description |
| policy_rules | JSONB | NO | - | Policy rules definition |
| organization_id | UUID | YES | - | Organization scope |
| applies_to_cert_types | VARCHAR(50)[] | YES | - | Certificate types |
| status | VARCHAR(50) | NO | 'draft' | Status: 'draft', 'active', 'inactive', 'archived' |
| version | INTEGER | NO | 1 | Policy version |
| enforcement_level | VARCHAR(50) | NO | 'mandatory' | Level: 'mandatory', 'advisory', 'audit_only' |
| effective_from | TIMESTAMP WITH TIME ZONE | YES | - | Effective start date |
| effective_until | TIMESTAMP WITH TIME ZONE | YES | - | Effective end date |
| compliance_frameworks | VARCHAR(100)[] | YES | - | Compliance frameworks |
| created_by_user_id | UUID | NO | - | Creator user |
| approved_by_user_id | UUID | YES | - | Approver user |
| approved_at | TIMESTAMP WITH TIME ZONE | YES | - | Approval timestamp |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_policies_code` on (policy_code) WHERE deleted_at IS NULL
- `idx_policies_type` on (policy_type) WHERE deleted_at IS NULL
- `idx_policies_status` on (status) WHERE deleted_at IS NULL
- `idx_policies_org` on (organization_id) WHERE deleted_at IS NULL

**Constraints**:
- CHECK: policy_type IN ('certificate', 'key_management', 'access_control', 'compliance', 'issuance')
- CHECK: status IN ('draft', 'active', 'inactive', 'archived')
- CHECK: enforcement_level IN ('mandatory', 'advisory', 'audit_only')
- UNIQUE: policy_code
- FOREIGN KEY: organization_id → organizations(id)
- FOREIGN KEY: created_by_user_id → users(id)
- FOREIGN KEY: approved_by_user_id → users(id)

**Example JSONB format for policy_rules**:
```json
{
  "max_validity_days": 365,
  "min_key_size": 2048,
  "allowed_algorithms": ["RSA", "ECDSA"],
  "require_approval": true,
  "auto_renewal": true,
  "renewal_threshold_days": 30,
  "allowed_san_types": ["DNS", "IP"],
  "max_sans": 10
}
```

---

### workflows

Workflow definitions.

**Purpose**: Define workflows for certificate lifecycle operations.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | UUID | NO | uuid_generate_v4() | Primary key |
| workflow_name | VARCHAR(255) | NO | - | Workflow name |
| workflow_code | VARCHAR(50) | NO | - | Unique workflow code |
| workflow_type | VARCHAR(50) | NO | - | Type: 'certificate_request', 'renewal', 'revocation', 'key_rotation', 'import', 'export' |
| description | TEXT | YES | - | Description |
| workflow_definition | JSONB | NO | - | Workflow steps definition |
| organization_id | UUID | YES | - | Organization scope |
| auto_approve_conditions | JSONB | YES | - | Auto-approval rules |
| requires_approval | BOOLEAN | NO | TRUE | Requires approval flag |
| approval_chain | JSONB | YES | - | Approval chain definition |
| status | VARCHAR(50) | NO | 'draft' | Status: 'draft', 'active', 'inactive', 'archived' |
| version | INTEGER | NO | 1 | Workflow version |
| created_by_user_id | UUID | NO | - | Creator user |
| created_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP WITH TIME ZONE | NO | CURRENT_TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP WITH TIME ZONE | YES | - | Soft delete timestamp |

**Indexes**:
- `idx_workflows_code` on (workflow_code) WHERE deleted_at IS NULL
- `idx_workflows_type` on (workflow_type) WHERE deleted_at IS NULL
- `idx_workflows_status` on (status) WHERE deleted_at IS NULL
- `idx_workflows_org` on (organization_id) WHERE deleted_at IS NULL

**Constraints**:
- CHECK: workflow_type IN ('certificate_request', 'renewal', 'revocation', 'key_rotation', 'import', 'export')
- CHECK: status IN ('draft', 'active', 'inactive', 'archived')
- UNIQUE: workflow_code
- FOREIGN KEY: organization_id → organizations(id)
- FOREIGN KEY: created_by_user_id → users(id)

---

*Due to length, remaining tables (workflow_instances, workflow_steps, notifications, audit_log, api_keys, sessions, certificate_metadata) follow similar patterns. Please refer to the migration files for complete details.*

## Common Patterns

### Soft Deletes
Most tables include `deleted_at TIMESTAMP WITH TIME ZONE` for soft deletes. Query with `WHERE deleted_at IS NULL` for active records.

### Audit Fields
Standard audit fields: `created_at`, `updated_at`, `created_by_user_id`, `deleted_at`

### UUID References
All cross-database references use UUIDs without foreign key constraints.

### JSONB Fields
Used for flexible schema fields. Always document expected structure in comments.

### Status Enums
Status fields use VARCHAR with CHECK constraints for type safety.

### Timestamps
All timestamps use `TIMESTAMP WITH TIME ZONE` for timezone-aware storage.
