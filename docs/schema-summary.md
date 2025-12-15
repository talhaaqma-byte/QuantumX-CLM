# Database Schema Summary

Quick reference guide for the CLM platform database schema.

## Database Overview

| Database | Tables | Purpose | Security Level |
|----------|--------|---------|----------------|
| clm_secure_db | 7 | Cryptographic materials | High |
| clm_core_db | 14 | Application data | Standard |

## Table Quick Reference

### clm_secure_db

| Table | Records | Key Columns | Purpose |
|-------|---------|-------------|---------|
| `encryption_keys` | Keys | key_id, key_type, key_status | Encryption key management |
| `certificates` | Certificates | certificate_id, common_name, status | X.509 certificate storage |
| `private_keys` | Keys | certificate_id, encrypted_key_material | Encrypted private keys |
| `certificate_requests` | CSRs | request_id, status | Certificate signing requests |
| `certificate_revocations` | Revocations | certificate_id, revocation_reason | Revocation records |
| `key_rotation_history` | Rotations | old_key_id, new_key_id | Key rotation audit |
| `secure_audit_log` | Events | event_type, user_id, action | Security audit trail |

### clm_core_db

| Table | Records | Key Columns | Purpose |
|-------|---------|-------------|---------|
| `users` | Users | username, email, status | User accounts |
| `roles` | Roles | role_code, permissions | Role definitions |
| `user_roles` | Assignments | user_id, role_id | User-role mappings |
| `organizations` | Orgs | org_code, status | Multi-tenant orgs |
| `user_organizations` | Memberships | user_id, organization_id | User-org mappings |
| `policies` | Policies | policy_code, policy_rules | Certificate policies |
| `workflows` | Workflows | workflow_code, workflow_definition | Workflow definitions |
| `workflow_instances` | Executions | workflow_id, status | Running workflows |
| `workflow_steps` | Steps | workflow_instance_id, status | Workflow steps |
| `notifications` | Alerts | user_id, notification_type | User notifications |
| `audit_log` | Events | event_type, user_id, action | Application audit |
| `api_keys` | Keys | key_hash, user_id | API authentication |
| `sessions` | Sessions | session_id, user_id | User sessions |
| `certificate_metadata` | Metadata | certificate_id, owner_user_id | Cert metadata |

## Common Queries

### User Authentication

```sql
-- Get user with roles
SELECT u.*, array_agg(r.role_code) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.revoked_at IS NULL
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'user@example.com' AND u.deleted_at IS NULL
GROUP BY u.id;
```

### Active Certificates

```sql
-- Get active certificates for a user
SELECT c.certificate_id, c.common_name, c.not_after, c.status
FROM certificates c
WHERE c.owner_user_id = 'user-uuid'
  AND c.deleted_at IS NULL
  AND c.status = 'active'
ORDER BY c.not_after ASC;
```

### Expiring Certificates

```sql
-- Certificates expiring in next 30 days
SELECT * FROM expiring_certificates;  -- Pre-defined view
```

### Pending Approvals

```sql
-- Get pending approvals for user
SELECT * FROM pending_approvals
WHERE assigned_to_user_id = 'user-uuid'
   OR assigned_to_role_id IN (
       SELECT role_id FROM user_roles 
       WHERE user_id = 'user-uuid' AND revoked_at IS NULL
   );
```

### Audit Trail

```sql
-- Recent certificate operations
SELECT event_type, action, user_id, event_timestamp
FROM secure_audit_log
WHERE resource_type = 'certificate'
  AND resource_id = 'cert-uuid'
ORDER BY event_timestamp DESC
LIMIT 50;
```

## Status Enums

### Certificate Status
- `pending` - Awaiting issuance
- `active` - Currently valid
- `expiring` - Expires soon
- `expired` - Past expiration
- `revoked` - Revoked
- `suspended` - Temporarily suspended

### User Status
- `active` - Active user
- `inactive` - Inactive
- `locked` - Account locked
- `suspended` - Suspended

### Workflow Status
- `initiated` - Started
- `in_progress` - Running
- `pending_approval` - Awaiting approval
- `approved` - Approved
- `rejected` - Rejected
- `completed` - Finished
- `failed` - Failed
- `cancelled` - Cancelled

### Policy Status
- `draft` - Being edited
- `active` - Active
- `inactive` - Not in use
- `archived` - Archived

## Relationships

### Cross-Database References (UUID only)

```
clm_secure_db.certificates.owner_user_id
    → clm_core_db.users.id

clm_secure_db.certificates.policy_id
    → clm_core_db.policies.id

clm_secure_db.certificates.workflow_id
    → clm_core_db.workflows.id

clm_core_db.certificate_metadata.certificate_id
    → clm_secure_db.certificates.id
```

### Within clm_secure_db

```
certificates ←→ private_keys (1:1)
certificates ← certificate_requests (1:N)
certificates ← certificate_revocations (1:N)
encryption_keys ← private_keys (1:N)
```

### Within clm_core_db

```
users ←→ user_roles ←→ roles (M:N)
users ←→ user_organizations ←→ organizations (M:N)
workflows → workflow_instances → workflow_steps (1:N:N)
```

## Index Strategy

### Primary Indexes
- All tables: UUID primary key
- Unique constraints: Automatic unique indexes

### Performance Indexes
- Foreign keys: All indexed
- Status columns: Partial indexes with `WHERE deleted_at IS NULL`
- Timestamps: Common query patterns
- JSONB: GIN indexes where appropriate

### Key Indexes

**clm_secure_db:**
```sql
idx_certificates_status (status)
idx_certificates_expiry (not_after)
idx_certificates_owner (owner_user_id)
idx_private_keys_cert (certificate_id)
idx_secure_audit_timestamp (event_timestamp DESC)
```

**clm_core_db:**
```sql
idx_users_username (username)
idx_users_email (email)
idx_certificate_metadata_cert_id (certificate_id)
idx_workflow_instances_status (status)
idx_audit_log_timestamp (event_timestamp DESC)
```

## Triggers

### Auto-Update Timestamps

All main tables have triggers to automatically update `updated_at`:

```sql
CREATE TRIGGER trg_table_name_updated_at
    BEFORE UPDATE ON table_name
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

## Views

### clm_secure_db Views

**active_certificates**
- Active and expiring certificates only
- Excludes sensitive cryptographic material

**expiring_certificates**
- Certificates expiring within 30 days
- Includes days_until_expiry calculation

### clm_core_db Views

**active_users_with_roles**
- Active users with their assigned roles
- Aggregated role names and codes

**pending_approvals**
- All pending approval workflow steps
- Ready for approver action

**certificate_summary**
- Certificate metadata with owner details
- Joins with users and organizations

## Soft Delete Pattern

Most tables use soft deletes:

```sql
-- Soft delete
UPDATE table_name SET deleted_at = NOW() WHERE id = 'uuid';

-- Query active only
SELECT * FROM table_name WHERE deleted_at IS NULL;

-- Restore
UPDATE table_name SET deleted_at = NULL WHERE id = 'uuid';
```

## JSONB Schemas

### roles.permissions
```json
{
  "certificates": ["create", "read", "update", "delete", "revoke"],
  "policies": ["read", "update"],
  "workflows": ["read", "execute"],
  "audit": ["read"]
}
```

### policies.policy_rules
```json
{
  "max_validity_days": 365,
  "min_key_size": 2048,
  "allowed_algorithms": ["RSA", "ECDSA"],
  "require_approval": true,
  "auto_renewal": true,
  "renewal_threshold_days": 30
}
```

### workflows.workflow_definition
```json
{
  "steps": [
    {
      "step_id": 1,
      "type": "validation",
      "config": {...}
    },
    {
      "step_id": 2,
      "type": "approval",
      "approvers": ["role:APPROVER"]
    }
  ]
}
```

### certificates.subject_alternative_names
```json
[
  {"type": "DNS", "value": "example.com"},
  {"type": "DNS", "value": "*.example.com"},
  {"type": "IP", "value": "192.168.1.1"}
]
```

## Security Notes

### Sensitive Tables
- `private_keys` - Always encrypted, access logged
- `encryption_keys` - Restricted access
- `users` - Contains password hashes

### Audit Requirements
- All access to `private_keys` logged in `secure_audit_log`
- All user actions logged in `audit_log`
- Logs are append-only (no updates/deletes)

### Encryption Fields
- `private_keys.encrypted_key_material` - Encrypted with `encryption_keys`
- `users.mfa_secret` - Should be encrypted at application level
- `api_keys.key_hash` - Hashed, never store plaintext

## Size Estimates

### Per Certificate
- certificates row: ~5 KB
- private_keys row: ~2 KB (encrypted)
- certificate_metadata row: ~1 KB
- Total: ~8 KB per certificate

### Per User
- users row: ~2 KB
- user_roles rows: ~0.5 KB
- Total: ~2.5 KB per user

### Audit Logs
- audit_log: ~1 KB per event
- secure_audit_log: ~1 KB per event
- Recommend: Archive after 90-365 days

## Performance Tips

1. **Always use WHERE deleted_at IS NULL** to utilize partial indexes
2. **Use prepared statements** to prevent SQL injection and improve performance
3. **Limit result sets** with LIMIT and OFFSET for pagination
4. **Use views** for common complex queries
5. **Index JSONB fields** with GIN indexes for containment queries
6. **Connection pooling** - separate pools for each database
7. **Read replicas** for reporting and analytics queries

## Maintenance

### Daily
- Monitor slow queries
- Check connection pool usage

### Weekly  
- VACUUM ANALYZE

### Monthly
- REINDEX
- Archive old audit logs
- Review index usage

### Quarterly
- Update statistics
- Capacity planning
- Security audit

## Quick Commands

```bash
# Connect to databases
psql -U postgres -d clm_core_db
psql -U postgres -d clm_secure_db

# List tables
\dt

# Describe table
\d table_name

# Show indexes
\di

# Show views
\dv

# Table sizes
SELECT tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables WHERE schemaname = 'public';

# Index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan;
```

## References

- [Full Schema Reference](./schema-reference.md)
- [Database Architecture](./database-architecture.md)
- [Security Best Practices](./database-security.md)
- [Quick Start Guide](./database-quickstart.md)
