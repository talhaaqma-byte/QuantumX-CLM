# Database Architecture

## Overview

The CLM (Certificate Lifecycle Management) platform uses a dual-database architecture to ensure the highest level of security for cryptographic materials while maintaining efficient application data access.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLM Application Layer                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────┐         ┌─────────────────────┐       │
│  │   Core Service      │         │   Secure Service    │       │
│  │  (Business Logic)   │         │  (Crypto Operations)│       │
│  └──────────┬──────────┘         └──────────┬──────────┘       │
│             │                               │                   │
│             │ UUID References               │                   │
│             │ (No FK Constraints)           │                   │
└─────────────┼───────────────────────────────┼───────────────────┘
              │                               │
              ▼                               ▼
    ┌─────────────────┐           ┌─────────────────────┐
    │  clm_core_db    │           │  clm_secure_db      │
    │  ─────────────  │           │  ───────────────    │
    │  • Users        │           │  • Certificates     │
    │  • Roles        │           │  • Private Keys     │
    │  • Policies     │           │  • Encryption Keys  │
    │  • Workflows    │           │  • CSRs             │
    │  • Audit Logs   │           │  • Revocations      │
    │  • Metadata     │◄─────────►│  • Secure Audit Log │
    └─────────────────┘           └─────────────────────┘
         (Port 5432)                   (Port 5433)
```

## Database Separation Rationale

### Why Two Databases?

1. **Security Isolation**
   - Cryptographic materials are isolated from general application data
   - Different access controls and encryption policies
   - Reduced attack surface for sensitive data

2. **Compliance Requirements**
   - Easier to meet regulatory requirements (FIPS, PCI-DSS, etc.)
   - Separate backup and encryption policies
   - Different retention policies for sensitive vs. non-sensitive data

3. **Performance Optimization**
   - Core database optimized for high transaction volume
   - Secure database optimized for encryption/decryption operations
   - Independent scaling strategies

4. **Access Control**
   - Different database users with minimal privileges
   - Secure database accessible only by crypto service
   - Core database accessible by main application services

## Database: clm_secure_db

### Purpose
Stores all sensitive cryptographic data including certificates, private keys, and encryption metadata.

### Schema Overview

#### Core Tables

**1. encryption_keys**
- Manages encryption keys used to protect other keys and sensitive data
- Supports key rotation and versioning
- Tracks key lifecycle and usage

**2. certificates**
- X.509 certificate storage with full details
- PEM and DER encoded formats
- Subject Alternative Names (SANs)
- Certificate chain information
- Revocation status

**3. private_keys**
- Encrypted private key material
- One-to-one relationship with certificates
- HSM integration support
- Access control and audit trail

**4. certificate_requests**
- Certificate Signing Requests (CSRs)
- Request approval workflow tracking
- Links to issued certificates

**5. certificate_revocations**
- Revocation records with CRL reason codes
- OCSP status tracking
- Revocation date and invalidity date

**6. key_rotation_history**
- Audit trail for key rotation events
- Tracks re-encryption operations
- Success/failure status

**7. secure_audit_log**
- Immutable audit log for all sensitive operations
- Key access, certificate operations
- Export operations

### Security Features

- **Encryption at Rest**: All sensitive fields encrypted
- **Soft Deletes**: Data retained for audit purposes
- **Access Logging**: Every access to private keys logged
- **Key Wrapping**: Keys encrypted with master keys
- **HSM Support**: Integration points for Hardware Security Modules

### Access Patterns

```sql
-- Typical query patterns:

-- 1. Retrieve certificate with metadata (no private key)
SELECT id, certificate_id, common_name, pem_encoded_cert, 
       not_before, not_after, status
FROM certificates
WHERE certificate_id = 'cert-uuid' AND deleted_at IS NULL;

-- 2. Access private key (logged operation)
SELECT encrypted_key_material, encryption_key_id, encryption_algorithm
FROM private_keys
WHERE certificate_id = 'cert-uuid' AND deleted_at IS NULL;

-- 3. Check expiring certificates
SELECT * FROM expiring_certificates; -- View
```

## Database: clm_core_db

### Purpose
Stores application data, user management, workflows, policies, and non-sensitive metadata.

### Schema Overview

#### User Management

**1. users**
- User accounts and authentication
- Password management
- MFA configuration
- Session tracking

**2. roles**
- Role-based access control (RBAC)
- Hierarchical roles
- Permission definitions (JSONB)

**3. user_roles**
- User-role assignments
- Temporal assignments (valid_from/valid_until)
- Assignment audit trail

#### Multi-Tenancy

**4. organizations**
- Organization/tenant management
- Subscription and licensing
- Organization settings

**5. user_organizations**
- User membership in organizations
- Primary organization designation

#### Policy & Workflow

**6. policies**
- Certificate policies
- Key management policies
- Compliance framework mappings
- Policy versioning

**7. workflows**
- Workflow definitions
- Approval chains
- Auto-approval conditions

**8. workflow_instances**
- Running workflow executions
- Current step tracking
- Context data

**9. workflow_steps**
- Individual workflow steps
- Assignments and completion tracking

#### Certificate Metadata

**10. certificate_metadata**
- Non-sensitive certificate metadata
- Tags and categorization
- Environment designation
- Custom fields

#### System Tables

**11. notifications**
- User notifications
- Multi-channel delivery
- Priority management

**12. audit_log**
- Application-level audit trail
- User actions and system events
- Change tracking

**13. api_keys**
- API authentication tokens
- Scope-based permissions

**14. sessions**
- User session management
- Session invalidation

### Access Patterns

```sql
-- Typical query patterns:

-- 1. User authentication
SELECT id, username, password_hash, password_salt, status, mfa_enabled
FROM users
WHERE username = 'user@example.com' AND deleted_at IS NULL;

-- 2. User permissions
SELECT r.role_code, r.permissions
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE u.id = 'user-uuid' AND ur.revoked_at IS NULL;

-- 3. Certificate metadata with owner
SELECT cm.*, u.username, u.email, o.org_name
FROM certificate_metadata cm
JOIN users u ON cm.owner_user_id = u.id
LEFT JOIN organizations o ON cm.organization_id = o.id
WHERE cm.deleted_at IS NULL;

-- 4. Pending approvals for user
SELECT * FROM pending_approvals -- View
WHERE assigned_to_user_id = 'user-uuid';
```

## Cross-Database References

### Design Pattern

Since PostgreSQL foreign key constraints cannot span databases, we use **UUID-based loose coupling**:

```
clm_secure_db.certificates.owner_user_id → clm_core_db.users.id (UUID)
```

### Application Responsibility

The application layer must ensure referential integrity:

1. **Validation**: Check referenced entities exist before insert
2. **Cascade Operations**: Handle cascading deletes via application logic
3. **Integrity Checks**: Periodic jobs to detect orphaned records
4. **Error Handling**: Graceful handling of missing references

### Example Pattern

```javascript
// Pseudo-code for creating a certificate with cross-DB references

async function createCertificate(certData) {
    // 1. Validate user exists in clm_core_db
    const user = await coreDb.query(
        'SELECT id FROM users WHERE id = $1',
        [certData.ownerUserId]
    );
    
    if (!user) {
        throw new Error('User not found');
    }
    
    // 2. Validate policy exists in clm_core_db
    const policy = await coreDb.query(
        'SELECT id FROM policies WHERE id = $1',
        [certData.policyId]
    );
    
    if (!policy) {
        throw new Error('Policy not found');
    }
    
    // 3. Insert certificate in clm_secure_db
    const cert = await secureDb.query(
        'INSERT INTO certificates (...) VALUES (...) RETURNING id',
        [...]
    );
    
    // 4. Insert metadata in clm_core_db
    await coreDb.query(
        'INSERT INTO certificate_metadata (...) VALUES (...)',
        [cert.id, ...]
    );
    
    return cert;
}
```

## Data Flow Patterns

### Certificate Issuance Flow

```
1. User submits CSR (via Core Service)
   ├─ Create workflow_instance in clm_core_db
   └─ Create certificate_request in clm_secure_db

2. Approval workflow (via Core Service)
   ├─ Create workflow_steps in clm_core_db
   └─ Update workflow status

3. Certificate generation (via Secure Service)
   ├─ Create certificate in clm_secure_db
   ├─ Create private_key in clm_secure_db
   └─ Create certificate_metadata in clm_core_db

4. Notification (via Core Service)
   └─ Create notification in clm_core_db
```

### Certificate Revocation Flow

```
1. Revocation request (via Core Service)
   └─ Create workflow_instance in clm_core_db

2. Approval (if required)
   └─ Update workflow_steps in clm_core_db

3. Revoke certificate (via Secure Service)
   ├─ Create certificate_revocation in clm_secure_db
   ├─ Update certificate.status in clm_secure_db
   ├─ Update certificate_metadata.status in clm_core_db
   └─ Create secure_audit_log entry in clm_secure_db
```

## Indexing Strategy

### Primary Keys
- All tables use UUID primary keys
- Default B-tree index created automatically

### Foreign Keys
- All FK columns indexed for JOIN performance
- Helps with ON DELETE CASCADE operations

### Status Columns
- Partial indexes for active records
- Example: `WHERE deleted_at IS NULL`
- Reduces index size and improves query performance

### Timestamp Columns
- Indexed for time-based queries
- `created_at`, `updated_at`, `expires_at`, etc.
- DESC order for recent-first queries

### JSONB Columns
- GIN indexes for JSONB containment queries
- Used for flexible schema fields
- Example: `tags`, `permissions`, `policy_rules`

### Composite Indexes
- Multi-column indexes for common queries
- Example: `(user_id, status)` for user's active items

## Performance Considerations

### Connection Pooling

```javascript
// Separate connection pools for each database
const corePool = new Pool({
    host: 'core-db-host',
    database: 'clm_core_db',
    max: 20,  // Higher for high-traffic core DB
});

const securePool = new Pool({
    host: 'secure-db-host',
    database: 'clm_secure_db',
    max: 10,  // Lower for less frequent secure operations
});
```

### Query Optimization

1. **Use Views**: Pre-defined views for common queries
2. **Pagination**: Always limit result sets
3. **Selective Columns**: Don't `SELECT *`
4. **Prepared Statements**: Reduce parsing overhead
5. **Batch Operations**: Reduce round trips

### Caching Strategy

- Cache frequently accessed data from clm_core_db
- Never cache sensitive data from clm_secure_db
- Cache metadata but not cryptographic material
- Implement cache invalidation on updates

## Backup and Recovery

### Backup Strategy

**clm_secure_db**: Critical - Zero data loss tolerance
- Continuous WAL archiving
- Hourly incremental backups
- Daily full backups
- Encrypted backup storage
- Off-site replication

**clm_core_db**: Important - Minimal data loss
- Daily full backups
- Hourly incremental backups
- Point-in-time recovery capability

### Recovery Time Objectives (RTO)

- **clm_secure_db**: < 1 hour
- **clm_core_db**: < 2 hours

### Recovery Point Objectives (RPO)

- **clm_secure_db**: < 5 minutes
- **clm_core_db**: < 15 minutes

## Monitoring

### Key Metrics

**clm_secure_db**:
- Private key access frequency
- Certificate operations per second
- Key rotation status
- Failed cryptographic operations
- Audit log growth rate

**clm_core_db**:
- Active user sessions
- Workflow completion times
- Pending approvals count
- API request rates
- Database connection pool utilization

### Alerting Thresholds

- Certificate expiry < 30 days
- Failed login attempts > 5 in 5 minutes
- Database connection pool > 80% utilized
- Replication lag > 10 seconds
- Disk usage > 80%

## Scaling Strategies

### Vertical Scaling
- Increase CPU/RAM for database servers
- Use faster storage (NVMe SSDs)

### Horizontal Scaling

**Read Replicas**:
- clm_core_db: 2-3 read replicas for queries
- clm_secure_db: 1 read replica for audit log queries
- Route read-only queries to replicas

**Sharding** (Future):
- Shard clm_core_db by organization_id
- Keep clm_secure_db centralized (higher security)

## Security Best Practices

### Database Level

1. **SSL/TLS Connections**: Required for all connections
2. **Certificate-Based Auth**: For application connections
3. **Network Isolation**: Secure DB on separate network
4. **Firewall Rules**: Restrict access by IP/subnet
5. **Database Encryption**: Transparent Data Encryption (TDE)

### Application Level

1. **Least Privilege**: Minimal permissions for each service
2. **Credential Rotation**: Regular rotation of DB passwords
3. **Connection Security**: Use secrets management (Vault, etc.)
4. **SQL Injection Prevention**: Parameterized queries only
5. **Audit Logging**: Log all database access

### Operational Security

1. **Access Controls**: MFA for DB admin access
2. **Change Management**: All schema changes reviewed
3. **Backup Encryption**: Encrypted backup files
4. **Key Management**: Separate key management for DB encryption
5. **Regular Audits**: Quarterly security audits

## Maintenance Windows

### Routine Maintenance

**Weekly** (Sunday 2-4 AM UTC):
- VACUUM ANALYZE
- Index maintenance
- Statistics update

**Monthly** (First Sunday 2-6 AM UTC):
- REINDEX DATABASE
- Audit log archival
- Performance tuning review

**Quarterly**:
- Major version updates (if needed)
- Capacity planning review
- Disaster recovery testing

## Future Enhancements

### Planned Improvements

1. **Row-Level Security (RLS)**
   - Multi-tenant data isolation
   - Automatic filtering by organization

2. **Partitioning**
   - Partition audit logs by date
   - Partition certificates by status

3. **Advanced Indexing**
   - BRIN indexes for timestamp columns
   - Bloom filters for multi-column queries

4. **Database Sharding**
   - Shard core DB by organization
   - Citus extension for distributed queries

5. **Real-Time Replication**
   - Logical replication for analytics
   - CDC (Change Data Capture) for event streaming

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Database Security Best Practices](https://www.postgresql.org/docs/current/security.html)
- [High Availability](https://www.postgresql.org/docs/current/high-availability.html)
- [Performance Tuning](https://wiki.postgresql.org/wiki/Performance_Optimization)
