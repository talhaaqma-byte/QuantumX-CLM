# Database Migrations

This directory contains SQL migration files for the CLM (Certificate Lifecycle Management) platform.

## Database Architecture

The CLM platform uses a **two-database architecture** for enhanced security:

1. **clm_secure_db** - Stores sensitive cryptographic data
2. **clm_core_db** - Stores application data and business logic

### Security Design Principles

- **No Cross-Database Joins**: The two databases are completely isolated
- **UUID References Only**: Cross-database relationships use UUIDs without foreign key constraints
- **Data Segregation**: Sensitive cryptographic material is isolated in clm_secure_db
- **Audit Trail**: Both databases maintain comprehensive audit logs

## Directory Structure

```
migrations/
├── clm_secure_db/          # Migrations for secure database
│   └── 001_init_secure_schema.sql
├── clm_core_db/            # Migrations for core database
│   └── 001_init_core_schema.sql
└── README.md               # This file
```

## Migration Files

### clm_secure_db Migrations

#### 001_init_secure_schema.sql

Creates the initial schema for the secure database:

**Tables:**
- `encryption_keys` - Encryption key management
- `certificates` - X.509 certificate storage
- `private_keys` - Encrypted private key storage
- `certificate_requests` - Certificate signing requests (CSRs)
- `certificate_revocations` - Revocation tracking
- `key_rotation_history` - Key rotation audit trail
- `secure_audit_log` - Audit log for sensitive operations

**Key Features:**
- UUID primary keys for all tables
- Soft delete support via `deleted_at` columns
- Comprehensive indexing for performance
- Encryption metadata fields
- JSONB fields for flexible data storage
- Automatic timestamp management via triggers

### clm_core_db Migrations

#### 001_init_core_schema.sql

Creates the initial schema for the core database:

**Tables:**
- `users` - User accounts and authentication
- `roles` - Role-based access control
- `user_roles` - User-role assignments
- `organizations` - Multi-tenant organization support
- `user_organizations` - User-organization membership
- `policies` - Certificate and security policies
- `workflows` - Workflow definitions
- `workflow_instances` - Workflow executions
- `workflow_steps` - Individual workflow steps
- `notifications` - User notifications
- `audit_log` - Application audit trail
- `api_keys` - API access tokens
- `sessions` - User session management
- `certificate_metadata` - Non-sensitive certificate metadata

**Key Features:**
- UUID primary keys for all tables
- Soft delete support where appropriate
- JSONB for flexible configuration storage
- Comprehensive audit trail
- Multi-tenancy support
- Temporal role assignments
- Default system roles seeded

## Running Migrations

### Prerequisites

1. PostgreSQL 12 or higher installed
2. Two separate databases created:
   ```sql
   CREATE DATABASE clm_secure_db;
   CREATE DATABASE clm_core_db;
   ```
3. Required PostgreSQL extensions enabled (handled by migrations):
   - `uuid-ossp` - UUID generation
   - `pgcrypto` - Cryptographic functions

### Manual Execution

Execute migrations in numerical order:

```bash
# Run secure database migrations
psql -U postgres -d clm_secure_db -f clm_secure_db/001_init_secure_schema.sql

# Run core database migrations
psql -U postgres -d clm_core_db -f clm_core_db/001_init_core_schema.sql
```

### Docker Execution

If using Docker:

```bash
# Secure database
docker exec -i postgres_container psql -U postgres -d clm_secure_db < clm_secure_db/001_init_secure_schema.sql

# Core database
docker exec -i postgres_container psql -U postgres -d clm_core_db < clm_core_db/001_init_core_schema.sql
```

### Kubernetes Execution

If using Kubernetes with a PostgreSQL pod:

```bash
# Copy migration files to pod
kubectl cp clm_secure_db/ postgres-pod:/tmp/migrations/clm_secure_db/
kubectl cp clm_core_db/ postgres-pod:/tmp/migrations/clm_core_db/

# Execute migrations
kubectl exec -i postgres-pod -- psql -U postgres -d clm_secure_db -f /tmp/migrations/clm_secure_db/001_init_secure_schema.sql
kubectl exec -i postgres-pod -- psql -U postgres -d clm_core_db -f /tmp/migrations/clm_core_db/001_init_core_schema.sql
```

## Database Users and Permissions

### Recommended User Setup

Create separate database users with minimal required permissions:

```sql
-- Secure database user
CREATE USER clm_secure_user WITH PASSWORD 'secure_password_here';
GRANT CONNECT ON DATABASE clm_secure_db TO clm_secure_user;
GRANT USAGE ON SCHEMA public TO clm_secure_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO clm_secure_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clm_secure_user;

-- Core database user
CREATE USER clm_core_user WITH PASSWORD 'core_password_here';
GRANT CONNECT ON DATABASE clm_core_db TO clm_core_user;
GRANT USAGE ON SCHEMA public TO clm_core_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO clm_core_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clm_core_user;

-- Read-only auditor user
CREATE USER clm_auditor WITH PASSWORD 'auditor_password_here';
GRANT CONNECT ON DATABASE clm_secure_db TO clm_auditor;
GRANT CONNECT ON DATABASE clm_core_db TO clm_auditor;
GRANT USAGE ON SCHEMA public TO clm_auditor;
GRANT SELECT ON secure_audit_log TO clm_auditor;
GRANT SELECT ON audit_log TO clm_auditor;
```

## Cross-Database References

Since foreign key constraints cannot span databases, cross-database references are managed via UUIDs:

### From clm_secure_db to clm_core_db

| Table in clm_secure_db | Column | References in clm_core_db |
|------------------------|--------|---------------------------|
| encryption_keys | created_by_user_id | users.id |
| certificates | owner_user_id | users.id |
| certificates | policy_id | policies.id |
| certificates | workflow_id | workflows.id |
| private_keys | created_by_user_id | users.id |
| certificate_requests | requester_user_id | users.id |
| certificate_requests | approver_user_id | users.id |
| certificate_requests | policy_id | policies.id |
| certificate_requests | workflow_id | workflows.id |
| certificate_revocations | revoked_by_user_id | users.id |
| key_rotation_history | initiated_by_user_id | users.id |
| secure_audit_log | user_id | users.id |

### From clm_core_db to clm_secure_db

| Table in clm_core_db | Column | References in clm_secure_db |
|----------------------|--------|-----------------------------|
| workflow_instances | certificate_id | certificates.id |
| workflow_instances | certificate_request_id | certificate_requests.id |
| certificate_metadata | certificate_id | certificates.id |

**Important**: Application code must maintain referential integrity for these cross-database relationships.

## Indexing Strategy

### Primary Indexes

- All tables use UUID primary keys with default index
- Unique constraints create automatic indexes

### Performance Indexes

- Foreign key columns are indexed
- Status columns are indexed with partial indexes (WHERE deleted_at IS NULL)
- Timestamp columns for common query patterns
- JSONB columns use GIN indexes where appropriate

### Query-Specific Indexes

- Composite indexes for common JOIN patterns
- Partial indexes for active/non-deleted records
- Covering indexes for frequently accessed columns

## Soft Delete Pattern

Most tables implement soft deletes using the `deleted_at` timestamp:

```sql
-- Soft delete
UPDATE table_name SET deleted_at = CURRENT_TIMESTAMP WHERE id = 'uuid';

-- Query active records
SELECT * FROM table_name WHERE deleted_at IS NULL;

-- Restore (if needed)
UPDATE table_name SET deleted_at = NULL WHERE id = 'uuid';
```

Benefits:
- Maintains data integrity
- Preserves audit trail
- Allows data recovery
- Supports compliance requirements

## Encryption Fields

### clm_secure_db Encryption Pattern

All sensitive data in clm_secure_db should be encrypted:

```sql
-- private_keys table stores encrypted key material
{
    "encrypted_key_material": <bytea>,
    "encryption_key_id": <uuid>,
    "encryption_algorithm": "AES-256-GCM",
    "encryption_iv": <bytea>,
    "encryption_auth_tag": <bytea>
}
```

### Encryption Key Rotation

The `key_rotation_history` table tracks key rotation events. When rotating keys:

1. Create new encryption key
2. Re-encrypt all data using new key
3. Update `encryption_key_id` references
4. Mark old key as `retired`
5. Record rotation in history table

## Data Integrity Checks

### Constraints Implemented

- **NOT NULL** constraints on required fields
- **UNIQUE** constraints on natural keys
- **CHECK** constraints for enumerated values
- **Foreign keys** within same database
- **Date range** validation

### Application-Level Integrity

For cross-database references, implement:

1. Validation before insert/update
2. Cascade operations via application logic
3. Periodic integrity checks
4. Orphaned record cleanup jobs

## Monitoring and Maintenance

### Recommended Monitoring

1. **Table sizes and growth**
   ```sql
   SELECT schemaname, tablename, 
          pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
   FROM pg_tables 
   WHERE schemaname = 'public';
   ```

2. **Index usage**
   ```sql
   SELECT schemaname, tablename, indexname, idx_scan
   FROM pg_stat_user_indexes
   ORDER BY idx_scan;
   ```

3. **Slow queries**
   ```sql
   -- Enable pg_stat_statements extension
   SELECT query, calls, total_time, mean_time
   FROM pg_stat_statements
   ORDER BY mean_time DESC
   LIMIT 20;
   ```

### Maintenance Tasks

1. **VACUUM** - Reclaim storage and update statistics
   ```sql
   VACUUM ANALYZE;
   ```

2. **REINDEX** - Rebuild indexes periodically
   ```sql
   REINDEX DATABASE clm_secure_db;
   REINDEX DATABASE clm_core_db;
   ```

3. **Audit log cleanup** - Archive old audit logs
   ```sql
   -- Archive logs older than 1 year
   DELETE FROM audit_log WHERE event_timestamp < NOW() - INTERVAL '1 year';
   ```

## Backup and Recovery

### Backup Strategy

1. **Full backups** - Daily
   ```bash
   pg_dump -U postgres -d clm_secure_db -F c -f clm_secure_db_backup.dump
   pg_dump -U postgres -d clm_core_db -F c -f clm_core_db_backup.dump
   ```

2. **Point-in-time recovery** - Enable WAL archiving
   ```
   wal_level = replica
   archive_mode = on
   archive_command = 'cp %p /path/to/archive/%f'
   ```

3. **Separate secure DB backups** - Store encrypted backups separately

### Recovery

```bash
# Restore from backup
pg_restore -U postgres -d clm_secure_db -c clm_secure_db_backup.dump
pg_restore -U postgres -d clm_core_db -c clm_core_db_backup.dump
```

## Security Considerations

1. **Database Encryption**
   - Enable encryption at rest
   - Use SSL/TLS for connections
   - Rotate connection credentials regularly

2. **Access Control**
   - Principle of least privilege
   - Separate users for different components
   - Read-only users for reporting

3. **Audit Logging**
   - Both databases have comprehensive audit tables
   - Logs are write-only (no updates/deletes)
   - Regular log exports for compliance

4. **Row-Level Security**
   - Consider enabling RLS for multi-tenant isolation
   - Sample policy in migration files (commented out)

5. **Sensitive Data**
   - Private keys always encrypted
   - Encryption keys wrapped with master keys
   - No plaintext secrets in database

## Testing Migrations

### Validation Checklist

- [ ] All tables created successfully
- [ ] All indexes created
- [ ] All constraints enforced
- [ ] Triggers working correctly
- [ ] Views returning expected data
- [ ] Default roles seeded in clm_core_db
- [ ] No foreign key errors
- [ ] Extension dependencies resolved

### Test Queries

```sql
-- Verify table creation (secure DB)
SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename IN 
  ('encryption_keys', 'certificates', 'private_keys', 'certificate_requests');

-- Verify table creation (core DB)
SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename IN 
  ('users', 'roles', 'policies', 'workflows', 'audit_log');

-- Verify default roles created
SELECT role_code, role_name FROM roles WHERE is_system_role = TRUE;

-- Verify triggers
SELECT tgname, tgrelid::regclass FROM pg_trigger WHERE tgname LIKE 'trg_%';
```

## Rollback Procedures

To rollback migrations, drop and recreate databases:

```sql
-- WARNING: This will delete all data
DROP DATABASE clm_secure_db;
DROP DATABASE clm_core_db;

CREATE DATABASE clm_secure_db;
CREATE DATABASE clm_core_db;
```

For production, create explicit rollback scripts for each migration.

## Future Migrations

When creating new migrations:

1. **Naming Convention**: `NNN_description.sql` (e.g., `002_add_certificate_templates.sql`)
2. **Version Control**: Track migration execution in a `schema_migrations` table
3. **Idempotent**: Use `IF NOT EXISTS` where possible
4. **Backwards Compatible**: Avoid breaking changes
5. **Test**: Test on staging before production
6. **Document**: Update this README with changes

## Support

For questions or issues with migrations:
1. Check documentation in `/docs/database/`
2. Review migration file comments
3. Contact the database team
