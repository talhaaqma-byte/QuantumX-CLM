# CLM Platform Documentation

Welcome to the Certificate Lifecycle Management (CLM) platform documentation.

## Documentation Index

### Database Documentation

| Document | Description |
|----------|-------------|
| [Database Architecture](./database-architecture.md) | Complete overview of the two-database architecture, design decisions, and data flow patterns |
| [Schema Reference](./schema-reference.md) | Detailed reference for all database tables, columns, constraints, and indexes |
| [Database Security](./database-security.md) | Security best practices, access controls, encryption, and compliance guidelines |
| [Database Quick Start](./database-quickstart.md) | Step-by-step guide to set up databases locally, Docker, Kubernetes, and cloud |

### Backend Documentation

- [Backend API (FastAPI)](./backend-api.md) - Running the API, configuration, and dual-DB setup

### Migration Documentation

- [Migration README](../migrations/README.md) - Guide for running database migrations

## Quick Links

### Getting Started
1. Start with [Database Quick Start](./database-quickstart.md) to set up your databases
2. Review [Database Architecture](./database-architecture.md) to understand the design
3. Check [Schema Reference](./schema-reference.md) when working with specific tables
4. Follow [Database Security](./database-security.md) for production deployments

### For Developers
- **API Setup**: See [Backend API (FastAPI)](./backend-api.md)
- **Schema Changes**: See [Migration README](../migrations/README.md)
- **Query Examples**: See [Schema Reference](./schema-reference.md)
- **Access Patterns**: See [Database Architecture](./database-architecture.md)
- **Security Guidelines**: See [Database Security](./database-security.md)

### For Database Administrators
- **Setup Guide**: [Database Quick Start](./database-quickstart.md)
- **Security Hardening**: [Database Security](./database-security.md)
- **Backup & Recovery**: [Database Architecture](./database-architecture.md#backup-and-recovery)
- **Monitoring**: [Database Architecture](./database-architecture.md#monitoring)

### For Security Engineers
- **Security Architecture**: [Database Security](./database-security.md)
- **Encryption Strategy**: [Database Security](./database-security.md#encryption)
- **Access Controls**: [Database Security](./database-security.md#access-control)
- **Audit Logging**: [Database Security](./database-security.md#audit-logging)

## Database Overview

The CLM platform uses a **two-database architecture**:

### clm_secure_db
**Purpose**: Stores sensitive cryptographic materials
- Certificates and private keys (encrypted)
- Certificate signing requests (CSRs)
- Encryption keys and rotation history
- Revocation records
- Secure audit logs

### clm_core_db
**Purpose**: Stores application data and business logic
- Users, roles, and permissions
- Organizations (multi-tenancy)
- Policies and workflows
- Notifications and audit logs
- Certificate metadata (non-sensitive)
- API keys and sessions

### Key Features

✅ **Security Isolation** - Sensitive data separated from application data  
✅ **No Cross-Database Joins** - References via UUIDs only  
✅ **Comprehensive Auditing** - Every operation logged  
✅ **Soft Deletes** - Data retention for compliance  
✅ **Encryption Support** - Fields for encryption metadata  
✅ **Multi-Tenancy** - Organization-level isolation  
✅ **Flexible Schema** - JSONB for extensibility  

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│                                                              │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  Core Service    │         │  Secure Service  │         │
│  │  (Business Logic)│         │  (Crypto Ops)    │         │
│  └────────┬─────────┘         └────────┬─────────┘         │
└───────────┼──────────────────────────────┼─────────────────┘
            │                              │
            │ UUID References              │
            │ (No FK Constraints)          │
            │                              │
     ┌──────▼────────┐            ┌───────▼────────┐
     │ clm_core_db   │            │ clm_secure_db  │
     │               │            │                │
     │ • Users       │            │ • Certificates │
     │ • Roles       │            │ • Private Keys │
     │ • Policies    │            │ • Encryption   │
     │ • Workflows   │            │   Keys         │
     │ • Audit Logs  │            │ • Secure Audit │
     │ • Metadata    │◄──────────►│   Logs         │
     └───────────────┘            └────────────────┘
```

## Schema Summary

### clm_secure_db Tables

1. **encryption_keys** - Key management and rotation
2. **certificates** - X.509 certificates with full metadata
3. **private_keys** - Encrypted private key storage
4. **certificate_requests** - CSR tracking and approval
5. **certificate_revocations** - Revocation records for CRL/OCSP
6. **key_rotation_history** - Key rotation audit trail
7. **secure_audit_log** - Immutable audit log for sensitive operations

### clm_core_db Tables

1. **users** - User accounts and authentication
2. **roles** - Role definitions and permissions
3. **user_roles** - User-role assignments
4. **organizations** - Multi-tenant organizations
5. **user_organizations** - User-organization membership
6. **policies** - Certificate and security policies
7. **workflows** - Workflow definitions
8. **workflow_instances** - Workflow executions
9. **workflow_steps** - Individual workflow steps
10. **notifications** - User notifications
11. **audit_log** - Application audit trail
12. **api_keys** - API authentication
13. **sessions** - Session management
14. **certificate_metadata** - Non-sensitive certificate metadata

## Security Highlights

### Encryption
- All private keys encrypted at rest
- Encryption metadata stored with encrypted data
- Support for key rotation and versioning
- HSM integration points

### Access Control
- Role-based access control (RBAC)
- Row-level security support
- Separate database users for each service
- Audit logging for all sensitive operations

### Compliance
- GDPR-compliant data deletion
- SOC 2 audit trail
- PCI-DSS encryption standards
- Comprehensive logging for compliance

### Best Practices
- Soft deletes for data retention
- Parameterized queries to prevent SQL injection
- UUID primary keys for security
- Timestamp tracking for audit trail

## Common Patterns

### Soft Delete Pattern
```sql
-- Soft delete
UPDATE table_name 
SET deleted_at = CURRENT_TIMESTAMP 
WHERE id = 'uuid';

-- Query active records
SELECT * FROM table_name 
WHERE deleted_at IS NULL;
```

### Cross-Database References
```javascript
// Always validate references across databases
async function createCertificate(certData) {
    // 1. Validate user exists in clm_core_db
    const user = await coreDb.query(
        'SELECT id FROM users WHERE id = $1',
        [certData.ownerId]
    );
    if (!user) throw new Error('User not found');
    
    // 2. Create certificate in clm_secure_db
    const cert = await secureDb.query(
        'INSERT INTO certificates (...) VALUES (...)',
        [...]
    );
    
    // 3. Create metadata in clm_core_db
    await coreDb.query(
        'INSERT INTO certificate_metadata (...) VALUES (...)',
        [cert.id, ...]
    );
}
```

### Audit Logging
```javascript
// Log every sensitive operation
async function accessPrivateKey(certId, userId, ipAddress) {
    try {
        const key = await getPrivateKey(certId);
        
        await secureDb.query(`
            INSERT INTO secure_audit_log 
            (event_id, event_type, user_id, resource_id, action, result)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [uuidv4(), 'private_key_access', userId, certId, 'read', 'success']);
        
        return key;
    } catch (error) {
        await secureDb.query(`
            INSERT INTO secure_audit_log 
            (event_id, event_type, user_id, resource_id, action, result, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [uuidv4(), 'private_key_access', userId, certId, 'read', 'failure', error.message]);
        
        throw error;
    }
}
```

## Migration Workflow

1. **Review Migration** - Check SQL files in `/migrations/`
2. **Backup Databases** - Always backup before migrations
3. **Run Migrations** - Execute in order (001, 002, etc.)
4. **Verify** - Check tables, indexes, and data
5. **Test** - Run integration tests
6. **Document** - Update documentation if schema changes

## Development Workflow

### Local Development
1. Use Docker Compose for local databases
2. Run migrations to set up schema
3. Create test data for development
4. Use provided views for common queries

### Testing
1. Use separate test databases
2. Reset databases between test runs
3. Test cross-database integrity
4. Validate audit logging

### Production Deployment
1. Review security checklist
2. Set up monitoring and alerts
3. Configure backups and replication
4. Enable SSL/TLS
5. Implement firewall rules
6. Test disaster recovery

## Troubleshooting

### Common Issues

**Connection Refused**
- Check PostgreSQL is running
- Verify firewall rules
- Check `pg_hba.conf` configuration

**Permission Denied**
- Verify user has correct grants
- Check database ownership
- Review role assignments

**Cross-Database References Broken**
- Validate UUIDs exist in both databases
- Check application integrity validation
- Run orphaned record cleanup

**Performance Issues**
- Check index usage with `EXPLAIN`
- Review slow query logs
- Optimize connection pooling
- Consider read replicas

## Contributing

When making database changes:

1. Create migration files in `/migrations/`
2. Update schema reference documentation
3. Add examples to relevant docs
4. Test migrations on clean databases
5. Document breaking changes
6. Update this README if needed

## Maintenance Tasks

### Daily
- Monitor connection pool usage
- Check slow query logs
- Review error logs

### Weekly
- Review audit logs
- Check disk space
- Verify backups

### Monthly
- VACUUM ANALYZE databases
- Review index usage
- Archive old audit logs
- Test disaster recovery

### Quarterly
- Security audit
- Performance review
- Capacity planning
- Compliance review

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2024-12-15 | Initial schema design |

## Support

For issues or questions:
1. Check this documentation
2. Review schema reference
3. Check migration files
4. Contact database team

## License

All rights reserved.
