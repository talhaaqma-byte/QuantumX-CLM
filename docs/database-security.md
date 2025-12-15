# Database Security Best Practices

This document outlines security best practices for the CLM platform's database architecture.

## Table of Contents

1. [Overview](#overview)
2. [Database Separation](#database-separation)
3. [Access Control](#access-control)
4. [Encryption](#encryption)
5. [Network Security](#network-security)
6. [Audit Logging](#audit-logging)
7. [Backup Security](#backup-security)
8. [Connection Security](#connection-security)
9. [SQL Injection Prevention](#sql-injection-prevention)
10. [Monitoring and Alerting](#monitoring-and-alerting)
11. [Compliance](#compliance)

## Overview

The CLM platform implements defense-in-depth security with multiple layers of protection for cryptographic materials and sensitive data.

### Security Principles

1. **Principle of Least Privilege** - Minimal necessary permissions
2. **Defense in Depth** - Multiple security layers
3. **Zero Trust** - Verify every access
4. **Data Isolation** - Separate sensitive from non-sensitive data
5. **Audit Everything** - Comprehensive logging

## Database Separation

### Two-Database Architecture

```
┌──────────────────────┐         ┌──────────────────────┐
│   clm_core_db        │         │   clm_secure_db      │
│   (Application Data) │         │   (Crypto Material)  │
│                      │         │                      │
│ • Less restrictive   │         │ • Highly restrictive │
│ • High throughput    │         │ • Encryption focused │
│ • General access     │         │ • Limited access     │
└──────────────────────┘         └──────────────────────┘
```

### Benefits

1. **Security Isolation**
   - Cryptographic materials isolated from general data
   - Breach of one database doesn't compromise both
   - Different encryption keys for each database

2. **Access Control**
   - Separate database users and permissions
   - Secure database accessible only by crypto service
   - Core database accessible by main application

3. **Compliance**
   - Easier to meet regulatory requirements
   - Separate audit trails
   - Different retention policies

4. **Performance**
   - Optimize each database independently
   - High-security operations don't impact general queries

### Cross-Database Reference Security

Since foreign key constraints don't span databases:

```javascript
// Always validate cross-database references
async function validateCrossDatabaseReference(userId) {
    // Check if user exists in core DB before using in secure DB
    const user = await coreDb.query(
        'SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL',
        [userId]
    );
    
    if (!user) {
        throw new Error('Invalid user reference');
    }
    
    return true;
}
```

## Access Control

### Database Users

Create separate database users with minimal permissions:

#### 1. Application User (Core DB)

```sql
-- Core database application user
CREATE USER clm_core_app WITH PASSWORD 'strong_random_password';

GRANT CONNECT ON DATABASE clm_core_db TO clm_core_app;
GRANT USAGE ON SCHEMA public TO clm_core_app;

-- Table-level permissions
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO clm_core_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clm_core_app;

-- No DELETE permissions - use soft deletes
-- No DDL permissions - schema changes via migrations only
```

#### 2. Application User (Secure DB)

```sql
-- Secure database application user (crypto service only)
CREATE USER clm_secure_app WITH PASSWORD 'strong_random_password';

GRANT CONNECT ON DATABASE clm_secure_db TO clm_secure_app;
GRANT USAGE ON SCHEMA public TO clm_secure_app;

GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO clm_secure_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clm_secure_app;

-- Restricted access to private_keys table
REVOKE ALL ON private_keys FROM clm_secure_app;
GRANT SELECT, INSERT, UPDATE (last_accessed_at, access_count) ON private_keys TO clm_secure_app;
```

#### 3. Read-Only Auditor

```sql
-- Auditor with read-only access to audit logs
CREATE USER clm_auditor WITH PASSWORD 'strong_random_password';

GRANT CONNECT ON DATABASE clm_core_db TO clm_auditor;
GRANT CONNECT ON DATABASE clm_secure_db TO clm_auditor;
GRANT USAGE ON SCHEMA public TO clm_auditor;

-- Only audit log access
GRANT SELECT ON audit_log TO clm_auditor;
GRANT SELECT ON secure_audit_log TO clm_auditor;
GRANT SELECT ON active_certificates TO clm_auditor;  -- View only
```

#### 4. Backup User

```sql
-- Backup user with minimal permissions
CREATE USER clm_backup WITH PASSWORD 'strong_random_password';

GRANT CONNECT ON DATABASE clm_core_db TO clm_backup;
GRANT CONNECT ON DATABASE clm_secure_db TO clm_backup;
GRANT USAGE ON SCHEMA public TO clm_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO clm_backup;
```

#### 5. Migration User

```sql
-- Migration user for schema changes (use only during migrations)
CREATE USER clm_migration WITH PASSWORD 'strong_random_password';

GRANT ALL PRIVILEGES ON DATABASE clm_core_db TO clm_migration;
GRANT ALL PRIVILEGES ON DATABASE clm_secure_db TO clm_migration;

-- Revoke after migrations complete
-- REVOKE ALL PRIVILEGES ON DATABASE clm_core_db FROM clm_migration;
```

### Row-Level Security (RLS)

Enable RLS for multi-tenant isolation:

```sql
-- Enable RLS on multi-tenant tables
ALTER TABLE certificate_metadata ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see certificates from their organization
CREATE POLICY org_isolation_policy ON certificate_metadata
    FOR ALL
    TO clm_core_app
    USING (organization_id = current_setting('app.current_org_id')::uuid);

-- Set organization context in application
-- SET LOCAL app.current_org_id = 'org-uuid';
```

### Permission Matrix

| User | Core DB | Secure DB | Audit Logs | Backups | Migrations |
|------|---------|-----------|------------|---------|------------|
| clm_core_app | SELECT, INSERT, UPDATE | - | - | - | - |
| clm_secure_app | - | SELECT, INSERT, UPDATE | - | - | - |
| clm_auditor | - | - | SELECT | - | - |
| clm_backup | SELECT | SELECT | SELECT | Full | - |
| clm_migration | ALL | ALL | ALL | - | ALL |

## Encryption

### Encryption at Rest

#### 1. Database-Level Encryption

```bash
# PostgreSQL with encryption at rest
# Using LUKS for disk encryption

# Encrypt the data directory
cryptsetup luksFormat /dev/sdb
cryptsetup luksOpen /dev/sdb pgdata_encrypted
mkfs.ext4 /dev/mapper/pgdata_encrypted
mount /dev/mapper/pgdata_encrypted /var/lib/postgresql/data
```

#### 2. Transparent Data Encryption (TDE)

For managed PostgreSQL services (AWS RDS, Azure Database, etc.):

```hcl
# Terraform example for AWS RDS
resource "aws_db_instance" "clm_secure" {
  identifier = "clm-secure-db"
  
  storage_encrypted = true
  kms_key_id       = aws_kms_key.database_encryption.arn
  
  # Other configuration...
}
```

#### 3. Column-Level Encryption

For highly sensitive fields:

```sql
-- Example: Encrypt MFA secret
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Insert with encryption
INSERT INTO users (username, email, mfa_secret)
VALUES (
    'user@example.com',
    'user@example.com',
    pgp_sym_encrypt('mfa_secret_value', 'encryption_key_from_vault')
);

-- Query with decryption
SELECT username, email, pgp_sym_decrypt(mfa_secret::bytea, 'encryption_key_from_vault')
FROM users
WHERE id = 'user-uuid';
```

### Encryption in Transit

#### SSL/TLS Configuration

```sql
-- PostgreSQL configuration (postgresql.conf)
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/ca.crt'
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
ssl_prefer_server_ciphers = on
ssl_min_protocol_version = 'TLSv1.2'
```

#### Connection String

```javascript
// Node.js connection with SSL
const pool = new Pool({
    host: 'db-host',
    database: 'clm_secure_db',
    user: 'clm_secure_app',
    password: process.env.DB_PASSWORD,
    ssl: {
        rejectUnauthorized: true,
        ca: fs.readFileSync('/path/to/ca.crt').toString(),
        cert: fs.readFileSync('/path/to/client.crt').toString(),
        key: fs.readFileSync('/path/to/client.key').toString(),
    },
});
```

### Key Management

#### Encryption Key Storage

```javascript
// Use a secrets manager for encryption keys
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getEncryptionKey(keyId) {
    const secret = await secretsManager.getSecretValue({
        SecretId: `clm/encryption-keys/${keyId}`
    }).promise();
    
    return JSON.parse(secret.SecretString).key;
}
```

#### Key Rotation

```sql
-- Key rotation workflow
BEGIN;

-- 1. Create new key
INSERT INTO encryption_keys (key_id, key_type, algorithm, encrypted_key_material, ...)
VALUES ('key-v2', 'data', 'AES-256-GCM', ...) RETURNING id;

-- 2. Log rotation start
INSERT INTO key_rotation_history (old_key_id, new_key_id, rotation_type, ...)
VALUES ('old-key-id', 'new-key-id', 'scheduled', ...);

-- 3. Re-encrypt data (application logic)
-- ... re-encrypt private keys, etc.

-- 4. Mark old key as retired
UPDATE encryption_keys
SET key_status = 'retired'
WHERE id = 'old-key-id';

-- 5. Complete rotation
UPDATE key_rotation_history
SET rotation_status = 'completed', rotation_completed_at = NOW()
WHERE id = 'rotation-id';

COMMIT;
```

## Network Security

### Network Segmentation

```
┌─────────────────────────────────────────┐
│         Application Tier                 │
│  ┌──────────────┐   ┌──────────────┐   │
│  │ Core Service │   │Crypto Service│   │
│  └──────┬───────┘   └──────┬───────┘   │
└─────────┼──────────────────┼───────────┘
          │                  │
    ┌─────▼─────┐      ┌─────▼─────┐
    │  Private  │      │  Highly   │
    │  Subnet   │      │ Restricted│
    │           │      │  Subnet   │
    │ clm_core  │      │clm_secure │
    │    _db    │      │    _db    │
    └───────────┘      └───────────┘
```

### Firewall Rules

```bash
# Core database - accessible from application subnet
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 5432 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -j DROP

# Secure database - accessible only from crypto service
iptables -A INPUT -s 10.0.2.10/32 -p tcp --dport 5433 -j ACCEPT
iptables -A INPUT -p tcp --dport 5433 -j DROP
```

### PostgreSQL Host-Based Access

```
# pg_hba.conf

# Core database - allow from application subnet with SSL
hostssl clm_core_db clm_core_app 10.0.1.0/24 md5

# Secure database - allow only from crypto service with SSL + cert
hostssl clm_secure_db clm_secure_app 10.0.2.10/32 cert

# Auditor from management network
hostssl all clm_auditor 10.0.0.0/24 md5

# Deny all others
host all all 0.0.0.0/0 reject
```

## Audit Logging

### Database Audit Logging

Enable PostgreSQL audit extension:

```sql
-- Install pgaudit extension
CREATE EXTENSION pgaudit;

-- Configure auditing
ALTER SYSTEM SET pgaudit.log = 'ddl, write, role';
ALTER SYSTEM SET pgaudit.log_catalog = off;
ALTER SYSTEM SET pgaudit.log_parameter = on;
ALTER SYSTEM SET pgaudit.log_relation = on;

-- Reload configuration
SELECT pg_reload_conf();
```

### Application-Level Auditing

```javascript
// Audit every database operation
async function auditedQuery(db, query, params, context) {
    const startTime = Date.now();
    const auditId = uuidv4();
    
    try {
        const result = await db.query(query, params);
        
        // Log successful operation
        await db.query(`
            INSERT INTO audit_log (event_id, event_type, user_id, action, result, event_data)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [
            auditId,
            'database_operation',
            context.userId,
            'query',
            'success',
            JSON.stringify({
                query: query.substring(0, 100),
                rowCount: result.rowCount,
                duration: Date.now() - startTime
            })
        ]);
        
        return result;
    } catch (error) {
        // Log failed operation
        await db.query(`
            INSERT INTO audit_log (event_id, event_type, user_id, action, result, error_message)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [
            auditId,
            'database_operation',
            context.userId,
            'query',
            'failure',
            error.message
        ]);
        
        throw error;
    }
}
```

### Audit Log Retention

```sql
-- Create partition for audit logs by month
CREATE TABLE audit_log_2024_01 PARTITION OF audit_log
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Archive old audit logs
DO $$
DECLARE
    archive_date DATE;
BEGIN
    archive_date := NOW() - INTERVAL '1 year';
    
    -- Export to archive table
    INSERT INTO audit_log_archive
    SELECT * FROM audit_log WHERE event_timestamp < archive_date;
    
    -- Delete from main table
    DELETE FROM audit_log WHERE event_timestamp < archive_date;
END $$;
```

## Backup Security

### Encrypted Backups

```bash
#!/bin/bash
# Encrypted backup script

BACKUP_DIR="/backups/encrypted"
ENCRYPTION_KEY="/secure/backup_key.gpg"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup secure database with encryption
pg_dump -U clm_backup -d clm_secure_db -F c | \
    gpg --encrypt --recipient backup@example.com | \
    gzip > "$BACKUP_DIR/clm_secure_db_$DATE.dump.gpg.gz"

# Backup core database with encryption
pg_dump -U clm_backup -d clm_core_db -F c | \
    gpg --encrypt --recipient backup@example.com | \
    gzip > "$BACKUP_DIR/clm_core_db_$DATE.dump.gpg.gz"

# Set restrictive permissions
chmod 400 "$BACKUP_DIR"/*

# Upload to secure storage
aws s3 cp "$BACKUP_DIR/" s3://clm-backups/encrypted/ --recursive \
    --sse aws:kms --sse-kms-key-id alias/backup-key
```

### Backup Verification

```bash
#!/bin/bash
# Verify backup integrity

# Decrypt and test restore
gpg --decrypt clm_secure_db_backup.dump.gpg.gz | \
    gunzip | \
    pg_restore --list -

# Verify checksums
sha256sum -c backup_checksums.txt
```

### Off-Site Backup

```bash
# Replicate to secondary region
aws s3 sync s3://clm-backups/encrypted/ \
    s3://clm-backups-dr/encrypted/ \
    --region us-west-2 \
    --sse aws:kms
```

## Connection Security

### Connection Pooling

```javascript
// Secure connection pool configuration
const { Pool } = require('pg');

const securePool = new Pool({
    host: process.env.SECURE_DB_HOST,
    port: 5433,
    database: 'clm_secure_db',
    user: 'clm_secure_app',
    password: process.env.SECURE_DB_PASSWORD,
    
    // SSL configuration
    ssl: {
        rejectUnauthorized: true,
        ca: fs.readFileSync('/certs/ca.crt'),
        cert: fs.readFileSync('/certs/client.crt'),
        key: fs.readFileSync('/certs/client.key'),
    },
    
    // Connection pool settings
    max: 10,  // Maximum connections
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    
    // Security settings
    statement_timeout: 30000,  // 30 second query timeout
    query_timeout: 30000,
});

// Handle connection errors
securePool.on('error', (err, client) => {
    console.error('Unexpected database error:', err);
    // Alert security team
});
```

### Credential Management

```javascript
// Use secrets manager for credentials
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getDatabaseCredentials() {
    const secret = await secretsManager.getSecretValue({
        SecretId: 'clm/database/secure-db'
    }).promise();
    
    return JSON.parse(secret.SecretString);
}

// Rotate credentials regularly
async function rotateCredentials() {
    // 1. Create new credentials
    const newPassword = generateSecurePassword();
    
    // 2. Update database
    await adminPool.query(
        'ALTER USER clm_secure_app WITH PASSWORD $1',
        [newPassword]
    );
    
    // 3. Update secrets manager
    await secretsManager.updateSecret({
        SecretId: 'clm/database/secure-db',
        SecretString: JSON.stringify({
            username: 'clm_secure_app',
            password: newPassword,
            host: process.env.DB_HOST,
        })
    }).promise();
    
    // 4. Restart application to pick up new credentials
}
```

## SQL Injection Prevention

### Parameterized Queries

```javascript
// GOOD: Parameterized query
async function getUser(userId) {
    const result = await pool.query(
        'SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL',
        [userId]
    );
    return result.rows[0];
}

// BAD: String concatenation (vulnerable to SQL injection)
async function getUserBAD(userId) {
    const result = await pool.query(
        `SELECT * FROM users WHERE id = '${userId}' AND deleted_at IS NULL`
    );
    return result.rows[0];
}
```

### Input Validation

```javascript
const { validate: isUUID } = require('uuid');

async function getCertificate(certId) {
    // Validate input
    if (!isUUID(certId)) {
        throw new Error('Invalid certificate ID format');
    }
    
    // Safe to query
    const result = await securePool.query(
        'SELECT * FROM certificates WHERE id = $1',
        [certId]
    );
    
    return result.rows[0];
}
```

### Stored Procedures for Complex Operations

```sql
-- Create stored procedure for sensitive operations
CREATE OR REPLACE FUNCTION access_private_key(
    p_certificate_id UUID,
    p_user_id UUID,
    p_ip_address INET
) RETURNS BYTEA AS $$
DECLARE
    v_encrypted_key BYTEA;
    v_allowed BOOLEAN;
BEGIN
    -- Check access policy
    SELECT check_key_access_policy(p_certificate_id, p_user_id)
    INTO v_allowed;
    
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'Access denied to private key';
    END IF;
    
    -- Retrieve key
    SELECT encrypted_key_material INTO v_encrypted_key
    FROM private_keys
    WHERE certificate_id = p_certificate_id AND deleted_at IS NULL;
    
    -- Update access tracking
    UPDATE private_keys
    SET last_accessed_at = NOW(),
        access_count = access_count + 1
    WHERE certificate_id = p_certificate_id;
    
    -- Audit log
    INSERT INTO secure_audit_log (
        event_id, event_type, event_category, severity,
        resource_type, resource_id, action,
        user_id, ip_address, result
    ) VALUES (
        gen_random_uuid()::text, 'private_key_access', 'key_access', 'info',
        'private_key', p_certificate_id, 'read',
        p_user_id, p_ip_address, 'success'
    );
    
    RETURN v_encrypted_key;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

## Monitoring and Alerting

### Security Metrics

```javascript
// Prometheus metrics for security monitoring
const prometheus = require('prom-client');

const dbAccessCounter = new prometheus.Counter({
    name: 'clm_db_access_total',
    help: 'Total database access operations',
    labelNames: ['database', 'user', 'operation', 'result']
});

const privateKeyAccessCounter = new prometheus.Counter({
    name: 'clm_private_key_access_total',
    help: 'Total private key access operations',
    labelNames: ['result']
});

const failedAuthAttempts = new prometheus.Counter({
    name: 'clm_failed_auth_attempts_total',
    help: 'Total failed authentication attempts',
    labelNames: ['user', 'reason']
});

// Alert rules
const alertRules = `
groups:
  - name: database_security
    rules:
      - alert: HighFailedAuthAttempts
        expr: rate(clm_failed_auth_attempts_total[5m]) > 5
        labels:
          severity: warning
        annotations:
          summary: High rate of failed authentication attempts
          
      - alert: UnauthorizedPrivateKeyAccess
        expr: clm_private_key_access_total{result="failure"} > 0
        labels:
          severity: critical
        annotations:
          summary: Unauthorized private key access attempted
`;
```

### Anomaly Detection

```sql
-- Query to detect unusual access patterns
SELECT 
    user_id,
    COUNT(*) as access_count,
    array_agg(DISTINCT ip_address) as ip_addresses,
    array_agg(DISTINCT resource_type) as resources_accessed
FROM secure_audit_log
WHERE event_timestamp > NOW() - INTERVAL '1 hour'
    AND event_category = 'key_access'
GROUP BY user_id
HAVING COUNT(*) > 100  -- Threshold for unusual activity
ORDER BY access_count DESC;
```

## Compliance

### GDPR Compliance

```sql
-- Right to be forgotten (data deletion)
CREATE OR REPLACE FUNCTION gdpr_delete_user(p_user_id UUID)
RETURNS VOID AS $$
BEGIN
    -- Soft delete user
    UPDATE users
    SET deleted_at = NOW(),
        email = 'deleted_' || id || '@gdpr.local',
        username = 'deleted_' || id,
        first_name = NULL,
        last_name = NULL,
        phone_number = NULL,
        mfa_secret = NULL
    WHERE id = p_user_id;
    
    -- Anonymize audit logs (keep for compliance)
    UPDATE audit_log
    SET username = 'anonymized',
        ip_address = NULL,
        user_agent = NULL
    WHERE user_id = p_user_id;
    
    -- Note: Keep certificate records for audit trail
END;
$$ LANGUAGE plpgsql;
```

### SOC 2 Compliance

- Audit logging: All access logged
- Encryption: Data encrypted at rest and in transit
- Access control: Role-based with least privilege
- Change management: All schema changes tracked
- Backup and recovery: Regular tested backups

### PCI-DSS Compliance

- Encryption: All sensitive data encrypted
- Access logging: Comprehensive audit trails
- Strong authentication: MFA enforced
- Regular testing: Quarterly security audits
- Secure configuration: Hardened database settings

## Security Checklist

- [ ] Database-level encryption enabled
- [ ] SSL/TLS required for all connections
- [ ] Certificate-based authentication configured
- [ ] Least privilege access controls implemented
- [ ] Row-level security policies defined
- [ ] Audit logging enabled and monitored
- [ ] Backup encryption configured
- [ ] Off-site backup replication enabled
- [ ] Secrets manager for credentials
- [ ] Regular credential rotation scheduled
- [ ] Network segmentation implemented
- [ ] Firewall rules configured
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented
- [ ] Regular security audits scheduled
- [ ] Compliance requirements documented

## References

- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- [OWASP Database Security](https://owasp.org/www-community/vulnerabilities/Database_Security)
- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
