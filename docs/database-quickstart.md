# Database Quick Start Guide

Get the CLM platform databases up and running quickly.

## Prerequisites

- PostgreSQL 12+ installed
- `psql` command-line tool
- Database administrator credentials
- Network access to database servers

## Quick Setup

### 1. Create Databases

```bash
# Connect as postgres superuser
psql -U postgres

# Create databases
CREATE DATABASE clm_secure_db;
CREATE DATABASE clm_core_db;

# Verify creation
\l

# Exit
\q
```

### 2. Run Migrations

```bash
# Navigate to migrations directory
cd /path/to/clm-platform/migrations

# Run secure database migration
psql -U postgres -d clm_secure_db -f clm_secure_db/001_init_secure_schema.sql

# Run core database migration
psql -U postgres -d clm_core_db -f clm_core_db/001_init_core_schema.sql
```

### 3. Verify Installation

```bash
# Check secure database tables
psql -U postgres -d clm_secure_db -c "\dt"

# Expected output:
# encryption_keys
# certificates
# private_keys
# certificate_requests
# certificate_revocations
# key_rotation_history
# secure_audit_log

# Check core database tables
psql -U postgres -d clm_core_db -c "\dt"

# Expected output:
# users
# roles
# user_roles
# organizations
# user_organizations
# policies
# workflows
# workflow_instances
# workflow_steps
# notifications
# audit_log
# api_keys
# sessions
# certificate_metadata
```

### 4. Verify Default Data

```bash
# Check default roles were created
psql -U postgres -d clm_core_db -c "SELECT role_code, role_name FROM roles WHERE is_system_role = TRUE;"

# Expected output:
# SYSTEM_ADMIN    | System Administrator
# CERT_ADMIN      | Certificate Administrator
# CERT_OPERATOR   | Certificate Operator
# APPROVER        | Approver
# AUDITOR         | Auditor
# USER            | User
```

## Docker Setup

### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  clm-core-db:
    image: postgres:14
    container_name: clm-core-db
    environment:
      POSTGRES_DB: clm_core_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - clm_core_data:/var/lib/postgresql/data
      - ./migrations/clm_core_db:/docker-entrypoint-initdb.d
    networks:
      - clm-network

  clm-secure-db:
    image: postgres:14
    container_name: clm-secure-db
    environment:
      POSTGRES_DB: clm_secure_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5433:5432"
    volumes:
      - clm_secure_data:/var/lib/postgresql/data
      - ./migrations/clm_secure_db:/docker-entrypoint-initdb.d
    networks:
      - clm-network

volumes:
  clm_core_data:
  clm_secure_data:

networks:
  clm-network:
    driver: bridge
```

Start the databases:

```bash
# Create .env file
echo "POSTGRES_PASSWORD=your_secure_password" > .env

# Start containers
docker-compose up -d

# Verify
docker-compose ps

# Check logs
docker-compose logs clm-core-db
docker-compose logs clm-secure-db
```

## Kubernetes Setup

### Using Helm Chart

Create `values.yaml`:

```yaml
postgresql:
  enabled: true
  
  # Core database
  core:
    persistence:
      enabled: true
      size: 50Gi
    resources:
      requests:
        memory: "2Gi"
        cpu: "1000m"
      limits:
        memory: "4Gi"
        cpu: "2000m"
    
  # Secure database
  secure:
    persistence:
      enabled: true
      size: 100Gi
    resources:
      requests:
        memory: "4Gi"
        cpu: "2000m"
      limits:
        memory: "8Gi"
        cpu: "4000m"
```

Deploy:

```bash
# Add Bitnami repo (if not already added)
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install PostgreSQL for core database
helm install clm-core-db bitnami/postgresql \
  --set auth.postgresPassword=secure_password \
  --set auth.database=clm_core_db \
  --set primary.persistence.size=50Gi

# Install PostgreSQL for secure database
helm install clm-secure-db bitnami/postgresql \
  --set auth.postgresPassword=secure_password \
  --set auth.database=clm_secure_db \
  --set primary.persistence.size=100Gi

# Run migrations
kubectl cp migrations/clm_core_db clm-core-db-postgresql-0:/tmp/
kubectl exec -it clm-core-db-postgresql-0 -- psql -U postgres -d clm_core_db -f /tmp/clm_core_db/001_init_core_schema.sql

kubectl cp migrations/clm_secure_db clm-secure-db-postgresql-0:/tmp/
kubectl exec -it clm-secure-db-postgresql-0 -- psql -U postgres -d clm_secure_db -f /tmp/clm_secure_db/001_init_secure_schema.sql
```

## AWS RDS Setup

### Using Terraform

```hcl
# Core database
resource "aws_db_instance" "clm_core" {
  identifier = "clm-core-db"
  
  engine               = "postgres"
  engine_version       = "14.7"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.database.arn
  
  db_name  = "clm_core_db"
  username = "postgres"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.core_db.id]
  db_subnet_group_name   = aws_db_subnet_group.database.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  tags = {
    Name = "CLM Core Database"
  }
}

# Secure database
resource "aws_db_instance" "clm_secure" {
  identifier = "clm-secure-db"
  
  engine               = "postgres"
  engine_version       = "14.7"
  instance_class       = "db.t3.large"
  allocated_storage    = 200
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.secure_database.arn
  
  db_name  = "clm_secure_db"
  username = "postgres"
  password = var.secure_db_password
  
  vpc_security_group_ids = [aws_security_group.secure_db.id]
  db_subnet_group_name   = aws_db_subnet_group.secure.name
  
  backup_retention_period = 30  # Longer retention for secure data
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  tags = {
    Name = "CLM Secure Database"
  }
}
```

Run migrations after RDS instances are created:

```bash
# Connect to core database
psql -h clm-core-db.xxxxxx.us-east-1.rds.amazonaws.com \
     -U postgres -d clm_core_db \
     -f migrations/clm_core_db/001_init_core_schema.sql

# Connect to secure database
psql -h clm-secure-db.xxxxxx.us-east-1.rds.amazonaws.com \
     -U postgres -d clm_secure_db \
     -f migrations/clm_secure_db/001_init_secure_schema.sql
```

## Create Application Users

After running migrations, create application-specific users:

```bash
# Create script: setup_users.sql
cat > setup_users.sql << 'EOF'
-- Core database user
\c clm_core_db
CREATE USER clm_core_app WITH PASSWORD 'strong_password_here';
GRANT CONNECT ON DATABASE clm_core_db TO clm_core_app;
GRANT USAGE ON SCHEMA public TO clm_core_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO clm_core_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clm_core_app;

-- Secure database user
\c clm_secure_db
CREATE USER clm_secure_app WITH PASSWORD 'strong_password_here';
GRANT CONNECT ON DATABASE clm_secure_db TO clm_secure_app;
GRANT USAGE ON SCHEMA public TO clm_secure_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO clm_secure_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clm_secure_app;

-- Auditor user
CREATE USER clm_auditor WITH PASSWORD 'strong_password_here';
\c clm_core_db
GRANT CONNECT ON DATABASE clm_core_db TO clm_auditor;
GRANT USAGE ON SCHEMA public TO clm_auditor;
GRANT SELECT ON audit_log TO clm_auditor;
\c clm_secure_db
GRANT CONNECT ON DATABASE clm_secure_db TO clm_auditor;
GRANT USAGE ON SCHEMA public TO clm_auditor;
GRANT SELECT ON secure_audit_log TO clm_auditor;
EOF

# Run the script
psql -U postgres -f setup_users.sql
```

## Connection Configuration

### Environment Variables

```bash
# .env file
# Core Database
CORE_DB_HOST=localhost
CORE_DB_PORT=5432
CORE_DB_NAME=clm_core_db
CORE_DB_USER=clm_core_app
CORE_DB_PASSWORD=strong_password_here
CORE_DB_SSL=true

# Secure Database
SECURE_DB_HOST=localhost
SECURE_DB_PORT=5433
SECURE_DB_NAME=clm_secure_db
SECURE_DB_USER=clm_secure_app
SECURE_DB_PASSWORD=strong_password_here
SECURE_DB_SSL=true
```

### Connection Strings

```bash
# Core database
postgresql://clm_core_app:password@localhost:5432/clm_core_db?sslmode=require

# Secure database
postgresql://clm_secure_app:password@localhost:5433/clm_secure_db?sslmode=require
```

## Testing the Setup

### Test Script

Create `test_db.sql`:

```sql
-- Test core database
\c clm_core_db

-- Check tables exist
SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';

-- Check default roles
SELECT role_code, role_name FROM roles WHERE is_system_role = TRUE;

-- Test insert
INSERT INTO users (username, email, password_hash, password_salt)
VALUES ('testuser', 'test@example.com', 'hash', 'salt')
RETURNING id;

-- Clean up test data
DELETE FROM users WHERE username = 'testuser';

-- Test secure database
\c clm_secure_db

-- Check tables exist
SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';

-- Check views
SELECT * FROM active_certificates LIMIT 1;
SELECT * FROM expiring_certificates LIMIT 1;

\echo 'All tests passed!'
```

Run tests:

```bash
psql -U postgres -f test_db.sql
```

## Common Issues

### Issue: Permission Denied

```
ERROR: permission denied for schema public
```

**Solution:**
```sql
GRANT USAGE ON SCHEMA public TO clm_core_app;
```

### Issue: Extension Not Found

```
ERROR: could not open extension control file
```

**Solution:**
```bash
# Install PostgreSQL contrib package
sudo apt-get install postgresql-contrib-14
```

### Issue: Connection Refused

```
could not connect to server: Connection refused
```

**Solution:**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Check pg_hba.conf allows connections
# Edit /etc/postgresql/14/main/pg_hba.conf

# Reload configuration
sudo systemctl reload postgresql
```

### Issue: Out of Disk Space

```
ERROR: could not extend file: No space left on device
```

**Solution:**
```bash
# Check disk space
df -h

# Clean up WAL files
# Adjust postgresql.conf:
# wal_keep_size = 1GB
# max_wal_size = 2GB
```

## Next Steps

1. **Security Hardening**
   - Review [database-security.md](./database-security.md)
   - Configure SSL/TLS
   - Set up firewall rules

2. **Backup Configuration**
   - Set up automated backups
   - Test restore procedures
   - Configure off-site replication

3. **Monitoring Setup**
   - Configure monitoring tools
   - Set up alerting
   - Create dashboards

4. **Application Integration**
   - Configure application connection pools
   - Test database operations
   - Run integration tests

## Resources

- [Database Architecture](./database-architecture.md)
- [Schema Reference](./schema-reference.md)
- [Security Best Practices](./database-security.md)
- [Migration README](../migrations/README.md)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the documentation in `/docs/`
3. Check migration files in `/migrations/`
4. Contact the database team
