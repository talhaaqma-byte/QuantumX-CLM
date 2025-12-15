# QuantumX-CLM

Certificate Lifecycle Management Platform

Enterprise-grade platform for managing X.509 certificates, private keys, and cryptographic operations with comprehensive workflow automation and policy enforcement.

## Project Structure

```
clm-platform/
│
├── frontend/
│   └── react-app/           # React frontend application
│
├── backend/
│   ├── auth/                # Authentication & authorization services
│   ├── certificates/        # Certificate management
│   ├── workflows/           # Workflow engine
│   ├── policies/            # Policy management
│   ├── integrations/        # Third-party integrations
│   └── common/              # Shared backend utilities
│
├── infra/
│   ├── docker/              # Docker configurations
│   ├── k8s/                 # Kubernetes manifests
│   └── ci/                  # CI/CD pipelines
│
├── migrations/              # Database migrations
│   ├── clm_secure_db/       # Secure database (crypto materials)
│   └── clm_core_db/         # Core database (application data)
│
└── docs/                    # Documentation
    ├── database-architecture.md
    ├── schema-reference.md
    ├── database-security.md
    └── database-quickstart.md
```

## Architecture Overview

The CLM platform uses a **two-database architecture** for enhanced security:

### clm_secure_db
Stores sensitive cryptographic materials:
- X.509 certificates
- Encrypted private keys
- Certificate signing requests (CSRs)
- Encryption keys and rotation history
- Revocation records

### clm_core_db
Stores application data:
- Users, roles, and permissions
- Organizations (multi-tenancy)
- Policies and workflows
- Audit logs and notifications
- Certificate metadata (non-sensitive)

## Quick Start

### Database Setup

1. **Create databases:**
```bash
psql -U postgres -c "CREATE DATABASE clm_secure_db;"
psql -U postgres -c "CREATE DATABASE clm_core_db;"
```

2. **Run migrations:**
```bash
psql -U postgres -d clm_secure_db -f migrations/clm_secure_db/001_init_secure_schema.sql
psql -U postgres -d clm_core_db -f migrations/clm_core_db/001_init_core_schema.sql
```

3. **Verify installation:**
```bash
psql -U postgres -d clm_core_db -c "SELECT role_code FROM roles WHERE is_system_role = TRUE;"
```

For detailed setup instructions, see [Database Quick Start Guide](./docs/database-quickstart.md).

## Documentation

### Database Documentation
- **[Database Architecture](./docs/database-architecture.md)** - Two-database design, data flow, and scaling strategies
- **[Schema Reference](./docs/schema-reference.md)** - Complete table, column, and constraint reference
- **[Database Security](./docs/database-security.md)** - Security best practices and compliance guidelines
- **[Database Quick Start](./docs/database-quickstart.md)** - Setup guide for local, Docker, K8s, and cloud
- **[Migration Guide](./migrations/README.md)** - How to run and create migrations

### Key Features

✅ **Dual-Database Security** - Isolate sensitive crypto materials  
✅ **Comprehensive Auditing** - Every operation logged  
✅ **Multi-Tenancy** - Organization-level isolation  
✅ **Workflow Automation** - Configurable approval workflows  
✅ **Policy Enforcement** - Certificate policies and compliance  
✅ **Key Rotation** - Automated encryption key rotation  
✅ **HSM Support** - Hardware security module integration  
✅ **RBAC** - Role-based access control  

## Security Highlights

- **Encryption at Rest**: All private keys and sensitive data encrypted
- **Encryption in Transit**: SSL/TLS required for all database connections
- **No Cross-Database Joins**: Security isolation via UUID references
- **Audit Logging**: Comprehensive audit trails in both databases
- **Access Control**: Separate database users with minimal privileges
- **Compliance**: GDPR, SOC 2, and PCI-DSS ready

## Development Status

### Completed
- [x] Database schema design
- [x] Migration scripts
- [x] Comprehensive documentation
- [x] Security architecture

### In Progress
- [ ] Backend service implementation
- [ ] Frontend application
- [ ] API development
- [ ] Integration testing

## Technology Stack

- **Databases**: PostgreSQL 12+
- **Backend**: Node.js / Python (TBD)
- **Frontend**: React
- **Infrastructure**: Docker, Kubernetes
- **Cloud**: AWS / Azure / GCP support

## Getting Started

This project is currently in the setup phase. The database schema and migrations are complete.

Next steps:
1. Review the [database documentation](./docs/)
2. Set up local databases using the [quick start guide](./docs/database-quickstart.md)
3. Explore the [schema reference](./docs/schema-reference.md)
4. Backend implementation coming soon

## License

All rights reserved.

