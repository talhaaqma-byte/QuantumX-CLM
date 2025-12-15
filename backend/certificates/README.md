# Certificate Domain Models Documentation

## Overview

The Certificate Domain Models provide a comprehensive foundation for certificate lifecycle management in the CLM (Certificate Lifecycle Management) platform. This implementation focuses on metadata management in the core database while maintaining strict security boundaries with sensitive certificate data stored in the secure database.

## Architecture

### Dual-Database Design

The certificate system implements a security-first dual-database architecture:

- **clm_core_db**: Stores non-sensitive certificate metadata, ownership, and organizational information
- **clm_secure_db**: Stores sensitive cryptographic materials (private keys, certificates, etc.)

This design ensures:
- ✅ **Security**: Sensitive data remains isolated in the secure database
- ✅ **Performance**: Common queries run against the core database
- ✅ **Compliance**: Meets regulatory requirements for data separation
- ✅ **Scalability**: Allows independent scaling of metadata vs. cryptographic operations

### Core Components

```python
# Domain Models
from backend.certificates.models import (
    CertificateMetadata,  # Main certificate metadata model
    CertificateStatus,    # Status lifecycle enum
    CertificateType,      # Certificate type classification
    EnvironmentType,      # Environment classification
    Organization,         # Multi-tenancy support
)
```

## Certificate Metadata Model

### Key Features

#### Security-First Design
- **No Sensitive Data**: Never stores private keys, certificates, or cryptographic materials
- **UUID References**: Uses `certificate_id` to reference secure database records
- **Ownership Tracking**: Links certificates to users and organizations
- **Audit Trail**: Complete creation/modification history

#### Comprehensive Metadata
```python
class CertificateMetadata:
    # Security reference
    certificate_id: UUID  # References secure_db.certificates.id
    
    # Certificate information
    common_name: str      # CN field
    certificate_type: str # root, intermediate, leaf, client, server, code_signing, email
    status: str          # pending, active, expiring, expired, revoked, suspended
    
    # Validity period
    not_before: datetime  # Certificate validity start
    not_after: datetime   # Certificate validity end
    
    # Ownership
    owner_user_id: UUID   # Certificate owner
    organization_id: UUID # Organization context (optional)
    
    # Organization
    tags: List[str]       # Tagging for categorization
    category: str         # Certificate category
    environment: str      # production, staging, development, testing
    
    # Custom metadata
    custom_fields: dict   # Extensible key-value pairs
    notes: str            # Free-form notes
```

#### Business Logic Methods

```python
# Status checking
certificate.is_expired()              # Boolean: Is certificate expired?
certificate.is_expiring_soon(30)      # Boolean: Expires within N days?
certificate.get_remaining_days()      # Integer: Days until expiry

# Data export
certificate.to_dict()                 # Dict: Complete certificate data
```

### Certificate Status Lifecycle

The status field follows a comprehensive lifecycle:

```python
class CertificateStatus(str, Enum):
    PENDING    = "pending"    # Certificate requested, not yet issued
    ACTIVE     = "active"     # Certificate is valid and usable
    EXPIRING   = "expiring"   # Certificate expires soon (within warning period)
    EXPIRED    = "expired"    # Certificate validity has ended
    REVOKED    = "revoked"    # Certificate has been revoked by CA
    SUSPENDED  = "suspended"  # Certificate temporarily suspended
```

### Certificate Types

```python
class CertificateType(str, Enum):
    ROOT         = "root"         # Root CA certificate
    INTERMEDIATE = "intermediate" # Intermediate CA certificate
    LEAF         = "leaf"         # End-entity certificate
    CLIENT       = "client"       # Client authentication certificate
    SERVER       = "server"       # Server authentication certificate
    CODE_SIGNING = "code_signing" # Code signing certificate
    EMAIL        = "email"        # Email security certificate
```

### Environment Classification

```python
class EnvironmentType(str, Enum):
    PRODUCTION  = "production"   # Production environment
    STAGING     = "staging"      # Staging/testing environment
    DEVELOPMENT = "development"  # Development environment
    TESTING     = "testing"      # Testing environment
```

## Organization Model

### Multi-Tenancy Support

The Organization model enables certificate isolation across different entities:

```python
class Organization:
    # Basic information
    org_name: str      # Organization name
    org_code: str      # Unique organization code
    
    # Details
    description: str   # Organization description
    website: str       # Organization website
    industry: str      # Industry classification
    
    # Contact
    primary_contact_user_id: UUID    # Primary contact user
    billing_email: str               # Billing email
    support_email: str               # Support email
    
    # Settings
    settings: dict                   # Organization settings
    status: str                      # active, suspended, inactive
    
    # License
    license_type: str                # License type
    license_expires_at: datetime     # License expiration
    max_users: int                   # User limit
    max_certificates: int            # Certificate limit
```

## Pydantic Schemas

### Comprehensive API Schemas

The certificates module provides complete Pydantic schemas for API integration:

#### CertificateMetadataCreate
```python
from backend.certificates.schemas import CertificateMetadataCreate

# Create new certificate metadata
data = CertificateMetadataCreate(
    certificate_id="uuid-ref-to-secure-db",
    common_name="example.com",
    certificate_type=CertificateType.SERVER,
    not_before=datetime.now(),
    not_after=datetime.now() + timedelta(days=365),
    owner_user_id="owner-uuid",
    organization_id="org-uuid",  # Optional
    tags=["ssl", "web"],
    environment=EnvironmentType.PRODUCTION
)
```

#### CertificateMetadataResponse
```python
from backend.certificates.schemas import CertificateMetadataResponse

# Response includes computed fields
response = CertificateMetadataResponse.from_orm(certificate_metadata)
# Includes: days_until_expiry, is_expired, is_expiring_soon
```

#### CertificateMetadataSearch
```python
from backend.certificates.schemas import CertificateMetadataSearch

# Advanced search and filtering
search_params = CertificateMetadataSearch(
    certificate_type=CertificateType.SERVER,
    status=CertificateStatus.ACTIVE,
    environment=EnvironmentType.PRODUCTION,
    owner_user_id="owner-uuid",
    search_text="example.com",
    tags=["ssl"],
    page=1,
    per_page=50,
    sort_by="not_after",
    sort_order="asc"
)
```

## Database Integration

### Alembic Migration

The certificate metadata models are managed via Alembic:

```bash
# Apply certificate metadata migration
alembic -c backend/alembic_core.ini upgrade 0003

# View migration status
alembic -c backend/alembic_core.ini current

# Rollback if needed
alembic -c backend/alembic_core.ini downgrade 0002
```

### Database Constraints

#### Check Constraints
```sql
-- Certificate type validation
CONSTRAINT chk_certificate_metadata_type 
CHECK (certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email'))

-- Status validation
CONSTRAINT chk_certificate_metadata_status 
CHECK (status IN ('pending', 'active', 'expiring', 'expired', 'revoked', 'suspended'))

-- Validity period validation
CONSTRAINT chk_certificate_metadata_validity_period 
CHECK (not_before < not_after)
```

#### Performance Indexes
```sql
-- Certificate lookup by secure DB reference
CREATE INDEX idx_cert_metadata_cert_id ON certificate_metadata(certificate_id);

-- Ownership queries
CREATE INDEX idx_cert_metadata_owner ON certificate_metadata(owner_user_id);
CREATE INDEX idx_cert_metadata_org ON certificate_metadata(organization_id);

-- Status filtering
CREATE INDEX idx_cert_metadata_status ON certificate_metadata(status);

-- Expiry monitoring
CREATE INDEX idx_cert_metadata_expiry ON certificate_metadata(not_after);

-- Tag filtering
CREATE INDEX idx_cert_metadata_tags ON certificate_metadata USING GIN(tags);

-- Environment filtering
CREATE INDEX idx_cert_metadata_environment ON certificate_metadata(environment);
```

## Usage Examples

### Basic Certificate Management

```python
from sqlalchemy.ext.asyncio import AsyncSession
from backend.certificates.models import CertificateMetadata, CertificateStatus
from backend.certificates.schemas import CertificateMetadataCreate

async def create_certificate_metadata(
    db: AsyncSession,
    data: CertificateMetadataCreate
) -> CertificateMetadata:
    """Create new certificate metadata."""
    
    # Create ORM model
    cert_metadata = CertificateMetadata(
        certificate_id=data.certificate_id,
        common_name=data.common_name,
        certificate_type=data.certificate_type.value,
        status=data.status.value,
        not_before=data.not_before,
        not_after=data.not_after,
        owner_user_id=data.owner_user_id,
        organization_id=data.organization_id,
        tags=data.tags,
        category=data.category,
        environment=data.environment.value if data.environment else None,
        custom_fields=data.custom_fields,
        notes=data.notes
    )
    
    # Save to database
    db.add(cert_metadata)
    await db.commit()
    await db.refresh(cert_metadata)
    
    return cert_metadata
```

### Certificate Search and Filtering

```python
from sqlalchemy import select, and_, or_
from backend.certificates.models import CertificateMetadata

async def search_certificates(
    db: AsyncSession,
    owner_id: UUID | None = None,
    status: str | None = None,
    tags: List[str] | None = None
) -> List[CertificateMetadata]:
    """Search certificates with filtering."""
    
    query = select(CertificateMetadata)
    
    # Apply filters
    if owner_id:
        query = query.where(CertificateMetadata.owner_user_id == owner_id)
    
    if status:
        query = query.where(CertificateMetadata.status == status)
    
    if tags:
        query = query.where(
            CertificateMetadata.tags.contains(tags)
        )
    
    # Exclude soft-deleted records
    query = query.where(CertificateMetadata.deleted_at.is_(None))
    
    # Execute query
    result = await db.execute(query)
    return result.scalars().all()
```

### Expiry Monitoring

```python
from datetime import datetime, timedelta

async def find_expiring_certificates(
    db: AsyncSession,
    days_ahead: int = 30
) -> List[CertificateMetadata]:
    """Find certificates expiring within specified days."""
    
    cutoff_date = datetime.utcnow() + timedelta(days=days_ahead)
    
    query = select(CertificateMetadata).where(
        and_(
            CertificateMetadata.not_after <= cutoff_date,
            CertificateMetadata.not_after > datetime.utcnow(),
            CertificateMetadata.status.in_([CertificateStatus.ACTIVE, CertificateStatus.EXPIRING]),
            CertificateMetadata.deleted_at.is_(None)
        )
    ).order_by(CertificateMetadata.not_after)
    
    result = await db.execute(query)
    return result.scalars().all()
```

### Organization-Based Filtering

```python
async def get_org_certificates(
    db: AsyncSession,
    org_id: UUID
) -> List[CertificateMetadata]:
    """Get all certificates for an organization."""
    
    query = select(CertificateMetadata).where(
        and_(
            CertificateMetadata.organization_id == org_id,
            CertificateMetadata.deleted_at.is_(None)
        )
    ).order_by(CertificateMetadata.created_at.desc())
    
    result = await db.execute(query)
    return result.scalars().all()
```

## Integration Guidelines

### FastAPI Integration

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from backend.certificates.schemas import (
    CertificateMetadataCreate,
    CertificateMetadataResponse,
    CertificateMetadataSearch
)

router = APIRouter(prefix="/certificates", tags=["certificates"])

@router.post("/", response_model=CertificateMetadataResponse)
async def create_certificate(
    data: CertificateMetadataCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create new certificate metadata."""
    try:
        cert_metadata = await create_certificate_metadata(db, data)
        return CertificateMetadataResponse.from_orm(cert_metadata)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/", response_model=List[CertificateMetadataResponse])
async def list_certificates(
    search: CertificateMetadataSearch = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """List certificates with filtering and pagination."""
    # Implementation using search parameters
    pass
```

### Dependency Injection

```python
from backend.common.deps import get_db

# Database dependency
db: AsyncSession = Depends(get_db)

# Certificate repository dependency
from backend.certificates.repository import CertificateRepository

cert_repo = CertificateRepository(db)
```

## Best Practices

### Security Considerations

1. **Never Store Sensitive Data**: Keep all cryptographic operations in secure database
2. **Validate References**: Always validate `certificate_id` references exist in secure DB
3. **Audit All Changes**: Log all certificate metadata modifications
4. **Soft Deletes**: Use `deleted_at` for certificate removal to maintain audit trail

### Performance Optimization

1. **Use Appropriate Indexes**: Leverage existing indexes for common queries
2. **Limit Query Scope**: Always filter by `deleted_at IS NULL` for active records
3. **Paginate Results**: Use `page` and `per_page` for large result sets
4. **Batch Operations**: Use bulk operations for multiple certificate updates

### Data Integrity

1. **Validate Business Rules**: Ensure `not_before < not_after`
2. **Check Ownership**: Verify `owner_user_id` corresponds to valid user
3. **Maintain Consistency**: Keep certificate metadata in sync with secure DB
4. **Handle Dependencies**: Consider foreign key constraints in deletions

### Monitoring and Maintenance

1. **Expiry Monitoring**: Regularly check for expiring certificates
2. **Status Updates**: Implement automated status transitions (active → expiring → expired)
3. **Tag Management**: Establish tag taxonomies for consistent categorization
4. **Audit Logging**: Log all certificate-related activities

## Migration Strategy

### From Legacy Systems

When migrating from legacy certificate systems:

1. **Extract Metadata**: Separate sensitive from non-sensitive data
2. **Generate UUIDs**: Assign unique identifiers for cross-database references
3. **Validate References**: Ensure all certificate_id references are valid
4. **Migrate Gradually**: Use feature flags for phased migration

### Backward Compatibility

- **API Versioning**: Maintain API compatibility during migration
- **Database Migration**: Use Alembic for schema changes
- **Data Validation**: Implement comprehensive validation during import

## Error Handling

### Common Error Scenarios

1. **Invalid certificate_id**: Reference doesn't exist in secure database
2. **Duplicate certificate_id**: Attempting to create duplicate metadata
3. **Invalid ownership**: Owner user doesn't exist
4. **Validity period errors**: Invalid date ranges
5. **Permission errors**: User lacks permission for operation

### Error Response Format

```python
from fastapi import HTTPException

async def create_certificate_metadata(db, data):
    try:
        # Validate certificate_id exists in secure DB
        cert_exists = await validate_certificate_exists(data.certificate_id)
        if not cert_exists:
            raise HTTPException(
                status_code=400, 
                detail="Certificate ID not found in secure database"
            )
        
        # Check for duplicates
        existing = await get_certificate_by_id(data.certificate_id)
        if existing:
            raise HTTPException(
                status_code=409,
                detail="Certificate metadata already exists"
            )
        
        # Proceed with creation
        return await perform_creation(db, data)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
```

This comprehensive implementation provides a robust foundation for certificate metadata management while maintaining the security boundaries and architectural principles of the CLM platform.