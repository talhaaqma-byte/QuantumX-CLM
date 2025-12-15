# Secure Certificate Storage Interface

## Overview

The `SecureCertificateStorageInterface` defines a contract for secure certificate storage implementations. This interface establishes strict security constraints to ensure that sensitive cryptographic material (private keys, encrypted key material) is never exposed, logged, or returned through normal operations.

**File Location**: `backend/certificates/interfaces.py`

## Key Design Principles

### 1. **No Private Key Exposure**

The interface guarantees that private keys are **never** exposed through any method:

- Methods return `CertificateReference` objects containing only non-sensitive metadata
- Private keys remain encrypted and isolated within the storage implementation
- No method returns raw key material, even in decrypted form
- Sensitive operations are abstracted away from this interface level

### 2. **Private Keys Must Be Pre-Encrypted**

When storing a certificate with a private key:

```python
# Caller is responsible for encrypting the private key BEFORE calling store_certificate
encrypted_key = kms.encrypt(
    plaintext=private_key_pem,
    key_id=encryption_key_id
)

# Then pass the encrypted bytes to storage
request = StoreCertificateRequest(
    certificate_id=cert_id,
    pem_encoded_certificate=cert_pem,
    private_key_encrypted=encrypted_key,  # Already encrypted!
    key_encryption_key_id=encryption_key_id,
    ...
)

cert_ref = await storage.store_certificate(request)
```

**Why?** This separation of concerns ensures:
- Storage layer doesn't need to implement encryption
- Encryption can be provided by HSM, KMS, or other services
- The interface remains backend-agnostic
- Caller maintains control over key encryption

### 3. **Encryption at Rest**

Implementations must ensure:

- All sensitive data is encrypted using strong algorithms (AES-256-GCM or equivalent)
- Encryption keys are rotated regularly
- Encryption keys themselves are protected
- Decryption happens only when explicitly needed
- No plaintext private key material persists in storage

### 4. **Immutable Revocation Records**

Revocation is permanent and immutable:

- Once revoked, a certificate cannot be unrevoked
- Revocation creates an immutable audit record
- Revocation reason is captured for compliance
- The certificate still exists in storage but is marked revoked
- Applications must check revocation status separately

## Interface Contract

### Method: `store_certificate()`

Stores a certificate with optional encrypted private key.

**Signature:**
```python
async def store_certificate(
    self, request: StoreCertificateRequest
) -> CertificateReference
```

**Input: `StoreCertificateRequest`**

```python
StoreCertificateRequest(
    certificate_id=UUID(...),              # Unique cert ID
    common_name="example.com",              # CN from certificate
    certificate_type="server",              # root|intermediate|leaf|client|server|code_signing|email
    pem_encoded_certificate="-----BEGIN...",  # PEM cert (public part)
    certificate_chain=[...],                # Optional cert chain
    private_key_encrypted=b"...",           # OPTIONAL: Pre-encrypted key bytes
    key_encryption_key_id=UUID(...),        # OPTIONAL: ID of KEK used
    issuer_dn="CN=Let's Encrypt Authority...",  # Issuer DN
    subject_dn="CN=example.com",            # Subject DN
    not_before=datetime(...),               # Validity start
    not_after=datetime(...),                # Validity end
    serial_number="12345",                  # Serial number
    thumbprint_sha256="abc123...",          # SHA256 fingerprint
    thumbprint_sha1="def456...",            # OPTIONAL: SHA1 fingerprint
    key_algorithm="RSA",                    # RSA|ECDSA|Ed25519
    key_size=2048,                          # OPTIONAL: Key size in bits
    signature_algorithm="sha256WithRSAEncryption",  # Sig algorithm
    owner_user_id=UUID(...),                # Certificate owner
    organization_id=UUID(...),              # OPTIONAL: Organization
    custom_metadata={...}                   # OPTIONAL: Custom metadata
)
```

**Output: `CertificateReference`**

```python
CertificateReference(
    certificate_id=UUID(...),
    common_name="example.com",
    certificate_type="server",
    issuer_dn="CN=Let's Encrypt Authority...",
    subject_dn="CN=example.com",
    not_before=datetime(...),
    not_after=datetime(...),
    serial_number="12345",
    thumbprint_sha256="abc123...",
    key_algorithm="RSA",
    key_size=2048,
    signature_algorithm="sha256WithRSAEncryption",
    owner_user_id=UUID(...),
    organization_id=UUID(...),
    stored_at=datetime(...),                # When stored
    custom_metadata={...}                   # Non-sensitive metadata
    # NOTE: No private_key, encrypted_key, or any sensitive data
)
```

**Exceptions:**
- `CertificateAlreadyStoredException`: Certificate ID already exists
- `EncryptionKeyNotFoundException`: Referenced encryption key not found
- `InvalidCertificateException`: Certificate data is invalid
- `SecureStorageOperationException`: Storage operation failed

**Security Guarantees:**
- Private key (if provided) is encrypted immediately upon receipt
- Certificate is validated for integrity
- Thumbprint is computed and verified
- Operation is atomic - fully succeeds or fully fails
- Audit entry is created with context (user_id, timestamp, certificate_id)

**Example:**
```python
from uuid import uuid4
from backend.certificates.interfaces import (
    SecureCertificateStorageInterface,
    StoreCertificateRequest
)

storage: SecureCertificateStorageInterface = ...  # Injected implementation

# 1. Prepare certificate and encrypted key
cert_id = uuid4()
cert_pem = "-----BEGIN CERTIFICATE-----\n..."
encrypted_key = await kms.encrypt(private_key_pem, kek_id)

# 2. Create storage request
request = StoreCertificateRequest(
    certificate_id=cert_id,
    common_name="api.example.com",
    certificate_type="server",
    pem_encoded_certificate=cert_pem,
    private_key_encrypted=encrypted_key,
    key_encryption_key_id=kek_id,
    issuer_dn="CN=Let's Encrypt Authority X3",
    subject_dn="CN=api.example.com",
    not_before=datetime(2024, 1, 1),
    not_after=datetime(2025, 1, 1),
    serial_number="123456789",
    thumbprint_sha256="a" * 64,
    key_algorithm="RSA",
    key_size=2048,
    signature_algorithm="sha256WithRSAEncryption",
    owner_user_id=admin_user_id,
    organization_id=org_id
)

# 3. Store certificate
cert_ref = await storage.store_certificate(request)
print(f"Stored: {cert_ref.certificate_id}")

# Private key is NOT in cert_ref - it's encrypted and stored separately
```

### Method: `retrieve_certificate_reference()`

Retrieves a certificate reference without exposing private keys.

**Signature:**
```python
async def retrieve_certificate_reference(
    self, certificate_id: UUID
) -> CertificateReference
```

**Input:**
- `certificate_id` (UUID): ID of the certificate to retrieve

**Output: `CertificateReference`**

Same as `store_certificate()` output - contains no sensitive data.

**Exceptions:**
- `CertificateNotFoundException`: Certificate not found
- `SecureStorageOperationException`: Retrieval operation failed

**Security Notes:**
- Returned data is completely safe to log
- Safe to cache in distributed systems
- Safe to pass to untrusted code
- Read-only operation
- Can be audited separately from write operations
- Does NOT require special credentials or permissions

**Example:**
```python
# Retrieve certificate information (safe, no secrets exposed)
ref = await storage.retrieve_certificate_reference(cert_id)

# All of these operations are safe - no sensitive data
print(f"Certificate: {ref.common_name}")
print(f"Valid: {ref.not_before} to {ref.not_after}")
print(f"Issuer: {ref.issuer_dn}")
print(f"Thumbprint: {ref.thumbprint_sha256}")  # Safe to log, send to clients
print(f"Key: {ref.key_algorithm} {ref.key_size} bits")

# Log to audit system safely
audit_log.info(f"Certificate {ref.common_name} accessed by user {ref.owner_user_id}")

# Send to client API
return {
    "id": str(ref.certificate_id),
    "common_name": ref.common_name,
    "thumbprint": ref.thumbprint_sha256,
    "expires_at": ref.not_after.isoformat(),
}
```

### Method: `revoke_certificate_reference()`

Revokes a certificate with an immutable revocation record.

**Signature:**
```python
async def revoke_certificate_reference(
    self,
    certificate_id: UUID,
    request: RevokeCertificateRequest
) -> CertificateRevocationReference
```

**Input: `RevokeCertificateRequest`**

```python
RevokeCertificateRequest(
    revocation_reason="keyCompromise",      # RFC 5280 reason
    revoked_by_user_id=UUID(...),           # Who revoked it
    notes="Key leaked in logs"              # OPTIONAL: Additional context
)
```

**Output: `CertificateRevocationReference`**

```python
CertificateRevocationReference(
    certificate_id=UUID(...),
    common_name="example.com",
    revocation_reason="keyCompromise",
    revoked_at=datetime(...),               # When revoked
    revoked_by_user_id=UUID(...),           # Who revoked it
    notes="Key leaked in logs"
)
```

**Exceptions:**
- `CertificateNotFoundException`: Certificate not found
- `CertificateAlreadyRevokedException`: Certificate already revoked
- `SecureStorageOperationException`: Revocation operation failed

**Security Guarantees:**
- Revocation is immutable and permanent
- Cannot be unrevoked once revoked
- Audit trail is created with user_id and timestamp
- Reason is captured for compliance requirements
- Private key (if stored) remains encrypted even after revocation

**Valid Revocation Reasons (RFC 5280):**

| Reason | Code | When to Use |
|--------|------|------------|
| `unspecified` | 0 | No specific reason given |
| `keyCompromise` | 1 | Private key was compromised/exposed |
| `cACompromise` | 2 | CA private key was compromised |
| `affiliationChanged` | 3 | Subject's affiliation changed |
| `superseded` | 4 | Replaced by new certificate |
| `cessationOfOperation` | 5 | Subject ceased operation |
| `certificateHold` | 6 | Temporary hold (may be lifted) |
| `removeFromCRL` | 8 | Remove from CRL (re-issuing) |
| `privilegeWithdrawn` | 9 | Privileges/authority withdrawn |
| `aACompromise` | 10 | AA private key was compromised |

**Example:**
```python
# Security admin discovers key was compromised
try:
    revocation = await storage.revoke_certificate_reference(
        cert_id,
        RevokeCertificateRequest(
            revocation_reason="keyCompromise",
            revoked_by_user_id=security_admin_id,
            notes="Private key found in GitHub commit history"
        )
    )
    print(f"Certificate revoked at {revocation.revoked_at}")
    
    # Notify stakeholders
    await notify_certificate_users(cert_id, revocation)
    
except CertificateAlreadyRevokedException:
    print(f"Certificate {cert_id} is already revoked")
    
except CertificateNotFoundException:
    print(f"Certificate {cert_id} does not exist")
```

**Checking Revocation Status:**

```python
# After revocation, the certificate still exists but is marked revoked
cert_ref = await storage.retrieve_certificate_reference(cert_id)
# cert_ref is still available

# Applications must check revocation status SEPARATELY
# This is implementation-dependent:
# - Some implementations might include a 'status' field in CertificateReference
# - Others might require a separate query
# - CRLs or OCSP could be used for distributed revocation checks

# Example: Implementation might add to CertificateReference
if hasattr(cert_ref, 'status') and cert_ref.status == 'revoked':
    raise CertificateRevokedException(cert_id)
```

## Data Models

### `StoreCertificateRequest`

**Purpose**: Encapsulates all data needed to store a certificate securely.

**Security Notes**:
- Private key MUST be pre-encrypted by caller
- All PEM strings are plaintext (safe - just X.509 public data)
- Immutable (frozen=True) to prevent modification after validation

**Fields**:
- `certificate_id` (UUID): Unique identifier, must be v4 UUID
- `common_name` (str): Certificate CN (from X.509)
- `certificate_type` (str): One of: root, intermediate, leaf, client, server, code_signing, email
- `pem_encoded_certificate` (str): PEM-encoded X.509 certificate
- `certificate_chain` (list[str], optional): Additional certificates in chain
- `private_key_encrypted` (bytes, optional): Pre-encrypted private key material
- `key_encryption_key_id` (UUID, optional): ID of key used to encrypt private key
- `issuer_dn` (str): Issuer's X.500 Distinguished Name
- `subject_dn` (str): Subject's X.500 Distinguished Name
- `not_before` (datetime): Certificate validity start (UTC)
- `not_after` (datetime): Certificate validity end (UTC)
- `serial_number` (str): Certificate serial number
- `thumbprint_sha256` (str): SHA256 fingerprint (hex, 64 chars)
- `thumbprint_sha1` (str, optional): SHA1 fingerprint (hex, 40 chars)
- `key_algorithm` (str): RSA, ECDSA, Ed25519, etc.
- `key_size` (int, optional): Key size in bits (for RSA)
- `signature_algorithm` (str): Signature algorithm (sha256WithRSAEncryption, etc.)
- `owner_user_id` (UUID): User who owns the certificate
- `organization_id` (UUID, optional): Organization context
- `custom_metadata` (dict, optional): Custom key-value metadata (non-sensitive)

### `CertificateReference`

**Purpose**: Reference to a stored certificate with NO sensitive data.

**Security Guarantees**:
- Contains no private key material
- Contains no encrypted key material
- Safe to log, cache, and distribute
- All data is immutable once returned

**Fields**: Same as above except:
- No `private_key_encrypted`
- No `key_encryption_key_id`
- Added `stored_at` (datetime): When certificate was stored

### `RevokeCertificateRequest`

**Purpose**: Encapsulates revocation request with audit context.

**Fields**:
- `revocation_reason` (str): RFC 5280 reason code
- `revoked_by_user_id` (UUID): Who initiated revocation
- `notes` (str, optional): Additional context

### `CertificateRevocationReference`

**Purpose**: Immutable record of a revocation.

**Fields**:
- `certificate_id` (UUID): Which certificate was revoked
- `common_name` (str): Certificate CN
- `revocation_reason` (str): Reason for revocation
- `revoked_at` (datetime): When revoked (UTC)
- `revoked_by_user_id` (UUID): Who revoked it
- `notes` (str, optional): Additional notes

## Exception Hierarchy

```
SecureStorageException (base)
├── CertificateAlreadyStoredException(certificate_id)
├── CertificateNotFoundException(certificate_id)
├── CertificateAlreadyRevokedException(certificate_id)
├── EncryptionKeyNotFoundException(key_id)
├── InvalidCertificateException(reason)
└── SecureStorageOperationException(operation, reason)
```

**Guidelines for Exception Handling:**

```python
from backend.certificates.interfaces import (
    SecureStorageException,
    CertificateAlreadyStoredException,
    CertificateNotFoundException,
    InvalidCertificateException,
)

try:
    cert_ref = await storage.store_certificate(request)
except CertificateAlreadyStoredException as e:
    # Idempotent: retrieve existing certificate
    cert_ref = await storage.retrieve_certificate_reference(e.certificate_id)
except EncryptionKeyNotFoundException as e:
    # Caller passed invalid encryption key ID
    # Ensure key is created before storing certificate with encrypted key
    raise ValueError(f"Encryption key {e.key_id} does not exist")
except InvalidCertificateException as e:
    # Certificate data is malformed
    # Validate certificate before attempting storage
    raise ValueError(f"Certificate is invalid: {e}")
except SecureStorageException as e:
    # Generic storage error
    logger.error(f"Storage failed: {e}")
    raise
```

## Implementation Guidelines

### When Implementing This Interface

1. **Validate Input Before Storage**
   - Validate PEM certificate format
   - Verify thumbprints match certificate
   - Ensure subject/issuer DNs parse correctly
   - Verify certificate validity period (not_before < not_after)

2. **Encrypt Sensitive Data at Rest**
   - Use AES-256-GCM or equivalent
   - Use authenticated encryption (AEAD)
   - Rotate encryption keys regularly
   - Never log unencrypted private key material

3. **Create Audit Trail**
   - Log store_certificate with: user_id, cert_id, timestamp
   - Log retrieve_certificate_reference with: user_id, cert_id, timestamp
   - Log revoke_certificate_reference with: user_id, cert_id, reason, timestamp
   - Store audit in separate audit_log table

4. **Make Operations Atomic**
   - store_certificate: All-or-nothing (no partial stores)
   - revoke_certificate_reference: All-or-nothing (revocation record created atomically)

5. **Handle Concurrency**
   - Handle race conditions when multiple callers try to store same cert
   - Handle race conditions when revoking already-revoked certificates
   - Use database transactions or optimistic locking

### When Calling This Interface

1. **Pre-Encrypt Private Keys**
   ```python
   # Get encryption key from KMS
   kek = await kms.get_key(kek_id)
   
   # Encrypt private key with KMS
   encrypted_key = await kms.encrypt(private_key_pem, kek)
   
   # Pass encrypted bytes to storage
   request = StoreCertificateRequest(
       ...,
       private_key_encrypted=encrypted_key,
       key_encryption_key_id=kek_id
   )
   ```

2. **Validate Before Storage**
   ```python
   from cryptography import x509
   from cryptography.hazmat.backends import default_backend
   
   # Parse certificate to validate format
   cert = x509.load_pem_x509_certificate(
       pem_cert.encode(),
       default_backend()
   )
   
   # Compute and verify thumbprint
   import hashlib
   computed_thumbprint = hashlib.sha256(
       cert.public_bytes(encoding=serialization.Encoding.DER)
   ).hexdigest()
   
   assert computed_thumbprint == request.thumbprint_sha256
   ```

3. **Check Revocation Separately**
   ```python
   # Retrieve certificate (doesn't check revocation)
   cert_ref = await storage.retrieve_certificate_reference(cert_id)
   
   # Check if revoked (implementation-dependent)
   try:
       # Try a separate query or check a status field
       revocation = await storage.get_revocation_status(cert_id)
       if revocation:
           raise CertificateRevokedException(cert_id)
   except NotImplementedError:
       # Some implementations might not track revocation status here
       # Use CRL or OCSP instead
       pass
   ```

## Integration Example

```python
from typing import Optional
from uuid import UUID
from datetime import datetime
from backend.certificates.interfaces import (
    SecureCertificateStorageInterface,
    StoreCertificateRequest,
    CertificateReference,
)

class CertificateManagementService:
    """Service for managing certificates using secure storage."""
    
    def __init__(
        self,
        storage: SecureCertificateStorageInterface,
        kms_client,  # Key management service
    ):
        self.storage = storage
        self.kms = kms_client
    
    async def import_certificate(
        self,
        certificate_pem: str,
        private_key_pem: Optional[str],
        owner_user_id: UUID,
        kek_id: UUID,
    ) -> CertificateReference:
        """Import a certificate with optional private key."""
        
        # Parse certificate to extract metadata
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import hashlib
        
        cert = x509.load_pem_x509_certificate(
            certificate_pem.encode(),
            default_backend()
        )
        
        # Compute thumbprint
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        thumbprint_sha256 = hashlib.sha256(cert_der).hexdigest()
        
        # Encrypt private key if provided
        encrypted_key = None
        if private_key_pem:
            encrypted_key = await self.kms.encrypt(private_key_pem, kek_id)
        
        # Create storage request
        request = StoreCertificateRequest(
            certificate_id=UUID(int=secrets.randbits(128)),
            common_name=cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value,
            certificate_type="server",
            pem_encoded_certificate=certificate_pem,
            private_key_encrypted=encrypted_key,
            key_encryption_key_id=kek_id if encrypted_key else None,
            issuer_dn=cert.issuer.rfc4514_string(),
            subject_dn=cert.subject.rfc4514_string(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            serial_number=hex(cert.serial_number),
            thumbprint_sha256=thumbprint_sha256,
            key_algorithm=str(cert.public_key().__class__.__name__),
            signature_algorithm=str(cert.signature_algorithm_oid._name),
            owner_user_id=owner_user_id,
        )
        
        # Store securely
        return await self.storage.store_certificate(request)
```

## Security Best Practices

### For Implementers

1. **Encryption**: Use AES-256-GCM with authenticated encryption
2. **Key Management**: Store encryption keys separately from data
3. **Access Control**: Implement fine-grained access control
4. **Audit**: Log all operations with full context
5. **Integrity**: Use message authentication codes (MAC) or signatures
6. **Rotation**: Regularly rotate encryption keys
7. **Isolation**: Store sensitive data in separate, restricted database
8. **Secrets**: Never log or return private key material in any form

### For Callers

1. **Pre-Encrypt**: Always encrypt private keys before passing to storage
2. **Validate**: Validate certificates before storing
3. **Verify**: Verify thumbprints after storage
4. **Audit**: Log who stores and retrieves certificates
5. **Rotation**: Implement certificate rotation policies
6. **Revocation**: Check revocation status before using certificates
7. **Access**: Implement least-privilege access to storage
8. **Monitoring**: Monitor for suspicious access patterns

## Related Documentation

- `backend/certificates/README.md`: Certificate domain models and repository
- `backend/certificates/models.py`: SQLAlchemy models for certificate metadata
- `backend/certificates/schemas.py`: Pydantic schemas
- `backend/common/models.py`: Base model mixins

## Version History

- **v1.0** (2024-01-15): Initial interface design
  - Abstract interface with no implementation
  - Three core methods: store, retrieve, revoke
  - Complete exception hierarchy
  - Comprehensive documentation
