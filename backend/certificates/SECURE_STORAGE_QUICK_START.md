# Secure Certificate Storage - Quick Start Guide

## 5-Minute Overview

The `SecureCertificateStorageInterface` in `backend/certificates/interfaces.py` defines how to securely store and manage certificates with these key principles:

1. **No Private Key Exposure**: Private keys are never returned or logged
2. **Pre-Encrypted Input**: Callers must encrypt private keys BEFORE storage
3. **Reference-Based API**: Methods return references containing only non-sensitive data
4. **Immutable Revocation**: Once revoked, certificates cannot be unrevoked

## Three Core Methods

### 1. Store a Certificate

```python
from backend.certificates.interfaces import StoreCertificateRequest

cert_ref = await storage.store_certificate(
    StoreCertificateRequest(
        certificate_id=uuid4(),
        common_name="api.example.com",
        certificate_type="server",
        pem_encoded_certificate=cert_pem,           # Public cert only
        private_key_encrypted=encrypted_key_bytes,  # Pre-encrypted by caller!
        key_encryption_key_id=kek_id,
        issuer_dn="CN=Let's Encrypt Authority X3",
        subject_dn="CN=api.example.com",
        not_before=cert.not_valid_before,
        not_after=cert.not_valid_after,
        serial_number="12345",
        thumbprint_sha256="abc123...",  # SHA256 hex, 64 chars
        key_algorithm="RSA",
        key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        owner_user_id=user_id,
    )
)

# Returns CertificateReference - no private key data!
print(cert_ref.thumbprint_sha256)  # Safe to log
```

### 2. Retrieve a Certificate Reference

```python
cert_ref = await storage.retrieve_certificate_reference(certificate_id)

# Safe for logging and sending to clients
print(f"{cert_ref.common_name} valid until {cert_ref.not_after}")
print(f"Fingerprint: {cert_ref.thumbprint_sha256}")
```

### 3. Revoke a Certificate

```python
from backend.certificates.interfaces import RevokeCertificateRequest

revocation = await storage.revoke_certificate_reference(
    certificate_id,
    RevokeCertificateRequest(
        revocation_reason="keyCompromise",
        revoked_by_user_id=admin_user_id,
        notes="Key found in GitHub commit"
    )
)

# Revocation is permanent and immutable
# Further attempts to revoke raise CertificateAlreadyRevokedException
```

## Common Patterns

### Pattern 1: Encrypt Private Key Before Storing

```python
# ❌ WRONG: Passing plaintext private key
request = StoreCertificateRequest(
    ...,
    private_key_encrypted=private_key_pem.encode(),  # ❌ NOT encrypted!
)

# ✅ CORRECT: Encrypt with KMS first
encrypted_key = await kms.encrypt(private_key_pem, kek_id)
request = StoreCertificateRequest(
    ...,
    private_key_encrypted=encrypted_key,  # ✅ Pre-encrypted
    key_encryption_key_id=kek_id,
)
```

### Pattern 2: Idempotent Storage

```python
try:
    cert_ref = await storage.store_certificate(request)
except CertificateAlreadyStoredException as e:
    # Certificate already exists - retrieve it instead
    cert_ref = await storage.retrieve_certificate_reference(e.certificate_id)
```

### Pattern 3: Safe Logging

```python
# All safe to log - no secrets exposed
cert_ref = await storage.retrieve_certificate_reference(cert_id)
logger.info(f"Certificate stored: {cert_ref.common_name}")
logger.info(f"Thumbprint: {cert_ref.thumbprint_sha256}")
logger.info(f"Owner: {cert_ref.owner_user_id}")

# ✅ Can send to clients
return {
    "id": str(cert_ref.certificate_id),
    "common_name": cert_ref.common_name,
    "thumbprint": cert_ref.thumbprint_sha256,
}
```

## Data Models Quick Reference

### Input: `StoreCertificateRequest`
- `certificate_id` - UUID
- `common_name` - str
- `certificate_type` - root|intermediate|leaf|client|server|code_signing|email
- `pem_encoded_certificate` - str (public cert)
- `private_key_encrypted` - bytes (OPTIONAL, pre-encrypted)
- `key_encryption_key_id` - UUID (OPTIONAL)
- `issuer_dn` - str
- `subject_dn` - str
- `not_before` - datetime
- `not_after` - datetime
- `serial_number` - str
- `thumbprint_sha256` - str (64 hex chars)
- `thumbprint_sha1` - str (40 hex chars, optional)
- `key_algorithm` - str (RSA|ECDSA|Ed25519)
- `key_size` - int (optional, bits)
- `signature_algorithm` - str
- `owner_user_id` - UUID
- `organization_id` - UUID (optional)
- `custom_metadata` - dict (optional, non-sensitive)

### Output: `CertificateReference`
- Same fields as above, MINUS:
  - ❌ `private_key_encrypted`
  - ❌ `key_encryption_key_id`
- PLUS:
  - ✅ `stored_at` - datetime

### Revocation Input: `RevokeCertificateRequest`
- `revocation_reason` - str (RFC 5280)
  - unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise
- `revoked_by_user_id` - UUID
- `notes` - str (optional)

### Revocation Output: `CertificateRevocationReference`
- `certificate_id` - UUID
- `common_name` - str
- `revocation_reason` - str
- `revoked_at` - datetime
- `revoked_by_user_id` - UUID
- `notes` - str (optional)

## Exception Handling

```python
from backend.certificates.interfaces import (
    CertificateAlreadyStoredException,
    CertificateNotFoundException,
    CertificateAlreadyRevokedException,
    EncryptionKeyNotFoundException,
    InvalidCertificateException,
    SecureStorageOperationException,
)

try:
    cert_ref = await storage.store_certificate(request)
except CertificateAlreadyStoredException as e:
    # Certificate already stored - retrieve instead
    cert_ref = await storage.retrieve_certificate_reference(e.certificate_id)
except EncryptionKeyNotFoundException as e:
    # Invalid KEK ID - ensure key exists first
    raise ValueError(f"Key {e.key_id} not found in KMS")
except InvalidCertificateException as e:
    # Certificate data malformed - validate input
    raise ValueError(f"Invalid certificate: {e}")
except SecureStorageOperationException as e:
    # Generic storage error - log and retry
    logger.error(f"Storage failed: {e}")
    raise
```

## Common Revocation Reasons

| Reason | When to Use |
|--------|------------|
| `keyCompromise` | Private key was exposed/compromised |
| `cACompromise` | CA private key was compromised |
| `superseded` | Certificate replaced by new one |
| `cessationOfOperation` | Organization stopped operations |
| `affiliationChanged` | Organization affiliation changed |
| `unspecified` | No specific reason |

## Validation Checklist

Before calling `store_certificate()`:

- [ ] Certificate is valid PEM format
- [ ] Certificate parses without errors
- [ ] not_before < not_after
- [ ] Thumbprint matches certificate
- [ ] owner_user_id is valid UUID
- [ ] If private_key_encrypted provided:
  - [ ] It's actually encrypted (not plaintext)
  - [ ] key_encryption_key_id is valid
  - [ ] Encryption key exists in KMS

## File Location

**Interface Definition**: `backend/certificates/interfaces.py`
**Full Documentation**: `backend/certificates/SECURE_STORAGE_INTERFACE.md`

## Next Steps

1. Implement the interface in `backend/certificates/services/secure_storage.py`
2. Use dependency injection to provide the implementation
3. Create tests in `backend/tests/certificates/test_secure_storage.py`
4. Integrate with KMS for key management
5. Set up audit logging for all operations

## Related Files

- `backend/certificates/models.py` - Certificate metadata models
- `backend/certificates/schemas.py` - Pydantic schemas
- `backend/certificates/repository.py` - Metadata repository
- `backend/common/models.py` - Base model mixins
