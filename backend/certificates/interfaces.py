"""
Secure certificate storage interface.

This module defines abstract interfaces for secure certificate storage operations.
These interfaces establish a contract for implementations that handle sensitive
certificate data (private keys, certificates) with strict security constraints.

No private key data is exposed through these interfaces. All operations return
references or metadata only, never actual sensitive cryptographic material.

Key Design Principles:
    - Private keys are never returned or exposed
    - Implementations must ensure encryption at rest
    - All operations are asynchronous
    - Interfaces are storage-backend agnostic
    - No direct database access in interface definition
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# =====================================================================
# Data Models
# =====================================================================


class StoreCertificateRequest(BaseModel):
    """Request model for storing a certificate securely."""

    certificate_id: UUID = Field(
        ...,
        description="Unique identifier for this certificate (UUID v4)",
    )
    common_name: str = Field(
        ...,
        max_length=255,
        description="Certificate common name (CN)",
    )
    certificate_type: str = Field(
        ...,
        description="Certificate type: root, intermediate, leaf, client, server, code_signing, email",
    )
    pem_encoded_certificate: str = Field(
        ...,
        description="PEM-encoded X.509 certificate (public key only, no private key)",
    )
    certificate_chain: Optional[list[str]] = Field(
        None,
        description="Array of PEM-encoded certificates in the chain (optional)",
    )
    private_key_encrypted: Optional[bytes] = Field(
        None,
        description="Encrypted private key material (only if managing keys). MUST be pre-encrypted by caller.",
    )
    key_encryption_key_id: Optional[UUID] = Field(
        None,
        description="Reference to the encryption key used to encrypt the private key",
    )
    issuer_dn: str = Field(
        ...,
        description="X.500 Distinguished Name of the issuer",
    )
    subject_dn: str = Field(
        ...,
        description="X.500 Distinguished Name of the subject",
    )
    not_before: datetime = Field(
        ...,
        description="Certificate validity start time (UTC)",
    )
    not_after: datetime = Field(
        ...,
        description="Certificate validity end time (UTC)",
    )
    serial_number: str = Field(
        ...,
        description="Certificate serial number (hex or decimal)",
    )
    thumbprint_sha256: str = Field(
        ...,
        max_length=64,
        description="SHA256 thumbprint/fingerprint of the certificate",
    )
    thumbprint_sha1: Optional[str] = Field(
        None,
        max_length=40,
        description="SHA1 thumbprint/fingerprint of the certificate (optional, for legacy)",
    )
    key_algorithm: str = Field(
        ...,
        description="Key algorithm: RSA, ECDSA, Ed25519, etc.",
    )
    key_size: Optional[int] = Field(
        None,
        description="Key size in bits (e.g., 2048 for RSA, or None for ECDSA curves)",
    )
    signature_algorithm: str = Field(
        ...,
        description="Signature algorithm: sha256WithRSAEncryption, ecdsa-with-SHA256, etc.",
    )
    owner_user_id: UUID = Field(
        ...,
        description="UUID of the user owning this certificate",
    )
    organization_id: Optional[UUID] = Field(
        None,
        description="UUID of the organization (optional)",
    )
    custom_metadata: Optional[dict] = Field(
        None,
        description="Custom metadata as key-value pairs (e.g., issuer, key_usage, etc.)",
    )

    model_config = {"frozen": True}


class CertificateReference(BaseModel):
    """Reference to a stored certificate (no sensitive data exposed)."""

    certificate_id: UUID = Field(
        ...,
        description="Unique identifier of the certificate",
    )
    common_name: str = Field(
        ...,
        description="Certificate common name (CN)",
    )
    certificate_type: str = Field(
        ...,
        description="Certificate type",
    )
    issuer_dn: str = Field(
        ...,
        description="Certificate issuer DN",
    )
    subject_dn: str = Field(
        ...,
        description="Certificate subject DN",
    )
    not_before: datetime = Field(
        ...,
        description="Validity start time",
    )
    not_after: datetime = Field(
        ...,
        description="Validity end time",
    )
    serial_number: str = Field(
        ...,
        description="Certificate serial number",
    )
    thumbprint_sha256: str = Field(
        ...,
        description="SHA256 fingerprint",
    )
    key_algorithm: str = Field(
        ...,
        description="Key algorithm type",
    )
    key_size: Optional[int] = Field(
        None,
        description="Key size in bits",
    )
    signature_algorithm: str = Field(
        ...,
        description="Signature algorithm",
    )
    owner_user_id: UUID = Field(
        ...,
        description="Certificate owner user ID",
    )
    organization_id: Optional[UUID] = Field(
        None,
        description="Organization ID",
    )
    stored_at: datetime = Field(
        ...,
        description="Timestamp when certificate was stored",
    )
    custom_metadata: Optional[dict] = Field(
        None,
        description="Custom metadata (no sensitive data)",
    )

    model_config = {"from_attributes": True}


class RevokeCertificateRequest(BaseModel):
    """Request model for revoking a certificate reference."""

    revocation_reason: str = Field(
        ...,
        max_length=100,
        description="Reason for revocation: unspecified, keyCompromise, cACompromise, affiliationChanged, "
        "superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise",
    )
    revoked_by_user_id: UUID = Field(
        ...,
        description="UUID of the user revoking the certificate",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes about the revocation",
    )

    model_config = {"frozen": True}


class CertificateRevocationReference(BaseModel):
    """Reference to a revoked certificate."""

    certificate_id: UUID = Field(
        ...,
        description="ID of the revoked certificate",
    )
    common_name: str = Field(
        ...,
        description="Common name of the revoked certificate",
    )
    revocation_reason: str = Field(
        ...,
        description="Reason for revocation",
    )
    revoked_at: datetime = Field(
        ...,
        description="Timestamp when certificate was revoked",
    )
    revoked_by_user_id: UUID = Field(
        ...,
        description="User ID who revoked the certificate",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes about revocation",
    )

    model_config = {"from_attributes": True}


# =====================================================================
# Exception Classes
# =====================================================================


class SecureStorageException(Exception):
    """Base exception for secure certificate storage operations."""

    pass


class CertificateAlreadyStoredException(SecureStorageException):
    """Raised when attempting to store a certificate that already exists."""

    def __init__(self, certificate_id: UUID):
        self.certificate_id = certificate_id
        super().__init__(f"Certificate {certificate_id} is already stored")


class CertificateNotFoundException(SecureStorageException):
    """Raised when a certificate cannot be found in storage."""

    def __init__(self, certificate_id: UUID):
        self.certificate_id = certificate_id
        super().__init__(f"Certificate {certificate_id} not found in secure storage")


class CertificateAlreadyRevokedException(SecureStorageException):
    """Raised when attempting to revoke an already-revoked certificate."""

    def __init__(self, certificate_id: UUID):
        self.certificate_id = certificate_id
        super().__init__(f"Certificate {certificate_id} is already revoked")


class EncryptionKeyNotFoundException(SecureStorageException):
    """Raised when an encryption key referenced by certificate is not found."""

    def __init__(self, key_id: UUID):
        self.key_id = key_id
        super().__init__(f"Encryption key {key_id} not found")


class InvalidCertificateException(SecureStorageException):
    """Raised when certificate data is invalid or malformed."""

    def __init__(self, reason: str):
        super().__init__(f"Invalid certificate: {reason}")


class SecureStorageOperationException(SecureStorageException):
    """Raised when a secure storage operation fails (generic error)."""

    def __init__(self, operation: str, reason: str):
        super().__init__(f"Secure storage operation '{operation}' failed: {reason}")


# =====================================================================
# Abstract Interface
# =====================================================================


class SecureCertificateStorageInterface(ABC):
    """
    Abstract interface for secure certificate storage.

    This interface establishes a contract for implementations that securely store
    and manage certificates and their associated cryptographic material. 
    Implementations must ensure:

    1. **No Private Key Exposure**: Private keys are never returned, logged, or
       exposed through any method. They remain encrypted and isolated.

    2. **Encryption at Rest**: All sensitive data must be encrypted using strong
       encryption algorithms (AES-256-GCM or equivalent).

    3. **Access Control**: All operations must be audited and access-controlled.
       Sensitive operations should be logged with context (user, timestamp, etc.).

    4. **Data Integrity**: All stored data must be protected against tampering.
       Use authenticated encryption (AEAD) or message authentication codes.

    5. **Asynchronous Operations**: All methods are asynchronous to prevent
       blocking I/O and support concurrent secure operations.

    6. **Backend Agnostic**: Implementations can use different storage backends
       (database, HSM, cloud KMS, etc.) without changing the interface.

    Security Guarantees:
        - Private keys are encrypted immediately upon receipt
        - Private keys are only decrypted when explicitly needed by cryptographic operations
        - All operations that touch cryptographic material are logged for audit
        - Revoked certificates are immutably marked and cannot be unrevoked
        - Certificate thumbprints enable integrity verification

    Example Usage:
        storage = SecureCertificateStorage()
        
        # Store a certificate
        cert_ref = await storage.store_certificate(
            StoreCertificateRequest(
                certificate_id=uuid4(),
                common_name="example.com",
                certificate_type="server",
                pem_encoded_certificate="-----BEGIN CERTIFICATE-----...",
                private_key_encrypted=encrypted_key_bytes,  # Pre-encrypted by caller
                key_encryption_key_id=kek_uuid,
                issuer_dn="CN=Let's Encrypt Authority X3",
                subject_dn="CN=example.com",
                ...
            )
        )
        
        # Retrieve certificate reference (no sensitive data)
        ref = await storage.retrieve_certificate_reference(cert_ref.certificate_id)
        print(ref.thumbprint_sha256)  # Safe to log
        
        # Revoke a certificate
        revoked = await storage.revoke_certificate_reference(
            cert_ref.certificate_id,
            RevokeCertificateRequest(
                revocation_reason="keyCompromise",
                revoked_by_user_id=admin_id
            )
        )
    """

    @abstractmethod
    async def store_certificate(
        self, request: StoreCertificateRequest
    ) -> CertificateReference:
        """
        Store a certificate securely in storage.

        This method persists a certificate and optionally its encrypted private key.
        The private key (if provided) must be pre-encrypted by the caller using
        the specified encryption key. This method does NOT handle encryption -
        it only persists already-encrypted data.

        Private keys are never exposed through this interface or any return value.

        Args:
            request: Certificate storage request with certificate data

        Returns:
            CertificateReference: Reference to the stored certificate (no sensitive data)

        Raises:
            CertificateAlreadyStoredException: Certificate with this ID already exists
            EncryptionKeyNotFoundException: Referenced encryption key not found
            InvalidCertificateException: Certificate data is invalid or malformed
            SecureStorageOperationException: Storage operation failed

        Security Notes:
            - Private key (if provided) must be encrypted before calling this method
            - Method logs the operation with context (user, timestamp)
            - Certificate data is validated for integrity
            - Thumbprint is computed and verified
            - Operation is atomic - either fully succeeds or fully fails
            - Audit entry is created (references user_id, timestamp, certificate_id)

        Example:
            request = StoreCertificateRequest(
                certificate_id=uuid4(),
                common_name="app.example.com",
                certificate_type="server",
                pem_encoded_certificate=pem_cert,
                private_key_encrypted=encrypted_key,  # Pre-encrypted
                key_encryption_key_id=kek_id,
                issuer_dn="CN=Let's Encrypt",
                subject_dn="CN=app.example.com",
                not_before=datetime(2024, 1, 1),
                not_after=datetime(2025, 1, 1),
                serial_number="12345",
                thumbprint_sha256="abc123...",
                key_algorithm="RSA",
                key_size=2048,
                signature_algorithm="sha256WithRSAEncryption",
                owner_user_id=user_id,
                organization_id=org_id
            )
            
            cert_ref = await storage.store_certificate(request)
            # cert_ref.certificate_id == request.certificate_id
            # No private key data in cert_ref
        """
        ...

    @abstractmethod
    async def retrieve_certificate_reference(
        self, certificate_id: UUID
    ) -> CertificateReference:
        """
        Retrieve a reference to a stored certificate.

        Returns a CertificateReference containing non-sensitive certificate metadata.
        Private keys are never returned or exposed by this method.

        This method is safe for logging, caching, and passing to untrusted code.

        Args:
            certificate_id: UUID of the certificate to retrieve

        Returns:
            CertificateReference: Reference to the certificate (no sensitive data)

        Raises:
            CertificateNotFoundException: Certificate not found
            SecureStorageOperationException: Retrieval operation failed

        Security Notes:
            - Returned data contains no cryptographic secrets
            - Safe to log the returned reference
            - Safe to cache in distributed systems
            - Operation is read-only and auditable

        Example:
            ref = await storage.retrieve_certificate_reference(certificate_id)
            print(f"Certificate: {ref.common_name}")
            print(f"Valid until: {ref.not_after}")
            print(f"Fingerprint: {ref.thumbprint_sha256}")  # Safe to log
            # ref.private_key is not present - method never exposes keys
        """
        ...

    @abstractmethod
    async def revoke_certificate_reference(
        self,
        certificate_id: UUID,
        request: RevokeCertificateRequest,
    ) -> CertificateRevocationReference:
        """
        Revoke a certificate reference.

        Marks a certificate as revoked with an immutable revocation record.
        Revoked certificates cannot be unrevoked. This operation is permanent.

        The revocation reason should follow RFC 5280 revocation reason codes.

        Args:
            certificate_id: UUID of the certificate to revoke
            request: Revocation request with reason and audit context

        Returns:
            CertificateRevocationReference: Immutable record of revocation

        Raises:
            CertificateNotFoundException: Certificate not found
            CertificateAlreadyRevokedException: Certificate is already revoked
            SecureStorageOperationException: Revocation operation failed

        Security Notes:
            - Revocation is immutable and permanent
            - Operation creates audit trail (who, when, why)
            - Revocation reason is logged for compliance
            - Private key (if stored) remains encrypted even after revocation
            - All revocations are audited with user_id and timestamp

        Valid Revocation Reasons (RFC 5280):
            - unspecified
            - keyCompromise (key was compromised)
            - cACompromise (CA private key was compromised)
            - affiliationChanged (certificate holder's affiliation changed)
            - superseded (replaced by new certificate)
            - cessationOfOperation (cert holder ceased operation)
            - certificateHold (temporary hold, may be lifted)
            - removeFromCRL (remove from CRL)
            - privilegeWithdrawn (privileges or authority withdrawn)
            - aACompromise (AA private key was compromised)

        Example:
            revocation = await storage.revoke_certificate_reference(
                certificate_id,
                RevokeCertificateRequest(
                    revocation_reason="keyCompromise",
                    revoked_by_user_id=security_admin_id,
                    notes="Key material was exposed in log files"
                )
            )
            
            # Immutable revocation record created
            assert revocation.revoked_at is not None
            
            # Attempting to revoke again raises error
            # await storage.revoke_certificate_reference(...)  # Raises CertificateAlreadyRevokedException
            
            # Certificate still exists but is marked revoked
            # ref = await storage.retrieve_certificate_reference(certificate_id)
            # Applications must check revocation status separately
        """
        ...
