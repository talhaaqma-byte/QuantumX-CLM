"""
Certificate Pydantic schemas for request/response models.

This module contains Pydantic schemas for certificate metadata operations.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class CertificateType(str, Enum):
    """Certificate type classification."""
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CLIENT = "client"
    SERVER = "server"
    CODE_SIGNING = "code_signing"
    EMAIL = "email"


class CertificateStatus(str, Enum):
    """Certificate status lifecycle values."""
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class EnvironmentType(str, Enum):
    """Deployment environment classification."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"


class CertificateMetadataBase(BaseModel):
    """Base certificate metadata schema with common fields."""

    certificate_id: UUID = Field(..., description="UUID referencing certificate in secure database")
    common_name: str = Field(..., max_length=255, description="Certificate common name (CN)")
    certificate_type: CertificateType = Field(..., description="Type of certificate")
    not_before: datetime = Field(..., description="Certificate validity start time")
    not_after: datetime = Field(..., description="Certificate validity end time")
    owner_user_id: UUID = Field(..., description="User ID of certificate owner")
    organization_id: Optional[UUID] = Field(None, description="Organization ID (optional)")

    # Categorization and tagging
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")
    category: Optional[str] = Field(None, max_length=100, description="Certificate category")
    environment: Optional[EnvironmentType] = Field(None, description="Deployment environment")

    # Custom metadata
    custom_fields: Optional[Dict[str, Any]] = Field(None, description="Custom metadata as key-value pairs")
    notes: Optional[str] = Field(None, description="Free-form notes about the certificate")

    @field_validator('certificate_type')
    @classmethod
    def validate_certificate_type(cls, v: str) -> str:
        """Validate certificate type."""
        valid_types = {'root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email'}
        if v not in valid_types:
            raise ValueError(f'Certificate type must be one of: {", ".join(valid_types)}')
        return v

    @field_validator('common_name')
    @classmethod
    def validate_common_name(cls, v: str) -> str:
        """Validate common name."""
        if not v or not v.strip():
            raise ValueError('Common name cannot be empty')
        return v.strip()

    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate and normalize tags."""
        if v is not None:
            # Remove duplicates while preserving order
            seen = set()
            unique_tags = []
            for tag in v:
                if tag and tag.strip() and tag not in seen:
                    seen.add(tag)
                    unique_tags.append(tag.strip())
            return unique_tags
        return v

    @field_validator('not_after')
    @classmethod
    def validate_not_after(cls, v: datetime, info):
        """Validate that not_after is after not_before."""
        not_before = info.data.get('not_before')
        if not_before and v <= not_before:
            raise ValueError('not_after must be after not_before')
        return v


class CertificateMetadataCreate(CertificateMetadataBase):
    """Schema for creating certificate metadata."""

    status: CertificateStatus = Field(default=CertificateStatus.PENDING, description="Initial certificate status")


class CertificateMetadataUpdate(BaseModel):
    """Schema for updating certificate metadata."""

    common_name: Optional[str] = Field(None, max_length=255, description="Certificate common name (CN)")
    certificate_type: Optional[CertificateType] = Field(None, description="Type of certificate")
    status: Optional[CertificateStatus] = Field(None, description="Current status of the certificate")
    not_before: Optional[datetime] = Field(None, description="Certificate validity start time")
    not_after: Optional[datetime] = Field(None, description="Certificate validity end time")
    owner_user_id: Optional[UUID] = Field(None, description="User ID of certificate owner")
    organization_id: Optional[UUID] = Field(None, description="Organization ID (optional)")

    # Categorization and tagging
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")
    category: Optional[str] = Field(None, max_length=100, description="Certificate category")
    environment: Optional[EnvironmentType] = Field(None, description="Deployment environment")

    # Custom metadata
    custom_fields: Optional[Dict[str, Any]] = Field(None, description="Custom metadata as key-value pairs")
    notes: Optional[str] = Field(None, description="Free-form notes about the certificate")

    @field_validator('certificate_type')
    @classmethod
    def validate_certificate_type(cls, v: Optional[str]) -> Optional[str]:
        """Validate certificate type."""
        if v is not None:
            valid_types = {'root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email'}
            if v not in valid_types:
                raise ValueError(f'Certificate type must be one of: {", ".join(valid_types)}')
        return v

    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate and normalize tags."""
        if v is not None:
            # Remove duplicates while preserving order
            seen = set()
            unique_tags = []
            for tag in v:
                if tag and tag.strip() and tag not in seen:
                    seen.add(tag)
                    unique_tags.append(tag.strip())
            return unique_tags
        return v


class CertificateMetadataResponse(BaseModel):
    """Schema for certificate metadata response."""

    id: UUID
    certificate_id: UUID
    common_name: str
    certificate_type: str
    status: str
    not_before: datetime
    not_after: datetime
    owner_user_id: UUID
    organization_id: Optional[UUID] = None

    # Categorization and tagging
    tags: Optional[List[str]] = None
    category: Optional[str] = None
    environment: Optional[str] = None

    # Custom metadata
    custom_fields: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None

    # Timestamps
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None

    # Computed fields
    days_until_expiry: Optional[int] = Field(None, description="Days until certificate expires")
    is_expired: Optional[bool] = Field(None, description="Whether certificate is expired")
    is_expiring_soon: Optional[bool] = Field(None, description="Whether certificate expires within 30 days")

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm(cls, certificate_metadata) -> "CertificateMetadataResponse":
        """Create response schema from ORM model."""
        data = certificate_metadata.to_dict()
        
        # Add computed fields
        data["is_expired"] = certificate_metadata.is_expired()
        data["is_expiring_soon"] = certificate_metadata.is_expiring_soon()
        data["days_until_expiry"] = certificate_metadata.get_remaining_days()

        return cls(**data)


class CertificateMetadataList(BaseModel):
    """Schema for certificate metadata list response."""

    certificates: List[CertificateMetadataResponse]
    total: int
    page: int = 1
    per_page: int = 50
    has_next: bool = False
    has_prev: bool = False


class CertificateMetadataSummary(BaseModel):
    """Schema for certificate summary information."""

    total_certificates: int = Field(..., description="Total number of certificates")
    by_type: Dict[str, int] = Field(..., description="Count of certificates by type")
    by_status: Dict[str, int] = Field(..., description="Count of certificates by status")
    by_environment: Dict[str, int] = Field(..., description="Count of certificates by environment")
    expiring_soon: int = Field(..., description="Number of certificates expiring within 30 days")
    expired: int = Field(..., description="Number of expired certificates")


class CertificateMetadataSearch(BaseModel):
    """Schema for certificate search parameters."""

    # Search terms
    common_name: Optional[str] = Field(None, description="Search by common name (case-insensitive)")
    certificate_type: Optional[CertificateType] = Field(None, description="Filter by certificate type")
    status: Optional[CertificateStatus] = Field(None, description="Filter by status")
    environment: Optional[EnvironmentType] = Field(None, description="Filter by environment")
    
    # Ownership filters
    owner_user_id: Optional[UUID] = Field(None, description="Filter by owner user ID")
    organization_id: Optional[UUID] = Field(None, description="Filter by organization ID")
    
    # Date filters
    valid_after: Optional[datetime] = Field(None, description="Filter certificates valid after this date")
    valid_before: Optional[datetime] = Field(None, description="Filter certificates valid before this date")
    expires_after: Optional[datetime] = Field(None, description="Filter certificates expiring after this date")
    expires_before: Optional[datetime] = Field(None, description="Filter certificates expiring before this date")
    
    # Tag filtering
    tags: Optional[List[str]] = Field(None, description="Filter by tags (AND match)")
    has_tags: Optional[List[str]] = Field(None, description="Filter certificates that have any of these tags")
    
    # Text search
    search_text: Optional[str] = Field(None, description="Full-text search across common_name, notes, and custom_fields")
    
    # Pagination
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(50, ge=1, le=100, description="Items per page")
    
    # Sorting
    sort_by: Optional[str] = Field("created_at", description="Sort field")
    sort_order: Optional[str] = Field("desc", pattern="^(asc|desc)$", description="Sort order")