"""
Certificate repository for data access operations.

This module provides a repository pattern for certificate metadata operations,
isolating database logic from business logic.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID

from sqlalchemy import (
    select, and_, or_, func, text,
    String, DateTime, String
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.certificates.models import (
    CertificateMetadata, CertificateStatus, CertificateType
)
from backend.certificates.schemas import (
    CertificateMetadataCreate, CertificateMetadataUpdate, CertificateMetadataSearch
)


class CertificateRepository:
    """Repository for certificate metadata operations."""
    
    def __init__(self, db: AsyncSession):
        """Initialize repository with database session."""
        self.db = db
    
    async def create(
        self, 
        data: CertificateMetadataCreate,
        created_by_user_id: Optional[UUID] = None
    ) -> CertificateMetadata:
        """Create new certificate metadata."""
        
        # Check if certificate_id already exists
        existing = await self.get_by_certificate_id(data.certificate_id)
        if existing:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=409, 
                detail="Certificate metadata already exists for this certificate_id"
            )
        
        # Create new certificate metadata
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
        
        self.db.add(cert_metadata)
        await self.db.commit()
        await self.db.refresh(cert_metadata)
        
        return cert_metadata
    
    async def get_by_id(self, cert_metadata_id: UUID) -> Optional[CertificateMetadata]:
        """Get certificate metadata by ID."""
        query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.id == cert_metadata_id,
                CertificateMetadata.deleted_at.is_(None)
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def get_by_certificate_id(self, certificate_id: UUID) -> Optional[CertificateMetadata]:
        """Get certificate metadata by certificate_id (secure DB reference)."""
        query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.certificate_id == certificate_id,
                CertificateMetadata.deleted_at.is_(None)
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def update(
        self, 
        cert_metadata_id: UUID, 
        data: CertificateMetadataUpdate
    ) -> Optional[CertificateMetadata]:
        """Update certificate metadata."""
        
        cert_metadata = await self.get_by_id(cert_metadata_id)
        if not cert_metadata:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Certificate metadata not found")
        
        # Update fields
        update_data = data.dict(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(cert_metadata, field):
                # Handle enum conversion
                if field == 'certificate_type' and value:
                    setattr(cert_metadata, field, value.value if hasattr(value, 'value') else value)
                elif field == 'environment' and value:
                    setattr(cert_metadata, field, value.value if hasattr(value, 'value') else value)
                elif field == 'status' and value:
                    setattr(cert_metadata, field, value.value if hasattr(value, 'value') else value)
                else:
                    setattr(cert_metadata, field, value)
        
        await self.db.commit()
        await self.db.refresh(cert_metadata)
        
        return cert_metadata
    
    async def delete(self, cert_metadata_id: UUID, deleted_by_user_id: Optional[UUID] = None) -> bool:
        """Soft delete certificate metadata."""
        
        cert_metadata = await self.get_by_id(cert_metadata_id)
        if not cert_metadata:
            return False
        
        cert_metadata.deleted_at = datetime.utcnow()
        await self.db.commit()
        
        return True
    
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        owner_user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        status: Optional[str] = None,
        certificate_type: Optional[str] = None,
        environment: Optional[str] = None
    ) -> List[CertificateMetadata]:
        """List certificate metadata with filtering."""
        
        query = select(CertificateMetadata).options(
            selectinload(CertificateMetadata.owner),
            selectinload(CertificateMetadata.organization)
        )
        
        # Apply filters
        conditions = [CertificateMetadata.deleted_at.is_(None)]
        
        if owner_user_id:
            conditions.append(CertificateMetadata.owner_user_id == owner_user_id)
        
        if organization_id:
            conditions.append(CertificateMetadata.organization_id == organization_id)
        
        if status:
            conditions.append(CertificateMetadata.status == status)
        
        if certificate_type:
            conditions.append(CertificateMetadata.certificate_type == certificate_type)
        
        if environment:
            conditions.append(CertificateMetadata.environment == environment)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Pagination and ordering
        query = query.order_by(CertificateMetadata.created_at.desc()).offset(skip).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def search(self, search_params: CertificateMetadataSearch) -> Tuple[List[CertificateMetadata], int]:
        """Search certificate metadata with advanced filtering."""
        
        # Build base query with joins for relationships
        query = select(CertificateMetadata).options(
            selectinload(CertificateMetadata.owner),
            selectinload(CertificateMetadata.organization)
        )
        
        # Build conditions
        conditions = [CertificateMetadata.deleted_at.is_(None)]
        
        # Text search
        if search_params.common_name:
            conditions.append(
                func.lower(CertificateMetadata.common_name).contains(
                    search_params.common_name.lower()
                )
            )
        
        # Type filter
        if search_params.certificate_type:
            conditions.append(CertificateMetadata.certificate_type == search_params.certificate_type.value)
        
        # Status filter
        if search_params.status:
            conditions.append(CertificateMetadata.status == search_params.status.value)
        
        # Environment filter
        if search_params.environment:
            conditions.append(CertificateMetadata.environment == search_params.environment.value)
        
        # Ownership filters
        if search_params.owner_user_id:
            conditions.append(CertificateMetadata.owner_user_id == search_params.owner_user_id)
        
        if search_params.organization_id:
            conditions.append(CertificateMetadata.organization_id == search_params.organization_id)
        
        # Date filters
        if search_params.valid_after:
            conditions.append(CertificateMetadata.not_before >= search_params.valid_after)
        
        if search_params.valid_before:
            conditions.append(CertificateMetadata.not_before <= search_params.valid_before)
        
        if search_params.expires_after:
            conditions.append(CertificateMetadata.not_after >= search_params.expires_after)
        
        if search_params.expires_before:
            conditions.append(CertificateMetadata.not_after <= search_params.expires_before)
        
        # Tag filtering
        if search_params.tags:
            conditions.append(
                func.array_cat(CertificateMetadata.tags, []).contains(search_params.tags)
            )
        
        if search_params.has_tags:
            conditions.append(
                func.array_cat(CertificateMetadata.tags, []).overlap(search_params.has_tags)
            )
        
        # Text search across multiple fields
        if search_params.search_text:
            search_text = search_params.search_text.lower()
            text_conditions = [
                func.lower(CertificateMetadata.common_name).contains(search_text),
                func.lower(CertificateMetadata.notes).contains(search_text)
            ]
            
            # Search in custom_fields JSON
            text_conditions.append(
                func.lower(CertificateMetadata.custom_fields.cast(String)).contains(search_text)
            )
            
            conditions.append(or_(*text_conditions))
        
        # Apply all conditions
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(CertificateMetadata.id)).where(and_(*conditions))
        count_result = await self.db.execute(count_query)
        total = count_result.scalar()
        
        # Apply sorting
        sort_field_map = {
            "created_at": CertificateMetadata.created_at,
            "updated_at": CertificateMetadata.updated_at,
            "common_name": CertificateMetadata.common_name,
            "certificate_type": CertificateMetadata.certificate_type,
            "status": CertificateMetadata.status,
            "not_before": CertificateMetadata.not_before,
            "not_after": CertificateMetadata.not_after
        }
        
        sort_field = sort_field_map.get(search_params.sort_by, CertificateMetadata.created_at)
        if search_params.sort_order.lower() == "desc":
            query = query.order_by(sort_field.desc())
        else:
            query = query.order_by(sort_field.asc())
        
        # Apply pagination
        skip = (search_params.page - 1) * search_params.per_page
        query = query.offset(skip).limit(search_params.per_page)
        
        # Execute query
        result = await self.db.execute(query)
        certificates = result.scalars().all()
        
        return certificates, total
    
    async def find_expiring(
        self,
        days_ahead: int = 30,
        status_filter: Optional[List[str]] = None
    ) -> List[CertificateMetadata]:
        """Find certificates expiring within specified days."""
        
        cutoff_date = datetime.utcnow() + timedelta(days=days_ahead)
        
        if not status_filter:
            status_filter = [CertificateStatus.ACTIVE.value, CertificateStatus.EXPIRING.value]
        
        query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.not_after <= cutoff_date,
                CertificateMetadata.not_after > datetime.utcnow(),
                CertificateMetadata.status.in_(status_filter),
                CertificateMetadata.deleted_at.is_(None)
            )
        ).order_by(CertificateMetadata.not_after)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def find_expired(self) -> List[CertificateMetadata]:
        """Find expired certificates."""
        
        query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.not_after <= datetime.utcnow(),
                CertificateMetadata.status != CertificateStatus.EXPIRED.value,
                CertificateMetadata.deleted_at.is_(None)
            )
        ).order_by(CertificateMetadata.not_after)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def update_status_by_expiry(self) -> int:
        """Update certificate statuses based on expiry dates. Returns number of updated certificates."""
        
        now = datetime.utcnow()
        updated_count = 0
        
        # Update expired certificates
        expired_query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.not_after <= now,
                CertificateMetadata.status != CertificateStatus.EXPIRED.value,
                CertificateMetadata.deleted_at.is_(None)
            )
        )
        
        result = await self.db.execute(expired_query)
        expired_certs = result.scalars().all()
        
        for cert in expired_certs:
            cert.status = CertificateStatus.EXPIRED.value
            updated_count += 1
        
        # Update expiring certificates (within 30 days)
        expiring_threshold = now + timedelta(days=30)
        expiring_query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.not_after <= expiring_threshold,
                CertificateMetadata.not_after > now,
                CertificateMetadata.status == CertificateStatus.ACTIVE.value,
                CertificateMetadata.deleted_at.is_(None)
            )
        )
        
        result = await self.db.execute(expiring_query)
        expiring_certs = result.scalars().all()
        
        for cert in expiring_certs:
            cert.status = CertificateStatus.EXPIRING.value
            updated_count += 1
        
        if updated_count > 0:
            await self.db.commit()
        
        return updated_count
    
    async def get_statistics(
        self,
        organization_id: Optional[UUID] = None,
        owner_user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Get certificate statistics."""
        
        # Base query with filters
        base_conditions = [CertificateMetadata.deleted_at.is_(None)]
        
        if organization_id:
            base_conditions.append(CertificateMetadata.organization_id == organization_id)
        
        if owner_user_id:
            base_conditions.append(CertificateMetadata.owner_user_id == owner_user_id)
        
        # Total certificates
        total_query = select(func.count(CertificateMetadata.id)).where(and_(*base_conditions))
        total_result = await self.db.execute(total_query)
        total_certificates = total_result.scalar()
        
        # By type
        type_query = select(
            CertificateMetadata.certificate_type,
            func.count(CertificateMetadata.id)
        ).where(and_(*base_conditions)).group_by(CertificateMetadata.certificate_type)
        
        type_result = await self.db.execute(type_query)
        by_type = dict(type_result.all())
        
        # By status
        status_query = select(
            CertificateMetadata.status,
            func.count(CertificateMetadata.id)
        ).where(and_(*base_conditions)).group_by(CertificateMetadata.status)
        
        status_result = await self.db.execute(status_query)
        by_status = dict(status_result.all())
        
        # By environment
        env_query = select(
            CertificateMetadata.environment,
            func.count(CertificateMetadata.id)
        ).where(and_(*base_conditions)).group_by(CertificateMetadata.environment)
        
        env_result = await self.db.execute(env_query)
        by_environment = dict(env_result.all())
        
        # Expiring soon
        expiring_conditions = base_conditions + [
            CertificateMetadata.not_after <= datetime.utcnow() + timedelta(days=30),
            CertificateMetadata.not_after > datetime.utcnow()
        ]
        
        expiring_query = select(func.count(CertificateMetadata.id)).where(and_(*expiring_conditions))
        expiring_result = await self.db.execute(expiring_query)
        expiring_soon = expiring_result.scalar()
        
        # Expired
        expired_conditions = base_conditions + [
            CertificateMetadata.not_after <= datetime.utcnow()
        ]
        
        expired_query = select(func.count(CertificateMetadata.id)).where(and_(*expired_conditions))
        expired_result = await self.db.execute(expired_query)
        expired = expired_result.scalar()
        
        return {
            "total_certificates": total_certificates,
            "by_type": by_type,
            "by_status": by_status,
            "by_environment": by_environment,
            "expiring_soon": expiring_soon,
            "expired": expired
        }
    
    async def validate_certificate_exists_in_secure_db(self, certificate_id: UUID) -> bool:
        """
        Validate that certificate_id exists in secure database.
        
        This is a placeholder implementation. In a real scenario, this would
        make a cross-database call to the secure database.
        """
        # TODO: Implement cross-database validation
        # For now, always return True to allow development
        return True
    
    async def bulk_update_status(
        self, 
        certificate_ids: List[UUID], 
        new_status: CertificateStatus,
        updated_by_user_id: Optional[UUID] = None
    ) -> int:
        """Bulk update certificate status."""
        
        if not certificate_ids:
            return 0
        
        query = select(CertificateMetadata).where(
            and_(
                CertificateMetadata.certificate_id.in_(certificate_ids),
                CertificateMetadata.deleted_at.is_(None)
            )
        )
        
        result = await self.db.execute(query)
        certificates = result.scalars().all()
        
        updated_count = 0
        for cert in certificates:
            cert.status = new_status.value
            updated_count += 1
        
        if updated_count > 0:
            await self.db.commit()
        
        return updated_count