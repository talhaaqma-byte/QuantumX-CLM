"""Add certificate metadata models

Revision ID: 0003_add_certificate_metadata_models
Revises: 0002_add_rbac_tables
Create Date: 2024-01-15 10:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0003_add_certificate_metadata_models'
down_revision = '0002_add_rbac_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Create certificate_metadata table with proper structure and relationships.
    
    This migration creates the certificate_metadata table that stores non-sensitive
    certificate metadata in the core database. Sensitive certificate data is stored
    in the secure database and referenced via certificate_id.
    """
    
    # Create certificate_metadata table
    op.create_table(
        'certificate_metadata',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False),
        sa.Column('certificate_id', sa.String(length=36), unique=True, nullable=False),
        sa.Column('common_name', sa.String(length=255), nullable=False),
        sa.Column('certificate_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=False),
        sa.Column('owner_user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String(length=100)), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('environment', sa.String(length=50), nullable=True),
        sa.Column('custom_fields', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint("certificate_type IN ('root', 'intermediate', 'leaf', 'client', 'server', 'code_signing', 'email')", name='chk_certificate_metadata_type'),
        sa.CheckConstraint("status IN ('pending', 'active', 'expiring', 'expired', 'revoked', 'suspended')", name='chk_certificate_metadata_status'),
        sa.CheckConstraint("not_before < not_after", name='chk_certificate_metadata_validity_period'),
        sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], name='fk_cert_metadata_owner'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_cert_metadata_org')
    )
    
    # Create indexes for performance
    op.create_index('idx_cert_metadata_cert_id', 'certificate_metadata', ['certificate_id'], unique=False, 
                   postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('idx_cert_metadata_owner', 'certificate_metadata', ['owner_user_id'], unique=False,
                   postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('idx_cert_metadata_org', 'certificate_metadata', ['organization_id'], unique=False,
                   postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('idx_cert_metadata_status', 'certificate_metadata', ['status'], unique=False,
                   postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('idx_cert_metadata_expiry', 'certificate_metadata', ['not_after'], unique=False,
                   postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('idx_cert_metadata_environment', 'certificate_metadata', ['environment'], unique=False,
                   postgresql_where=sa.text('deleted_at IS NULL'))
    
    # Create GIN index for tags array
    op.create_index('idx_cert_metadata_tags', 'certificate_metadata', ['tags'], unique=False, 
                   postgresql_using='gin')
    
    # Create trigger for updated_at
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    op.create_trigger('trg_certificate_metadata_updated_at',
                     table_name='certificate_metadata',
                     func_name='update_updated_at_column')


def downgrade() -> None:
    """
    Drop certificate_metadata table and related objects.
    """
    # Drop trigger and function
    op.execute("DROP TRIGGER IF EXISTS trg_certificate_metadata_updated_at ON certificate_metadata")
    
    # Drop indexes
    op.drop_index('idx_cert_metadata_tags', table_name='certificate_metadata')
    op.drop_index('idx_cert_metadata_environment', table_name='certificate_metadata')
    op.drop_index('idx_cert_metadata_expiry', table_name='certificate_metadata')
    op.drop_index('idx_cert_metadata_status', table_name='certificate_metadata')
    op.drop_index('idx_cert_metadata_org', table_name='certificate_metadata')
    op.drop_index('idx_cert_metadata_owner', table_name='certificate_metadata')
    op.drop_index('idx_cert_metadata_cert_id', table_name='certificate_metadata')
    
    # Drop table
    op.drop_table('certificate_metadata')