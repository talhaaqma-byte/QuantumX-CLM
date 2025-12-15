"""Baseline for clm_secure_db.

This revision intentionally contains no DDL. The initial schema is currently
defined in `migrations/clm_secure_db/001_init_secure_schema.sql`.

Use this environment for future incremental schema changes.
"""

from __future__ import annotations

# revision identifiers, used by Alembic.
revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
