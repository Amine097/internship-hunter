"""at most one queued/running scan per profile

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_ACTIVE = sa.text("state IN ('queued', 'running')")


def upgrade() -> None:
    # Pre-existing duplicates would violate the new index: close all but the newest.
    op.execute(
        "UPDATE scans SET state = 'failed', error = 'superseded by migration 0002' "
        "WHERE state IN ('queued', 'running') AND id NOT IN ("
        "SELECT MAX(id) FROM scans WHERE state IN ('queued', 'running') GROUP BY profile_id)"
    )
    op.create_index(
        "uq_scans_one_active_per_profile", "scans", ["profile_id"], unique=True,
        postgresql_where=_ACTIVE, sqlite_where=_ACTIVE,
    )


def downgrade() -> None:
    op.drop_index("uq_scans_one_active_per_profile", table_name="scans")
