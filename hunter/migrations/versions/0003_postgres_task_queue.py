"""PostgreSQL-backed task queue (replaces RQ/Redis); scan state check; scans.started_at

Expand-only: adds a table, a nullable column and constraints that every previously valid
row already satisfies, so release N (head 0002) keeps working on a schema at 0003.

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False, unique=True),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('scan')", name="ck_tasks_kind"),
        sa.CheckConstraint(
            "state IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_tasks_state"),
        sa.CheckConstraint("attempts >= 0 AND max_attempts >= 1", name="ck_tasks_attempts"),
    )
    op.create_index("ix_tasks_claim", "tasks", ["state", "available_at"])
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("started_at", sa.DateTime(timezone=True)))
        batch.create_check_constraint(
            "ck_scans_state",
            "state IN ('queued', 'running', 'finished', 'partial', 'failed', 'cancelled')")
    # Scans that were active under RQ lost their Redis job: give each a queued task so it
    # is executed (once) by the new workers instead of staying 'running' forever.
    op.execute(
        "UPDATE scans SET state = 'queued' WHERE state = 'running'")
    op.execute(
        "INSERT INTO tasks (kind, scan_id, state, attempts, max_attempts, available_at, "
        "cancel_requested, created_at) "
        "SELECT 'scan', id, 'queued', 0, 3, created_at, false, created_at FROM scans "
        "WHERE state = 'queued'"
        if op.get_bind().dialect.name == "postgresql" else
        "INSERT INTO tasks (kind, scan_id, state, attempts, max_attempts, available_at, "
        "cancel_requested, created_at) "
        "SELECT 'scan', id, 'queued', 0, 3, created_at, 0, created_at FROM scans "
        "WHERE state = 'queued'"
    )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("ck_scans_state", type_="check")
        batch.drop_column("started_at")
    op.drop_index("ix_tasks_claim", table_name="tasks")
    op.drop_table("tasks")
