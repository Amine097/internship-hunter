"""resource sessions: approval requests, controller commands, notification outbox

Expand-only (three new tables, nothing altered): release N (head 0003) keeps working on a
schema at 0004.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "resource_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("trigger", sa.String(12), nullable=False),
        sa.Column("slot_key", sa.String(32), unique=True),
        sa.Column("profile_ids", sa.JSON()),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("nonce", sa.String(32), nullable=False),
        sa.Column("lock_key", sa.String(8), unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("prompt_sent_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("deadline", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("restore_requested", sa.Boolean(), nullable=False),
        sa.Column("restore_attempts", sa.Integer(), nullable=False),
        sa.Column("scan_ids", sa.JSON(), nullable=False),
        sa.Column("broker", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.CheckConstraint(
            "state IN ('pending', 'declined', 'expired', 'accepted', 'reserving', 'running', "
            "'restoring', 'restore_failed', 'completed', 'failed', 'blocked')",
            name="ck_resource_sessions_state"),
        sa.CheckConstraint("trigger IN ('scheduled', 'manual', 'api')",
                           name="ck_resource_sessions_trigger"),
    )
    op.create_table(
        "rsm_commands",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("command", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("handled_at", sa.DateTime(timezone=True)),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.CheckConstraint("command IN ('emergency_restore')", name="ck_rsm_commands_command"),
    )
    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("session_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("kind IN ('info', 'alert')", name="ck_notifications_kind"),
    )


def downgrade() -> None:
    for t in ("notifications", "rsm_commands", "resource_sessions"):
        op.drop_table(t)
