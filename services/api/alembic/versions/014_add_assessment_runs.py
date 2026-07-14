"""Add assessment score history.

Revision ID: 014_add_assessment_runs
Revises: 013_add_notification_state
Create Date: 2026-07-14
"""

from alembic import op

revision = "014_add_assessment_runs"
down_revision = "013_add_notification_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS assessment_runs (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL,
            score INTEGER NOT NULL,
            pass_count INTEGER NOT NULL,
            warn_count INTEGER NOT NULL,
            fail_count INTEGER NOT NULL,
            status_hash VARCHAR(64) NOT NULL,
            checks_json TEXT NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_assessment_runs_created_at ON assessment_runs (created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS assessment_runs")
