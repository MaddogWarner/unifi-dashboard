"""Add notification delivery state.

Revision ID: 013_add_notification_state
Revises: 012_add_threat_feed_source_type
Create Date: 2026-07-14
"""

from alembic import op

revision = "013_add_notification_state"
down_revision = "012_add_threat_feed_source_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS notification_state (
            fingerprint VARCHAR(64) PRIMARY KEY,
            severity VARCHAR(16) NOT NULL,
            title VARCHAR(256) NOT NULL,
            first_seen TIMESTAMPTZ NOT NULL,
            last_notified_at TIMESTAMPTZ NULL,
            active BOOLEAN NOT NULL
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS notification_state")
