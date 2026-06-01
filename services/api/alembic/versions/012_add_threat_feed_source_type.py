"""Add source_type, api_key, misp_verify_ssl to threat_feed_sources.

Revision ID: 012_add_threat_feed_source_type
Revises: 011_add_user_theme
Create Date: 2026-06-01
"""

from alembic import op


revision = "012_add_threat_feed_source_type"
down_revision = "011_add_user_theme"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE threat_feed_sources "
        "ADD COLUMN IF NOT EXISTS source_type VARCHAR(16) NOT NULL DEFAULT 'url'"
    )
    op.execute("ALTER TABLE threat_feed_sources ADD COLUMN IF NOT EXISTS api_key TEXT")
    op.execute(
        "ALTER TABLE threat_feed_sources "
        "ADD COLUMN IF NOT EXISTS misp_verify_ssl BOOLEAN NOT NULL DEFAULT false"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE threat_feed_sources DROP COLUMN IF EXISTS misp_verify_ssl")
    op.execute("ALTER TABLE threat_feed_sources DROP COLUMN IF EXISTS api_key")
    op.execute("ALTER TABLE threat_feed_sources DROP COLUMN IF EXISTS source_type")
