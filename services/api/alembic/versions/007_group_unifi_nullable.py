"""Reassert threat_feed_rules.group_unifi_id nullable.

Revision ID: 007_group_unifi_nullable
Revises: 006_fix_group_unifi_id_nullable
Create Date: 2026-05-29
"""

from __future__ import annotations

from alembic import op

revision: str = "007_group_unifi_nullable"
down_revision: str | None = "006_fix_group_unifi_id_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE threat_feed_rules ALTER COLUMN group_unifi_id DROP NOT NULL"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE threat_feed_rules SET group_unifi_id = '' WHERE group_unifi_id IS NULL"
    )
    op.execute(
        "ALTER TABLE threat_feed_rules ALTER COLUMN group_unifi_id SET NOT NULL"
    )
