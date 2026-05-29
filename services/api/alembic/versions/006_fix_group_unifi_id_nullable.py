"""Force threat_feed_rules.group_unifi_id nullable via raw SQL.

op.alter_column did not reliably apply through the asyncpg run_sync adapter.
This migration uses op.execute() directly, which is idempotent on PostgreSQL
(DROP NOT NULL on an already-nullable column is a no-op).

Revision ID: 006_fix_group_unifi_id_nullable
Revises: 005_nullable_group_unifi_id
Create Date: 2026-05-29
"""

from __future__ import annotations

from alembic import op

revision: str = "006_fix_group_unifi_id_nullable"
down_revision: str | None = "005_nullable_group_unifi_id"
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
