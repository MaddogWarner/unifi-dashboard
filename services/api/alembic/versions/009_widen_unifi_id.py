"""Widen unifi_id columns from VARCHAR(64) to VARCHAR(128).

Zone-based policy IDs from UniFi Network are composite strings of the form
siteId-zoneId1-zoneId2, which reach 74+ characters and exceed the previous
VARCHAR(64) limit, causing StringDataRightTruncationError on every poll cycle.

Revision ID: 009_widen_unifi_id
Revises: 008_threat_feed_direction
Create Date: 2026-05-31
"""

from __future__ import annotations

from alembic import op

revision: str = "009_widen_unifi_id"
down_revision: str | None = "008_threat_feed_direction"
branch_labels = None
depends_on = None

_TARGETS = [
    ("firewall_policies", "unifi_id"),
    ("firewall_rules", "unifi_id"),
    ("firewall_port_forwards", "unifi_id"),
    ("networks", "unifi_id"),
]


def upgrade() -> None:
    for table, column in _TARGETS:
        # Widening VARCHAR never rewrites rows on PostgreSQL, so this is fast.
        # The DO $$ guard makes the step idempotent if the column is already ≥128.
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name   = '{table}'
                      AND column_name  = '{column}'
                      AND character_maximum_length IS NOT NULL
                      AND character_maximum_length < 128
                ) THEN
                    ALTER TABLE {table} ALTER COLUMN {column} TYPE VARCHAR(128);
                END IF;
            END $$;
        """)


def downgrade() -> None:
    for table, column in reversed(_TARGETS):
        op.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} TYPE VARCHAR(64)"
        )
