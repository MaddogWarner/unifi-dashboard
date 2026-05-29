"""Add threat feed rule direction.

Revision ID: 008_threat_feed_direction
Revises: 007_group_unifi_nullable
Create Date: 2026-05-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "008_threat_feed_direction"
down_revision: str | None = "007_group_unifi_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "threat_feed_rules",
        sa.Column("direction", sa.String(16), nullable=False, server_default="inbound"),
    )
    op.add_column(
        "threat_feed_pending_rules",
        sa.Column("direction", sa.String(16), nullable=False, server_default="inbound"),
    )
    op.execute("""
        DO $$
        DECLARE constraint_name text;
        BEGIN
            SELECT c.conname INTO constraint_name
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE t.relname = 'threat_feed_rules'
              AND n.nspname = current_schema()
              AND c.contype = 'u'
              AND (
                SELECT array_agg(a.attname::text ORDER BY keys.ordinality)
                FROM unnest(c.conkey) WITH ORDINALITY AS keys(attnum, ordinality)
                JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = keys.attnum
              ) = ARRAY['ruleset', 'chunk_index'];
            IF constraint_name IS NOT NULL THEN
                EXECUTE format('ALTER TABLE threat_feed_rules DROP CONSTRAINT %I', constraint_name);
            END IF;
        END $$;
    """)
    op.execute("""
        DO $$
        DECLARE constraint_name text;
        BEGIN
            SELECT c.conname INTO constraint_name
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE t.relname = 'threat_feed_pending_rules'
              AND n.nspname = current_schema()
              AND c.contype = 'u'
              AND (
                SELECT array_agg(a.attname::text ORDER BY keys.ordinality)
                FROM unnest(c.conkey) WITH ORDINALITY AS keys(attnum, ordinality)
                JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = keys.attnum
              ) = ARRAY['ruleset', 'chunk_index', 'action', 'payload_hash', 'status'];
            IF constraint_name IS NOT NULL THEN
                EXECUTE format(
                    'ALTER TABLE threat_feed_pending_rules DROP CONSTRAINT %I',
                    constraint_name
                );
            END IF;
        END $$;
    """)
    op.create_unique_constraint(
        "uq_threat_feed_rules_key",
        "threat_feed_rules",
        ["ruleset", "chunk_index", "direction"],
    )
    op.create_unique_constraint(
        "uq_threat_feed_pending_rules_key",
        "threat_feed_pending_rules",
        ["ruleset", "chunk_index", "direction", "action", "payload_hash", "status"],
    )
    op.alter_column("threat_feed_rules", "direction", server_default=None)
    op.alter_column("threat_feed_pending_rules", "direction", server_default=None)


def downgrade() -> None:
    op.drop_constraint("uq_threat_feed_pending_rules_key", "threat_feed_pending_rules", type_="unique")
    op.drop_constraint("uq_threat_feed_rules_key", "threat_feed_rules", type_="unique")
    op.execute("DELETE FROM threat_feed_pending_rules WHERE direction <> 'inbound'")
    op.execute("DELETE FROM threat_feed_rules WHERE direction <> 'inbound'")
    op.create_unique_constraint(
        "uq_threat_feed_pending_rules_legacy_key",
        "threat_feed_pending_rules",
        ["ruleset", "chunk_index", "action", "payload_hash", "status"],
    )
    op.create_unique_constraint(
        "uq_threat_feed_rules_legacy_key",
        "threat_feed_rules",
        ["ruleset", "chunk_index"],
    )
    op.drop_column("threat_feed_pending_rules", "direction")
    op.drop_column("threat_feed_rules", "direction")
