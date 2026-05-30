"""Add threat feed rule direction.

Revision ID: 008_threat_feed_direction
Revises: 007_group_unifi_nullable
Create Date: 2026-05-30
"""

from __future__ import annotations

from alembic import op

revision: str = "008_threat_feed_direction"
down_revision: str | None = "007_group_unifi_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Use op.execute (raw SQL) throughout to avoid the asyncpg run_sync adapter
    # issue where op.add_column / op.alter_column may silently not apply
    # (see migration 006 for prior precedent).
    op.execute(
        "ALTER TABLE threat_feed_rules "
        "ADD COLUMN IF NOT EXISTS direction VARCHAR(16) NOT NULL DEFAULT 'inbound'"
    )
    op.execute(
        "ALTER TABLE threat_feed_pending_rules "
        "ADD COLUMN IF NOT EXISTS direction VARCHAR(16) NOT NULL DEFAULT 'inbound'"
    )
    # Drop old unique constraints (pattern-matching by column set in case the
    # constraint was auto-named by PostgreSQL).
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
    # Create new unique constraints (IF NOT EXISTS so the migration is idempotent
    # if a prior partial run already created them).
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'uq_threat_feed_rules_key'
            ) THEN
                ALTER TABLE threat_feed_rules
                ADD CONSTRAINT uq_threat_feed_rules_key
                UNIQUE (ruleset, chunk_index, direction);
            END IF;
        END $$;
    """)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'uq_threat_feed_pending_rules_key'
            ) THEN
                ALTER TABLE threat_feed_pending_rules
                ADD CONSTRAINT uq_threat_feed_pending_rules_key
                UNIQUE (ruleset, chunk_index, direction, action, payload_hash, status);
            END IF;
        END $$;
    """)
    # Remove the transient DEFAULT now that all existing rows have been filled.
    # ALTER COLUMN DROP DEFAULT is a no-op if no default exists, so this is safe
    # to run even if the ADD COLUMN above was a no-op (column pre-existed).
    op.execute("ALTER TABLE threat_feed_rules ALTER COLUMN direction DROP DEFAULT")
    op.execute("ALTER TABLE threat_feed_pending_rules ALTER COLUMN direction DROP DEFAULT")


def downgrade() -> None:
    op.execute("ALTER TABLE threat_feed_pending_rules DROP CONSTRAINT IF EXISTS uq_threat_feed_pending_rules_key")
    op.execute("ALTER TABLE threat_feed_rules DROP CONSTRAINT IF EXISTS uq_threat_feed_rules_key")
    op.execute("DELETE FROM threat_feed_pending_rules WHERE direction <> 'inbound'")
    op.execute("DELETE FROM threat_feed_rules WHERE direction <> 'inbound'")
    op.execute("""
        ALTER TABLE threat_feed_pending_rules
        ADD CONSTRAINT uq_threat_feed_pending_rules_legacy_key
        UNIQUE (ruleset, chunk_index, action, payload_hash, status)
    """)
    op.execute("""
        ALTER TABLE threat_feed_rules
        ADD CONSTRAINT uq_threat_feed_rules_legacy_key
        UNIQUE (ruleset, chunk_index)
    """)
    op.execute("ALTER TABLE threat_feed_pending_rules DROP COLUMN direction")
    op.execute("ALTER TABLE threat_feed_rules DROP COLUMN direction")
