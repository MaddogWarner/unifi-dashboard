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
    # Fail fast (rather than hang) if autovacuum or another process holds a
    # conflicting AccessExclusiveLock.  The container restart will retry once
    # the blocker has cleared.
    op.execute("SET LOCAL lock_timeout = '30s'")

    # Wrap ADD COLUMN in an existence check so the ALTER TABLE (and its
    # AccessExclusiveLock) is skipped entirely when the column was already
    # added by a runtime guard in an older deployment.
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name   = 'threat_feed_rules'
                  AND column_name  = 'direction'
            ) THEN
                ALTER TABLE threat_feed_rules
                    ADD COLUMN direction VARCHAR(16) NOT NULL DEFAULT 'inbound';
                ALTER TABLE threat_feed_rules
                    ALTER COLUMN direction DROP DEFAULT;
            END IF;
        END $$;
    """)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name   = 'threat_feed_pending_rules'
                  AND column_name  = 'direction'
            ) THEN
                ALTER TABLE threat_feed_pending_rules
                    ADD COLUMN direction VARCHAR(16) NOT NULL DEFAULT 'inbound';
                ALTER TABLE threat_feed_pending_rules
                    ALTER COLUMN direction DROP DEFAULT;
            END IF;
        END $$;
    """)
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
    # DEFAULT removal is handled inside the DO $$ ADD COLUMN blocks above.


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
