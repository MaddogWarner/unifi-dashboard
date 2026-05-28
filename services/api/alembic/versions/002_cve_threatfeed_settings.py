"""Add CVE monitoring and threat feed tables.

Revision ID: 002_cve_threatfeed_settings
Revises: 001_initial_schema
Create Date: 2026-05-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002_cve_threatfeed_settings"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "device_inventory",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("unifi_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(256)),
        sa.Column("model", sa.String(128)),
        sa.Column("firmware_version", sa.String(64)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("site", sa.String(64)),
        sa.Column("raw_json", sa.Text()),
        sa.Column("synced_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("unifi_id"),
    )
    op.create_table(
        "cve_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(256)),
        sa.Column("description", sa.Text()),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("cvss_score", sa.Numeric(4, 1)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("affected_cpe", sa.String(512)),
        sa.Column("ubiquiti_bulletin_url", sa.String(512)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("raw_json", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_table(
        "cve_device_links",
        sa.Column(
            "cve_id",
            sa.String(32),
            sa.ForeignKey("cve_alerts.cve_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "device_id",
            sa.Integer(),
            sa.ForeignKey("device_inventory.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.UniqueConstraint("cve_id", "device_id"),
    )
    op.create_table(
        "threat_feed_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_polled_at", sa.DateTime(timezone=True)),
        sa.Column("last_entry_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("url"),
    )
    op.create_table(
        "threat_feed_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column(
            "feed_source_id",
            sa.Integer(),
            sa.ForeignKey("threat_feed_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("cidr", "feed_source_id"),
    )
    op.create_table(
        "threat_feed_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ruleset", sa.String(64), nullable=False),
        sa.Column("group_unifi_id", sa.String(128), nullable=False),
        sa.Column("rule_unifi_id", sa.String(128)),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("payload_hash", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("ruleset", "chunk_index"),
    )
    op.create_table(
        "threat_feed_pending_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ruleset", sa.String(64), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("group_name", sa.String(256), nullable=False),
        sa.Column("rule_name", sa.String(256), nullable=False),
        sa.Column("group_unifi_id", sa.String(128)),
        sa.Column("rule_unifi_id", sa.String(128)),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("ruleset", "chunk_index", "action", "payload_hash", "status"),
    )


def downgrade() -> None:
    op.drop_table("threat_feed_pending_rules")
    op.drop_table("threat_feed_rules")
    op.drop_table("threat_feed_entries")
    op.drop_table("threat_feed_sources")
    op.drop_table("cve_device_links")
    op.drop_table("cve_alerts")
    op.drop_table("device_inventory")
    op.drop_table("app_settings")
