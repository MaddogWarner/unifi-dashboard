"""Initial schema.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-05-27
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "firewall_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("unifi_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("src_zone", sa.String(64)),
        sa.Column("dst_zone", sa.String(64)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("protocol", sa.String(16)),
        sa.Column("schedule", sa.String(64)),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("unifi_id"),
    )
    op.create_index("ix_firewall_policies_unifi_id", "firewall_policies", ["unifi_id"])

    op.create_table(
        "firewall_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("unifi_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("ruleset", sa.String(32)),
        sa.Column("rule_index", sa.Integer()),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("src_address", sa.String(256)),
        sa.Column("dst_address", sa.String(256)),
        sa.Column("protocol", sa.String(16)),
        sa.Column("dst_port", sa.String(128)),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("unifi_id"),
    )
    op.create_index("ix_firewall_rules_unifi_id", "firewall_rules", ["unifi_id"])

    op.create_table(
        "networks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("unifi_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("vlan_id", sa.Integer()),
        sa.Column("zone", sa.String(64)),
        sa.Column("subnet", sa.String(64)),
        sa.Column("purpose", sa.String(64)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("unifi_id"),
    )
    op.create_index("ix_networks_unifi_id", "networks", ["unifi_id"])

    op.create_table(
        "ids_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("mode", sa.String(16)),
        sa.Column("categories", sa.Text()),
        sa.Column("sensitivity", sa.String(16)),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "threat_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature_id", sa.String(64)),
        sa.Column("signature_name", sa.String(256)),
        sa.Column("category", sa.String(128)),
        sa.Column("severity", sa.String(16)),
        sa.Column("src_ip", sa.String(45)),
        sa.Column("dst_ip", sa.String(45)),
        sa.Column("action", sa.String(16)),
        sa.Column("raw_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_threat_events_timestamp", "threat_events", ["timestamp"])
    op.create_index("ix_threat_events_src_ip", "threat_events", ["src_ip"])

    op.create_table(
        "policy_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_type", sa.String(32), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("snapshot_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_snapshots_created_at", "policy_snapshots", ["created_at"])

    op.create_table(
        "scan_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_ip", sa.String(45), nullable=False),
        sa.Column("scan_type", sa.String(16), nullable=False),
        sa.Column("ports_requested", sa.String(256), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result_json", sa.Text()),
        sa.Column("nmap_output", sa.Text()),
        sa.Column("triggered_by", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_scan_results_target_ip", "scan_results", ["target_ip"])
    op.create_index("ix_scan_results_created_at", "scan_results", ["created_at"])

    op.create_table(
        "firewall_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule_name", sa.String(256)),
        sa.Column("action", sa.String(8), nullable=False),
        sa.Column("src_ip", sa.String(45)),
        sa.Column("dst_ip", sa.String(45)),
        sa.Column("src_port", sa.Integer()),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("protocol", sa.String(8)),
        sa.Column("interface", sa.String(32)),
        sa.Column("direction", sa.String(16)),
        sa.Column("matched_policy_id", sa.Integer(), sa.ForeignKey("firewall_policies.id")),
        sa.Column("raw_line", sa.Text(), nullable=False),
    )
    op.create_index("ix_firewall_logs_timestamp", "firewall_logs", ["timestamp"])
    op.create_index("ix_firewall_logs_rule_name", "firewall_logs", ["rule_name"])
    op.create_index("ix_firewall_logs_src_ip", "firewall_logs", ["src_ip"])


def downgrade() -> None:
    op.drop_table("firewall_logs")
    op.drop_table("scan_results")
    op.drop_table("policy_snapshots")
    op.drop_table("threat_events")
    op.drop_table("ids_config")
    op.drop_table("networks")
    op.drop_table("firewall_rules")
    op.drop_table("firewall_policies")
