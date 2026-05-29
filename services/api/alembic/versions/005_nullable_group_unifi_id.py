"""Make threat_feed_rules.group_unifi_id nullable for zone-policy enforcement

Revision ID: 005_nullable_group_unifi_id
Revises: 004_firewall_port_forwards
Create Date: 2026-05-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "005_nullable_group_unifi_id"
down_revision: str | None = "004_firewall_port_forwards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "threat_feed_rules",
        "group_unifi_id",
        existing_type=sa.String(128),
        nullable=True,
    )


def downgrade() -> None:
    # Set NULLs to empty string before restoring NOT NULL constraint
    op.execute("UPDATE threat_feed_rules SET group_unifi_id = '' WHERE group_unifi_id IS NULL")
    op.alter_column(
        "threat_feed_rules",
        "group_unifi_id",
        existing_type=sa.String(128),
        nullable=False,
    )
