"""Add firewall port forwards.

Revision ID: 004_firewall_port_forwards
Revises: 003_ids_config_raw_json
Create Date: 2026-05-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "004_firewall_port_forwards"
down_revision: str | None = "003_ids_config_raw_json"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    if "firewall_port_forwards" in inspector.get_table_names():
        return
    op.create_table(
        "firewall_port_forwards",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("unifi_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("protocol", sa.String(16)),
        sa.Column("dst_port", sa.String(128)),
        sa.Column("fwd_port", sa.String(128)),
        sa.Column("fwd_ip", sa.String(45)),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("unifi_id"),
    )
    op.create_index("ix_firewall_port_forwards_unifi_id", "firewall_port_forwards", ["unifi_id"])
    op.create_index("ix_firewall_port_forwards_fwd_ip", "firewall_port_forwards", ["fwd_ip"])


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    if "firewall_port_forwards" in inspector.get_table_names():
        op.drop_table("firewall_port_forwards")
