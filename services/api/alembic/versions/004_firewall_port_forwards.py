"""Add firewall port forwards.

Revision ID: 004_firewall_port_forwards
Revises: 003_ids_config_raw_json
Create Date: 2026-05-29
"""

from collections.abc import Sequence

revision: str = "004_firewall_port_forwards"
down_revision: str | None = "003_ids_config_raw_json"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Additive table is created by Base.metadata.create_all during API startup.
    pass


def downgrade() -> None:
    pass
