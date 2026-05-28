"""Add raw IDS config storage.

Revision ID: 003_ids_config_raw_json
Revises: 002_cve_threatfeed_settings
Create Date: 2026-05-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "003_ids_config_raw_json"
down_revision: str | None = "002_cve_threatfeed_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("ids_config", "mode", type_=sa.String(32), existing_type=sa.String(16))
    op.add_column("ids_config", sa.Column("raw_json", sa.Text()))


def downgrade() -> None:
    op.drop_column("ids_config", "raw_json")
    op.alter_column("ids_config", "mode", type_=sa.String(16), existing_type=sa.String(32))
