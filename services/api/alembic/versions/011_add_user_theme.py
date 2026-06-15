"""Add user theme preference.

Revision ID: 011_add_user_theme
Revises: 010_add_users_table
Create Date: 2026-06-01
"""

import sqlalchemy as sa

from alembic import op

revision = "011_add_user_theme"
down_revision = "010_add_users_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user", sa.Column("theme", sa.String(16), nullable=False, server_default="light"))


def downgrade() -> None:
    op.drop_column("user", "theme")
