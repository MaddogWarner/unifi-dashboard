"""add users table

Revision ID: 010_add_users_table
Revises: 009_widen_unifi_id
Create Date: 2026-05-31
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "010_add_users_table"
down_revision = "009_widen_unifi_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("hashed_password", sa.String(length=1024), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_user_email"), "user", ["email"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_user_email"), table_name="user")
    op.drop_table("user")
