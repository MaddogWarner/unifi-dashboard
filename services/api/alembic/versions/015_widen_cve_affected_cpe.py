"""Widen cve_alerts.affected_cpe to TEXT.

The NVD collector stores every affected Ubiquiti CPE as one comma-joined string, which for
advisories covering many hardware models runs to several kilobytes. VARCHAR(512) made the insert
raise StringDataRightTruncationError and aborted the whole poll, so later CVEs were never stored.

Revision ID: 015_widen_cve_affected_cpe
Revises: 014_add_assessment_runs
Create Date: 2026-11-15
"""

from alembic import op

revision = "015_widen_cve_affected_cpe"
down_revision = "014_add_assessment_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE cve_alerts ALTER COLUMN affected_cpe TYPE TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE cve_alerts ALTER COLUMN affected_cpe TYPE VARCHAR(512) USING left(affected_cpe, 512)")
