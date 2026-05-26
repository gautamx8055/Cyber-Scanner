"""add_vulnerabilities_table

Revision ID: a1b2c3d4e5f6
Revises: 7b2a9f3c4d5e
Create Date: 2026-05-26

Phase 4 adds CVE persistence. Each row is one CVE matched against a service
found during a scan, linked to its parent scan via scan_id (CASCADE delete).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "7b2a9f3c4d5e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("proto", sa.String(8), nullable=False, server_default="tcp"),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="Unknown"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="local"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_vulnerabilities_scan_id", "vulnerabilities", ["scan_id"])
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_cve_id", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_scan_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
