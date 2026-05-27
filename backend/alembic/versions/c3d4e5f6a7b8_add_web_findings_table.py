"""add_web_findings_table

Revision ID: c3d4e5f6a7b8
Revises: a1b2c3d4e5f6
Create Date: 2026-05-27

Phase 5 adds web-scan persistence. Each row is one web-security finding
(TLS issue, missing header, discovered path, OWASP probe hit, or live
subdomain), linked to its parent scan via scan_id (CASCADE delete).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "web_findings",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("finding_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="Info"),
        sa.Column("url", sa.String(2048), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_web_findings_scan_id", "web_findings", ["scan_id"])
    op.create_index("ix_web_findings_finding_type", "web_findings", ["finding_type"])


def downgrade() -> None:
    op.drop_index("ix_web_findings_finding_type", table_name="web_findings")
    op.drop_index("ix_web_findings_scan_id", table_name="web_findings")
    op.drop_table("web_findings")
