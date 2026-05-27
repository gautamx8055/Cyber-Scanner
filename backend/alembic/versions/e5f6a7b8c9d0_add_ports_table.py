"""add_ports_table

Revision ID: e5f6a7b8c9d0
Revises: c3d4e5f6a7b8
Create Date: 2026-05-27

Phase 6 normalizes port results into their own table. Each row is one port
finding (state, service, banner, parsed product/version) from a port scan,
linked to its parent scan via scan_id (CASCADE delete). This replaces the
JSON blob in scans.results with queryable per-port rows.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ports",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("proto", sa.String(8), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("service", sa.String(64), nullable=True),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_ports_scan_id", "ports", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_ports_scan_id", table_name="ports")
    op.drop_table("ports")
