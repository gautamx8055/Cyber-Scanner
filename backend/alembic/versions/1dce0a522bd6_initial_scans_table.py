"""initial_scans_table

Revision ID: 1dce0a522bd6
Revises:
Create Date: 2026-04-11

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "1dce0a522bd6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create ENUM types first
    scan_type_enum = sa.Enum("port", "vuln", "web", "full", name="scan_type_enum")
    scan_status_enum = sa.Enum("queued", "running", "completed", "failed", name="scan_status_enum")

    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("target_ip", sa.String(255), nullable=False),
        sa.Column("target_hostname", sa.String(255), nullable=True),
        sa.Column("scan_type", scan_type_enum, nullable=False, server_default="port"),
        sa.Column("status", scan_status_enum, nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("options", sa.JSON(), nullable=True),
    )
    op.create_index("ix_scans_target_ip", "scans", ["target_ip"])
    op.create_index("ix_scans_started_at", "scans", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_started_at", table_name="scans")
    op.drop_index("ix_scans_target_ip", table_name="scans")
    op.drop_table("scans")
    sa.Enum(name="scan_type_enum").drop(op.get_bind())
    sa.Enum(name="scan_status_enum").drop(op.get_bind())
