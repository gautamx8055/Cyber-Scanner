"""add_results_column_to_scans

Revision ID: 7b2a9f3c4d5e
Revises: 1dce0a522bd6
Create Date: 2026-04-19

Phase 2 adds per-port findings persistence. Using a JSON column keeps the
schema minimal now; Phase 6 introduces the normalized Port/Vulnerability/
WebFinding tables that replace this.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "7b2a9f3c4d5e"
down_revision: Union[str, None] = "1dce0a522bd6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("results", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "results")
