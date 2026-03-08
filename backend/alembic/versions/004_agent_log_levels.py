"""Add log_levels column to agents table.

Revision ID: 004
Revises: 003
Create Date: 2026-03-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("log_levels", sa.String(32), nullable=True, server_default="1,2,3"))


def downgrade() -> None:
    op.drop_column("agents", "log_levels")
