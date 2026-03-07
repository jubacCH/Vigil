"""Add unique case-insensitive index on agents.hostname.

Revision ID: 003
Revises: 002
Create Date: 2026-03-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_agents_hostname_lower",
        "agents",
        [sa.text("lower(hostname)")],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_agents_hostname_lower", table_name="agents")
