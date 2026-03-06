"""Initial schema — all tables managed by the new models package.

Revision ID: 001
Revises: None
Create Date: 2026-03-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Settings
    op.create_table(
        "settings",
        sa.Column("key", sa.String(), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("encrypted", sa.Boolean(), default=False),
    )

    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(64), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(128), nullable=False),
        sa.Column("role", sa.String(16), server_default="admin"),
        sa.Column("created_at", sa.DateTime()),
    )

    # Sessions
    op.create_table(
        "sessions",
        sa.Column("token", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )

    # Ping hosts
    op.create_table(
        "ping_hosts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="1"),
        sa.Column("check_type", sa.String(), server_default="icmp"),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("latency_threshold_ms", sa.Float(), nullable=True),
        sa.Column("maintenance", sa.Boolean(), server_default="0"),
        sa.Column("ssl_expiry_days", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(), server_default="manual"),
        sa.Column("source_detail", sa.String(), nullable=True),
        sa.Column("mac_address", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime()),
    )

    # Ping results
    op.create_table(
        "ping_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("ping_hosts.id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), index=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
    )

    # Integration configs (generic)
    op.create_table(
        "integration_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("type", sa.String(32), nullable=False, index=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="1"),
        sa.Column("created_at", sa.DateTime()),
    )

    # Snapshots (generic)
    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime()),
        sa.Column("ok", sa.Boolean(), server_default="1"),
        sa.Column("data_json", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_snap_type_entity_ts",
        "snapshots",
        ["entity_type", "entity_id", sa.text("timestamp DESC")],
    )


def downgrade() -> None:
    op.drop_table("snapshots")
    op.drop_table("integration_configs")
    op.drop_table("ping_results")
    op.drop_table("ping_hosts")
    op.drop_table("sessions")
    op.drop_table("users")
    op.drop_table("settings")
