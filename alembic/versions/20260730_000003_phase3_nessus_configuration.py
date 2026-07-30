"""phase3 nessus configuration

Revision ID: 20260730_000003
Revises: 20260730_000002
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000003"
down_revision = "20260730_000002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user_sessions", sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE user_sessions SET reauthenticated_at = created_at WHERE reauthenticated_at IS NULL")
    op.alter_column("user_sessions", "reauthenticated_at", nullable=False)

    op.create_table(
        "nessus_configurations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("base_url", sa.String(length=255), nullable=False, unique=True),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("approved_hosts", sa.JSON(), nullable=False),
        sa.Column("access_key_encrypted", sa.Text(), nullable=False),
        sa.Column("secret_key_encrypted", sa.Text(), nullable=False),
        sa.Column("masked_access_key", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("masked_secret_key", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("server_info", sa.JSON(), nullable=False),
        sa.Column("api_permissions", sa.JSON(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
    )
    op.create_index("ix_nessus_configurations_base_url", "nessus_configurations", ["base_url"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_nessus_configurations_base_url", table_name="nessus_configurations")
    op.drop_table("nessus_configurations")
    op.drop_column("user_sessions", "reauthenticated_at")
