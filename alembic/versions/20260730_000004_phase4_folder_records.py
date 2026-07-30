"""phase4 folder records

Revision ID: 20260730_000004
Revises: 20260730_000003
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000004"
down_revision = "20260730_000003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "folder_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("nessus_folder_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("folder_type", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("is_custom", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("owner", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("permission_status", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("scan_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_synchronized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_folder_records_name", "folder_records", ["name"], unique=False)
    op.create_index("ix_folder_records_nessus_folder_id", "folder_records", ["nessus_folder_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_folder_records_nessus_folder_id", table_name="folder_records")
    op.drop_index("ix_folder_records_name", table_name="folder_records")
    op.drop_table("folder_records")
