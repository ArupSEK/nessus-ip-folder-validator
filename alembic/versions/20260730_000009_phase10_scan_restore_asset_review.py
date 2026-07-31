"""phase10 scan restore and asset review

Revision ID: 20260730_000009
Revises: 20260730_000008
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000009"
down_revision = "20260730_000008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_records", sa.Column("permanently_deleted_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "asset_key_overrides",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("source_asset_key", sa.String(length=255), nullable=False),
        sa.Column("resolved_asset_key", sa.String(length=255), nullable=False),
        sa.Column("resolution_type", sa.String(length=32), nullable=False, server_default="merge"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_asset_key_overrides_source_asset_key", "asset_key_overrides", ["source_asset_key"], unique=True)
    op.create_index("ix_asset_key_overrides_resolved_asset_key", "asset_key_overrides", ["resolved_asset_key"], unique=False)

    op.create_table(
        "asset_review_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("left_asset_key", sa.String(length=255), nullable=False),
        sa.Column("right_asset_key", sa.String(length=255), nullable=False),
        sa.Column("left_hostname", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("right_hostname", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("left_ipv4_address", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("right_ipv4_address", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("left_fqdn", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("right_fqdn", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("match_basis", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("canonical_asset_key", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("resolved_by_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_asset_review_records_left_asset_key", "asset_review_records", ["left_asset_key"], unique=False)
    op.create_index("ix_asset_review_records_right_asset_key", "asset_review_records", ["right_asset_key"], unique=False)
    op.create_index("ix_asset_review_records_status", "asset_review_records", ["status"], unique=False)
    op.create_index("ix_asset_review_pair", "asset_review_records", ["left_asset_key", "right_asset_key"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_asset_review_pair", table_name="asset_review_records")
    op.drop_index("ix_asset_review_records_status", table_name="asset_review_records")
    op.drop_index("ix_asset_review_records_right_asset_key", table_name="asset_review_records")
    op.drop_index("ix_asset_review_records_left_asset_key", table_name="asset_review_records")
    op.drop_table("asset_review_records")

    op.drop_index("ix_asset_key_overrides_resolved_asset_key", table_name="asset_key_overrides")
    op.drop_index("ix_asset_key_overrides_source_asset_key", table_name="asset_key_overrides")
    op.drop_table("asset_key_overrides")

    op.drop_column("scan_records", "permanently_deleted_at")
