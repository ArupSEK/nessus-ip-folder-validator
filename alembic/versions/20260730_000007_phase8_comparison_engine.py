"""phase8 comparison engine

Revision ID: 20260730_000007
Revises: 20260730_000006
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000007"
down_revision = "20260730_000006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("asset_records") as batch_op:
        batch_op.drop_index("ix_asset_records_stable_asset_key")
        batch_op.create_index("ix_asset_records_stable_asset_key", ["stable_asset_key"], unique=False)
        batch_op.create_index("ix_asset_records_import_asset_key", ["source_import_job_id", "stable_asset_key"], unique=True)

    with op.batch_alter_table("finding_records") as batch_op:
        batch_op.drop_index("ix_finding_records_finding_key")
        batch_op.create_index("ix_finding_records_finding_key", ["finding_key"], unique=False)
        batch_op.create_index("ix_finding_records_import_finding_key", ["source_import_job_id", "finding_key"], unique=True)

    op.create_table(
        "comparison_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("previous_import_job_id", sa.String(length=36), sa.ForeignKey("import_jobs.id"), nullable=False),
        sa.Column("latest_import_job_id", sa.String(length=36), sa.ForeignKey("import_jobs.id"), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="completed"),
        sa.Column("comparable_asset_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("non_comparable_asset_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("existing_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("closed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("not_validated_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity_changed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("port_changed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "comparison_result_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("comparison_run_id", sa.String(length=36), sa.ForeignKey("comparison_runs.id"), nullable=False),
        sa.Column("asset_key", sa.String(length=255), nullable=False),
        sa.Column("finding_key", sa.String(length=255), nullable=False),
        sa.Column("previous_finding_id", sa.String(length=36), sa.ForeignKey("finding_records.id"), nullable=True),
        sa.Column("latest_finding_id", sa.String(length=36), sa.ForeignKey("finding_records.id"), nullable=True),
        sa.Column("comparison_eligibility", sa.String(length=128), nullable=False, server_default="comparable"),
        sa.Column("lifecycle_status", sa.String(length=64), nullable=False, server_default="Existing"),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_comparison_result_records_comparison_run_id", "comparison_result_records", ["comparison_run_id"], unique=False)
    op.create_index("ix_comparison_result_records_asset_key", "comparison_result_records", ["asset_key"], unique=False)
    op.create_index("ix_comparison_result_records_finding_key", "comparison_result_records", ["finding_key"], unique=False)
    op.create_index("ix_comparison_result_records_lifecycle_status", "comparison_result_records", ["lifecycle_status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_comparison_result_records_lifecycle_status", table_name="comparison_result_records")
    op.drop_index("ix_comparison_result_records_finding_key", table_name="comparison_result_records")
    op.drop_index("ix_comparison_result_records_asset_key", table_name="comparison_result_records")
    op.drop_index("ix_comparison_result_records_comparison_run_id", table_name="comparison_result_records")
    op.drop_table("comparison_result_records")
    op.drop_table("comparison_runs")

    with op.batch_alter_table("finding_records") as batch_op:
        batch_op.drop_index("ix_finding_records_import_finding_key")
        batch_op.drop_index("ix_finding_records_finding_key")
        batch_op.create_index("ix_finding_records_finding_key", ["finding_key"], unique=True)

    with op.batch_alter_table("asset_records") as batch_op:
        batch_op.drop_index("ix_asset_records_import_asset_key")
        batch_op.drop_index("ix_asset_records_stable_asset_key")
        batch_op.create_index("ix_asset_records_stable_asset_key", ["stable_asset_key"], unique=True)
