"""phase5 scan management

Revision ID: 20260730_000005
Revises: 20260730_000004
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000005"
down_revision = "20260730_000004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("nessus_scan_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("nessus_uuid", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("folder_record_id", sa.String(length=36), sa.ForeignKey("folder_records.id"), nullable=True),
        sa.Column("folder_nessus_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("folder_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("template_uuid", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("scanner_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("targets_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("target_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("schedule_type", sa.String(length=64), nullable=False, server_default="on_demand"),
        sa.Column("owner", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("history_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("permission_status", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("last_launch_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_completion_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_synchronized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_records_name", "scan_records", ["name"], unique=False)
    op.create_index("ix_scan_records_nessus_scan_id", "scan_records", ["nessus_scan_id"], unique=True)

    op.create_table(
        "scan_history_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scan_record_id", sa.String(length=36), sa.ForeignKey("scan_records.id"), nullable=False),
        sa.Column("nessus_history_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_baseline_locked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_evidence_locked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_history_records_scan_record_id", "scan_history_records", ["scan_record_id"], unique=False)
    op.create_index("ix_scan_history_records_nessus_history_id", "scan_history_records", ["nessus_history_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scan_history_records_nessus_history_id", table_name="scan_history_records")
    op.drop_index("ix_scan_history_records_scan_record_id", table_name="scan_history_records")
    op.drop_table("scan_history_records")
    op.drop_index("ix_scan_records_nessus_scan_id", table_name="scan_records")
    op.drop_index("ix_scan_records_name", table_name="scan_records")
    op.drop_table("scan_records")
