"""phase10 workflow

Revision ID: 20260730_000008
Revises: 20260730_000007
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000008"
down_revision = "20260730_000007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sla_policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("severity_name", sa.String(length=32), nullable=False),
        sa.Column("days_to_due", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sla_policies_severity_name", "sla_policies", ["severity_name"], unique=True)

    op.create_table(
        "finding_workflows",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("finding_key", sa.String(length=255), nullable=False),
        sa.Column("asset_key", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("current_finding_record_id", sa.String(length=36), sa.ForeignKey("finding_records.id"), nullable=True),
        sa.Column("current_comparison_result_id", sa.String(length=36), sa.ForeignKey("comparison_result_records.id"), nullable=True),
        sa.Column("owner", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("remediation_team", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("workflow_status", sa.String(length=64), nullable=False, server_default="Open"),
        sa.Column("sla_start_date", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("days_overdue", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("target_date", sa.Date(), nullable=True),
        sa.Column("actual_remediation_date", sa.Date(), nullable=True),
        sa.Column("ticket_number", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("ticket_url", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("comments", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("rescan_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("validation_status", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("created_by_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_by_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_workflows_finding_key", "finding_workflows", ["finding_key"], unique=True)
    op.create_index("ix_finding_workflows_asset_key", "finding_workflows", ["asset_key"], unique=False)
    op.create_index("ix_finding_workflows_workflow_status", "finding_workflows", ["workflow_status"], unique=False)

    op.create_table(
        "workflow_decisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("finding_workflow_id", sa.String(length=36), sa.ForeignKey("finding_workflows.id"), nullable=False),
        sa.Column("decision_type", sa.String(length=64), nullable=False),
        sa.Column("requester_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approver_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("business_justification", sa.Text(), nullable=False, server_default=""),
        sa.Column("compensating_controls", sa.Text(), nullable=False, server_default=""),
        sa.Column("start_date", sa.Date(), nullable=True),
        sa.Column("expiry_date", sa.Date(), nullable=True),
        sa.Column("review_date", sa.Date(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="requested"),
        sa.Column("renewal_history", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_workflow_decisions_finding_workflow_id", "workflow_decisions", ["finding_workflow_id"], unique=False)
    op.create_index("ix_workflow_decisions_decision_type", "workflow_decisions", ["decision_type"], unique=False)
    op.create_index("ix_workflow_decisions_status", "workflow_decisions", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_workflow_decisions_status", table_name="workflow_decisions")
    op.drop_index("ix_workflow_decisions_decision_type", table_name="workflow_decisions")
    op.drop_index("ix_workflow_decisions_finding_workflow_id", table_name="workflow_decisions")
    op.drop_table("workflow_decisions")
    op.drop_index("ix_finding_workflows_workflow_status", table_name="finding_workflows")
    op.drop_index("ix_finding_workflows_asset_key", table_name="finding_workflows")
    op.drop_index("ix_finding_workflows_finding_key", table_name="finding_workflows")
    op.drop_table("finding_workflows")
    op.drop_index("ix_sla_policies_severity_name", table_name="sla_policies")
    op.drop_table("sla_policies")
