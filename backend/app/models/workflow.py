from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SlaPolicy(Base):
    __tablename__ = "sla_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    severity_name: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    days_to_due: Mapped[int] = mapped_column(Integer(), default=0)
    is_active: Mapped[bool] = mapped_column(Boolean(), default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class FindingWorkflow(Base):
    __tablename__ = "finding_workflows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    finding_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    asset_key: Mapped[str] = mapped_column(String(255), default="", index=True)
    current_finding_record_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("finding_records.id"), nullable=True)
    current_comparison_result_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("comparison_result_records.id"), nullable=True)
    owner: Mapped[str] = mapped_column(String(255), default="")
    remediation_team: Mapped[str] = mapped_column(String(255), default="")
    workflow_status: Mapped[str] = mapped_column(String(64), default="Open", index=True)
    sla_start_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    days_overdue: Mapped[int] = mapped_column(Integer(), default=0)
    target_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    actual_remediation_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    ticket_number: Mapped[str] = mapped_column(String(128), default="")
    ticket_url: Mapped[str] = mapped_column(String(512), default="")
    comments: Mapped[str] = mapped_column(Text(), default="")
    evidence: Mapped[str] = mapped_column(Text(), default="")
    rescan_requested: Mapped[bool] = mapped_column(Boolean(), default=False)
    validation_status: Mapped[str] = mapped_column(String(128), default="")
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    updated_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class WorkflowDecision(Base):
    __tablename__ = "workflow_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    finding_workflow_id: Mapped[str] = mapped_column(String(36), ForeignKey("finding_workflows.id"), index=True)
    decision_type: Mapped[str] = mapped_column(String(64), index=True)
    requester_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    approver_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    reason: Mapped[str] = mapped_column(Text(), default="")
    business_justification: Mapped[str] = mapped_column(Text(), default="")
    compensating_controls: Mapped[str] = mapped_column(Text(), default="")
    start_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    expiry_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    review_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    evidence: Mapped[str] = mapped_column(Text(), default="")
    status: Mapped[str] = mapped_column(String(64), default="requested", index=True)
    renewal_history: Mapped[str] = mapped_column(Text(), default="[]")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
