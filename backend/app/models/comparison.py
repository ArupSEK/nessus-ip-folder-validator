from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ComparisonRun(Base):
    __tablename__ = "comparison_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    previous_import_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("import_jobs.id"), index=True)
    latest_import_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("import_jobs.id"), index=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    comparable_asset_count: Mapped[int] = mapped_column(Integer(), default=0)
    non_comparable_asset_count: Mapped[int] = mapped_column(Integer(), default=0)
    new_count: Mapped[int] = mapped_column(Integer(), default=0)
    existing_count: Mapped[int] = mapped_column(Integer(), default=0)
    closed_count: Mapped[int] = mapped_column(Integer(), default=0)
    reopened_count: Mapped[int] = mapped_column(Integer(), default=0)
    not_validated_count: Mapped[int] = mapped_column(Integer(), default=0)
    severity_changed_count: Mapped[int] = mapped_column(Integer(), default=0)
    port_changed_count: Mapped[int] = mapped_column(Integer(), default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ComparisonResultRecord(Base):
    __tablename__ = "comparison_result_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    comparison_run_id: Mapped[str] = mapped_column(String(36), ForeignKey("comparison_runs.id"), index=True)
    asset_key: Mapped[str] = mapped_column(String(255), index=True)
    finding_key: Mapped[str] = mapped_column(String(255), index=True)
    previous_finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("finding_records.id"), nullable=True)
    latest_finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("finding_records.id"), nullable=True)
    comparison_eligibility: Mapped[str] = mapped_column(String(128), default="comparable")
    lifecycle_status: Mapped[str] = mapped_column(String(64), default="Existing", index=True)
    reason: Mapped[str] = mapped_column(Text(), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
