from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FindingRecord(Base):
    __tablename__ = "finding_records"
    __table_args__ = (
        Index("ix_finding_records_import_finding_key", "source_import_job_id", "finding_key", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    finding_key: Mapped[str] = mapped_column(String(255), index=True)
    source_import_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("import_jobs.id"), index=True)
    source_scan_record_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_records.id"), index=True)
    source_history_record_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_history_records.id"), nullable=True, index=True)
    asset_record_id: Mapped[str] = mapped_column(String(36), ForeignKey("asset_records.id"), index=True)
    plugin_id: Mapped[int] = mapped_column(Integer(), default=0)
    plugin_name: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[int] = mapped_column(Integer(), default=0)
    port: Mapped[int] = mapped_column(Integer(), default=0)
    protocol: Mapped[str] = mapped_column(String(32), default="")
    plugin_family: Mapped[str] = mapped_column(String(255), default="")
    risk_factor: Mapped[str] = mapped_column(String(64), default="")
    synopsis: Mapped[str] = mapped_column(Text(), default="")
    plugin_output: Mapped[str] = mapped_column(Text(), default="")
    state: Mapped[str] = mapped_column(String(64), default="active")
    first_found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
