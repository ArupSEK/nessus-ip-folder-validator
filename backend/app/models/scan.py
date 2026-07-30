from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    nessus_scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    nessus_uuid: Mapped[str] = mapped_column(String(128), default="")
    name: Mapped[str] = mapped_column(String(255), index=True)
    folder_record_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("folder_records.id"), nullable=True)
    folder_nessus_id: Mapped[str] = mapped_column(String(64), default="")
    folder_name: Mapped[str] = mapped_column(String(255), default="")
    template_uuid: Mapped[str] = mapped_column(String(128), default="")
    scanner_id: Mapped[str] = mapped_column(String(64), default="")
    targets_text: Mapped[str] = mapped_column(Text(), default="")
    target_count: Mapped[int] = mapped_column(Integer(), default=0)
    schedule_type: Mapped[str] = mapped_column(String(64), default="on_demand")
    owner: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(64), default="unknown")
    history_count: Mapped[int] = mapped_column(Integer(), default=0)
    permission_status: Mapped[str] = mapped_column(String(64), default="unknown")
    last_launch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_completion_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_synchronized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    histories: Mapped[list["ScanHistoryRecord"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanHistoryRecord(Base):
    __tablename__ = "scan_history_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_record_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_records.id"), index=True)
    nessus_history_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(64), default="unknown")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer(), default=0)
    is_baseline_locked: Mapped[bool] = mapped_column(Boolean(), default=False)
    is_evidence_locked: Mapped[bool] = mapped_column(Boolean(), default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    scan: Mapped[ScanRecord] = relationship(back_populates="histories")
