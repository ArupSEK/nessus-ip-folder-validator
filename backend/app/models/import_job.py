from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ImportJob(Base):
    __tablename__ = "import_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_record_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_records.id"), index=True)
    scan_history_record_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_history_records.id"), nullable=True, index=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    job_scope_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    progress_percent: Mapped[int] = mapped_column(Integer(), default=0)
    export_format: Mapped[str] = mapped_column(String(32), default="nessus")
    export_file_id: Mapped[str] = mapped_column(String(128), default="")
    export_status: Mapped[str] = mapped_column(String(64), default="")
    imported_asset_count: Mapped[int] = mapped_column(Integer(), default=0)
    imported_finding_count: Mapped[int] = mapped_column(Integer(), default=0)
    error_message: Mapped[str] = mapped_column(Text(), default="")
    last_checkpoint: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
