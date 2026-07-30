from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FolderRecord(Base):
    __tablename__ = "folder_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    nessus_folder_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    folder_type: Mapped[str] = mapped_column(String(64), default="")
    is_custom: Mapped[bool] = mapped_column(Boolean(), default=False)
    owner: Mapped[str] = mapped_column(String(255), default="")
    permission_status: Mapped[str] = mapped_column(String(64), default="unknown")
    scan_count: Mapped[int] = mapped_column(Integer(), default=0)
    last_synchronized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
