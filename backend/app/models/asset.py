from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AssetRecord(Base):
    __tablename__ = "asset_records"
    __table_args__ = (
        Index("ix_asset_records_import_asset_key", "source_import_job_id", "stable_asset_key", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    stable_asset_key: Mapped[str] = mapped_column(String(255), index=True)
    source_import_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("import_jobs.id"), index=True)
    source_scan_record_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_records.id"), index=True)
    source_history_record_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_history_records.id"), nullable=True, index=True)
    tenable_asset_uuid: Mapped[str] = mapped_column(String(128), default="")
    agent_uuid: Mapped[str] = mapped_column(String(128), default="")
    bios_uuid: Mapped[str] = mapped_column(String(128), default="")
    mac_address: Mapped[str] = mapped_column(String(64), default="")
    fqdn: Mapped[str] = mapped_column(String(255), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ipv4_address: Mapped[str] = mapped_column(String(64), default="")
    ipv6_address: Mapped[str] = mapped_column(String(128), default="")
    os_name: Mapped[str] = mapped_column(String(255), default="")
    raw_metadata: Mapped[str] = mapped_column(Text(), default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
