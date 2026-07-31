from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AssetKeyOverride(Base):
    __tablename__ = "asset_key_overrides"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_asset_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    resolved_asset_key: Mapped[str] = mapped_column(String(255), index=True)
    resolution_type: Mapped[str] = mapped_column(String(32), default="merge")
    is_active: Mapped[bool] = mapped_column(Boolean(), default=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class AssetReviewRecord(Base):
    __tablename__ = "asset_review_records"
    __table_args__ = (
        Index("ix_asset_review_pair", "left_asset_key", "right_asset_key", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    left_asset_key: Mapped[str] = mapped_column(String(255), index=True)
    right_asset_key: Mapped[str] = mapped_column(String(255), index=True)
    left_hostname: Mapped[str] = mapped_column(String(255), default="")
    right_hostname: Mapped[str] = mapped_column(String(255), default="")
    left_ipv4_address: Mapped[str] = mapped_column(String(64), default="")
    right_ipv4_address: Mapped[str] = mapped_column(String(64), default="")
    left_fqdn: Mapped[str] = mapped_column(String(255), default="")
    right_fqdn: Mapped[str] = mapped_column(String(255), default="")
    match_basis: Mapped[str] = mapped_column(Text(), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    canonical_asset_key: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text(), default="")
    resolved_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
