from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NessusConfiguration(Base):
    __tablename__ = "nessus_configurations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    base_url: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean(), default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer(), default=15)
    approved_hosts: Mapped[list[str]] = mapped_column(JSON(), default=list)
    access_key_encrypted: Mapped[str] = mapped_column(Text())
    secret_key_encrypted: Mapped[str] = mapped_column(Text())
    masked_access_key: Mapped[str] = mapped_column(String(64), default="")
    masked_secret_key: Mapped[str] = mapped_column(String(64), default="")
    server_info: Mapped[dict] = mapped_column(JSON(), default=dict)
    api_permissions: Mapped[list[str]] = mapped_column(JSON(), default=list)
    capabilities: Mapped[dict] = mapped_column(JSON(), default=dict)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    updated_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
