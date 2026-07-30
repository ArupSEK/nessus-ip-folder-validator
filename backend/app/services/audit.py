from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.auth import AuditEvent, User
from backend.app.schemas.audit import AuditEventListResponse, AuditEventResponse


def _ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def write_audit(
    db: Session,
    *,
    actor_user_id: str | None,
    action: str,
    object_type: str,
    object_id: str = "",
    object_name: str = "",
    source_ip: str = "",
    result: str = "success",
    previous_state: dict | None = None,
    new_state: dict | None = None,
    justification: str = "",
) -> AuditEvent:
    event = AuditEvent(
        actor_user_id=actor_user_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        object_name=object_name,
        source_ip=source_ip,
        result=result,
        previous_state=json.dumps(previous_state or {}, sort_keys=True),
        new_state=json.dumps(new_state or {}, sort_keys=True),
        justification=justification,
    )
    db.add(event)
    return event


def _event_to_response(db: Session, event: AuditEvent) -> AuditEventResponse:
    actor_username = ""
    if event.actor_user_id:
        actor = db.get(User, event.actor_user_id)
        actor_username = actor.username if actor is not None else ""
    return AuditEventResponse(
        id=event.id,
        actor_username=actor_username,
        timestamp=_ensure_utc(event.created_at).isoformat() if _ensure_utc(event.created_at) else "",
        source_ip=event.source_ip,
        action=event.action,
        object_type=event.object_type,
        object_id=event.object_id,
        object_name=event.object_name,
        result=event.result,
        justification=event.justification,
        previous_state=event.previous_state,
        new_state=event.new_state,
    )


def list_audit_events(
    db: Session,
    *,
    action: str = "",
    object_type: str = "",
    result: str = "",
    search: str = "",
    limit: int = 100,
) -> AuditEventListResponse:
    safe_limit = max(1, min(limit, 500))
    query = select(AuditEvent)
    if action.strip():
        query = query.where(AuditEvent.action == action.strip())
    if object_type.strip():
        query = query.where(AuditEvent.object_type == object_type.strip())
    if result.strip():
        query = query.where(AuditEvent.result == result.strip())
    if search.strip():
        token = f"%{search.strip()}%"
        query = query.where(
            or_(
                AuditEvent.action.ilike(token),
                AuditEvent.object_type.ilike(token),
                AuditEvent.object_id.ilike(token),
                AuditEvent.object_name.ilike(token),
                AuditEvent.source_ip.ilike(token),
                AuditEvent.justification.ilike(token),
            )
        )
    rows = db.scalars(query.order_by(AuditEvent.created_at.desc()).limit(safe_limit)).all()
    return AuditEventListResponse(total=len(rows), events=[_event_to_response(db, row) for row in rows])
