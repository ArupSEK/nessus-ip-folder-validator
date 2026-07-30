from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import require_permissions
from backend.app.db.session import get_db
from backend.app.schemas.audit import AuditEventListResponse
from backend.app.services.audit import list_audit_events

router = APIRouter(tags=["audit"])


@router.get("/events", response_model=AuditEventListResponse)
def get_audit_events_route(
    action: str = Query(default=""),
    object_type: str = Query(default=""),
    result: str = Query(default=""),
    search: str = Query(default=""),
    limit: int = Query(default=100),
    _: object = Depends(require_permissions("audit.view")),
    db: Session = Depends(get_db),
) -> AuditEventListResponse:
    return list_audit_events(
        db,
        action=action,
        object_type=object_type,
        result=result,
        search=search,
        limit=limit,
    )
