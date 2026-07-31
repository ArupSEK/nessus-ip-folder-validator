from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from backend.app.api.deps import get_source_ip, require_permissions
from backend.app.db.session import get_db
from backend.app.services.auth import collect_permissions
from backend.app.services.reports import ReportServiceError, build_report_bytes

router = APIRouter(tags=["reports"])


@router.get("/export")
def export_report_route(
    request: Request,
    report_type: str = Query(...),
    export_format: str = Query(default="csv"),
    comparison_run_id: str | None = Query(default=None),
    entries: str = Query(default=""),
    expand_cidr: bool = Query(default=False),
    days_until_expiry: int = Query(default=30, ge=0, le=365),
    current_session=Depends(require_permissions("reports.export")),
    db: Session = Depends(get_db),
) -> Response:
    if report_type.strip().lower() in {"deleted_objects_audit", "audit_events"}:
        permissions = collect_permissions(current_session.user)
        if "audit.view" not in permissions:
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
    try:
        filename, content_type, payload = build_report_bytes(
            db,
            actor_session=current_session,
            report_type=report_type,
            export_format=export_format,
            comparison_run_id=comparison_run_id,
            source_ip=get_source_ip(request),
            ip_search_entries=[item.strip() for item in entries.replace("\r", "\n").replace(",", "\n").splitlines() if item.strip()],
            expand_cidr=expand_cidr,
            days_until_expiry=days_until_expiry,
        )
    except ReportServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(
        content=payload,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
