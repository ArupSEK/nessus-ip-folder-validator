from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import require_permissions
from backend.app.db.session import get_db
from backend.app.schemas.dashboard import DashboardFindingListResponse, DashboardSummaryResponse
from backend.app.services.dashboard import DashboardServiceError, get_dashboard_summary, list_dashboard_findings

router = APIRouter(tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary_route(
    comparison_run_id: str | None = Query(default=None),
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> DashboardSummaryResponse:
    try:
        return get_dashboard_summary(db, comparison_run_id=comparison_run_id)
    except DashboardServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/findings", response_model=DashboardFindingListResponse)
def get_dashboard_findings_route(
    comparison_run_id: str | None = Query(default=None),
    lifecycle_status: str = Query(default=""),
    severity: int | None = Query(default=None),
    search: str = Query(default=""),
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> DashboardFindingListResponse:
    try:
        return list_dashboard_findings(
            db,
            comparison_run_id=comparison_run_id,
            lifecycle_status=lifecycle_status,
            severity=severity,
            search=search,
        )
    except DashboardServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
