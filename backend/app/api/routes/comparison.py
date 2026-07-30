from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import get_source_ip, require_csrf, require_permissions
from backend.app.db.session import get_db
from backend.app.schemas.comparison import ComparisonRunRequest, ComparisonRunResponse
from backend.app.services.comparison import ComparisonServiceError, run_comparison

router = APIRouter(tags=["comparison"])


@router.post("/run", response_model=ComparisonRunResponse)
def run_comparison_route(
    payload: ComparisonRunRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> ComparisonRunResponse:
    try:
        return run_comparison(db, actor_session=current_session, payload=payload, source_ip=get_source_ip(request))
    except ComparisonServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
