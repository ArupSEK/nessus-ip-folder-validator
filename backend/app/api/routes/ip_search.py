from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from backend.app.api.deps import require_permissions
from backend.app.db.session import get_db
from backend.app.schemas.ip_search import IpSearchRequest, IpSearchResponse
from backend.app.services.ip_search import IpSearchError, parse_uploaded_entries, run_ip_search

router = APIRouter(tags=["ip-search"])


@router.post("/query", response_model=IpSearchResponse)
def query_ip_search(
    payload: IpSearchRequest,
    _: object = Depends(require_permissions("scans.view")),
    db: Session = Depends(get_db),
) -> IpSearchResponse:
    try:
        return run_ip_search(db, payload.entries, expand_cidr=payload.expand_cidr)
    except IpSearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/upload", response_model=IpSearchResponse)
async def upload_ip_search(
    file: UploadFile = File(...),
    expand_cidr: bool = False,
    _: object = Depends(require_permissions("scans.view")),
    db: Session = Depends(get_db),
) -> IpSearchResponse:
    try:
        payload = await file.read()
        entries = parse_uploaded_entries(file.filename or "", payload)
        return run_ip_search(db, entries, expand_cidr=expand_cidr)
    except IpSearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
