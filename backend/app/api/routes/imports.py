from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import get_nessus_client_factory, get_source_ip, require_csrf, require_permissions
from backend.app.db.session import get_db
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.schemas.imports import ImportJobListResponse, ImportRecoverRequest, ImportResultResponse, ImportScanRequest
from backend.app.services.imports import ImportServiceError, list_import_jobs, recover_import_job, run_import_job
from backend.app.services.nessus import NessusConfigError, translate_nessus_error

router = APIRouter(tags=["imports"])


def _translate_import_error(exc: Exception) -> tuple[int, str]:
    if isinstance(exc, (ImportServiceError, NessusConfigError)):
        return 400, str(exc)
    return translate_nessus_error(exc)


@router.get("/jobs", response_model=ImportJobListResponse)
def get_import_jobs(
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> ImportJobListResponse:
    return list_import_jobs(db)


@router.post("/scans/{scan_id}", response_model=ImportResultResponse)
def run_import_route(
    scan_id: str,
    payload: ImportScanRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ImportResultResponse:
    try:
        return run_import_job(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            request=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_import_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/jobs/{job_id}/recover", response_model=ImportResultResponse)
def recover_import_route(
    job_id: str,
    payload: ImportRecoverRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ImportResultResponse:
    try:
        return recover_import_job(
            db,
            actor_session=current_session,
            job_id=job_id,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_import_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc
