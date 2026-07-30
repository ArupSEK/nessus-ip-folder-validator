from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import get_nessus_client_factory, get_source_ip, require_csrf, require_permissions
from backend.app.db.session import get_db
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.schemas.auth import GenericMessage
from backend.app.schemas.scan import (
    PolicyListResponse,
    ScanCloneRequest,
    ScanCreateRequest,
    ScanHistoryDeleteRequest,
    ScanHistoryListResponse,
    ScanListResponse,
    ScanMoveRequest,
    ScanResponse,
    ScanUpdateRequest,
    ScannerListResponse,
    TemplateListResponse,
)
from backend.app.services.nessus import NessusConfigError, translate_nessus_error
from backend.app.services.scans import (
    ScanServiceError,
    clone_scan,
    create_scan,
    delete_scan_history,
    launch_scan,
    list_scan_policies,
    list_scan_history,
    list_scan_templates,
    list_scanners,
    list_scans,
    move_scan,
    refresh_scans,
    stop_scan,
    trash_scan,
    update_scan,
)

router = APIRouter(tags=["scans"])


def _translate_scan_error(exc: Exception) -> tuple[int, str]:
    if isinstance(exc, (ScanServiceError, NessusConfigError)):
        return 400, str(exc)
    return translate_nessus_error(exc)


@router.get("", response_model=ScanListResponse)
def get_scans(
    search: str = Query(default=""),
    _: object = Depends(require_permissions("scans.view")),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    return ScanListResponse(scans=list_scans(db, search=search))


@router.post("/refresh", response_model=ScanListResponse)
def refresh_scans_route(
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.view")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanListResponse:
    try:
        scans = refresh_scans(
            db,
            actor_session=current_session,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
        return ScanListResponse(scans=scans)
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.get("/templates", response_model=TemplateListResponse)
def get_templates(
    _: object = Depends(require_permissions("scans.create")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> TemplateListResponse:
    try:
        return list_scan_templates(db, client_factory=client_factory)
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.get("/policies", response_model=PolicyListResponse)
def get_policies(
    _: object = Depends(require_permissions("scans.create")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> PolicyListResponse:
    try:
        return list_scan_policies(db, client_factory=client_factory)
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.get("/scanners", response_model=ScannerListResponse)
def get_scanners(
    _: object = Depends(require_permissions("scans.create")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScannerListResponse:
    try:
        return list_scanners(db, client_factory=client_factory)
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("", response_model=ScanResponse)
def create_scan_route(
    payload: ScanCreateRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.create")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanResponse:
    try:
        return create_scan(
            db,
            actor_session=current_session,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan_route(
    scan_id: str,
    payload: ScanUpdateRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.edit")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanResponse:
    try:
        return update_scan(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{scan_id}/clone", response_model=ScanResponse)
def clone_scan_route(
    scan_id: str,
    payload: ScanCloneRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.clone")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanResponse:
    try:
        return clone_scan(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{scan_id}/move", response_model=ScanResponse)
def move_scan_route(
    scan_id: str,
    payload: ScanMoveRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.move")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanResponse:
    try:
        return move_scan(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{scan_id}/launch", response_model=ScanResponse)
def launch_scan_route(
    scan_id: str,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.launch")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanResponse:
    try:
        return launch_scan(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{scan_id}/stop", response_model=ScanResponse)
def stop_scan_route(
    scan_id: str,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.stop")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanResponse:
    try:
        return stop_scan(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{scan_id}/trash", response_model=GenericMessage)
def trash_scan_route(
    scan_id: str,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scans.delete")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> GenericMessage:
    try:
        trash_scan(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc
    return GenericMessage(message="Scan moved to Trash.")


@router.get("/{scan_id}/history", response_model=ScanHistoryListResponse)
def get_history_route(
    scan_id: str,
    _: object = Depends(require_permissions("scan_history.view")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> ScanHistoryListResponse:
    try:
        return list_scan_history(db, scan_record_id=scan_id, client_factory=client_factory)
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{scan_id}/history/{history_id}/delete", response_model=GenericMessage)
def delete_history_route(
    scan_id: str,
    history_id: str,
    payload: ScanHistoryDeleteRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("scan_history.delete")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> GenericMessage:
    try:
        delete_scan_history(
            db,
            actor_session=current_session,
            scan_record_id=scan_id,
            history_record_id=history_id,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_scan_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc
    return GenericMessage(message="Scan history deleted.")
