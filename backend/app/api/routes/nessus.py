from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import get_nessus_client_factory, get_source_ip, require_csrf, require_superuser
from backend.app.db.session import get_db
from backend.app.schemas.auth import GenericMessage
from backend.app.schemas.nessus import (
    NessusConfigurationResetRequest,
    NessusConfigurationResponse,
    NessusConfigurationSaveRequest,
    NessusConfigurationTestRequest,
    NessusValidationResponse,
)
from backend.app.services.nessus import (
    get_nessus_configuration,
    reset_nessus_configuration,
    save_nessus_configuration,
    test_nessus_configuration,
    translate_nessus_error,
)

router = APIRouter(tags=["nessus"])


@router.get("/configuration", response_model=NessusConfigurationResponse)
def get_configuration(
    _: object = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> NessusConfigurationResponse:
    return get_nessus_configuration(db)


@router.post("/configuration/test", response_model=NessusValidationResponse)
def test_configuration(
    payload: NessusConfigurationTestRequest,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> NessusValidationResponse:
    if not current_session.user.is_superuser:
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    try:
        return test_nessus_configuration(
            db,
            actor_session=current_session,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = translate_nessus_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.put("/configuration", response_model=NessusConfigurationResponse)
def save_configuration(
    payload: NessusConfigurationSaveRequest,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> NessusConfigurationResponse:
    if not current_session.user.is_superuser:
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    try:
        return save_nessus_configuration(
            db,
            actor_session=current_session,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = translate_nessus_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/configuration/reset", response_model=GenericMessage)
def reset_configuration(
    payload: NessusConfigurationResetRequest,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> GenericMessage:
    if not current_session.user.is_superuser:
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    try:
        reset_nessus_configuration(
            db,
            actor_session=current_session,
            payload=payload,
            source_ip=get_source_ip(request),
        )
    except Exception as exc:
        status_code, detail = translate_nessus_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc
    return GenericMessage(message="Nessus credentials reset.")
