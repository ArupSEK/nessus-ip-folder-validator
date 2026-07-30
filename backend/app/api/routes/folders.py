from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_session, get_nessus_client_factory, get_source_ip, require_csrf, require_permissions
from backend.app.db.session import get_db
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.schemas.auth import GenericMessage
from backend.app.schemas.folder import (
    FolderCreateRequest,
    FolderDeletePreviewResponse,
    FolderDeleteRequest,
    FolderListResponse,
    FolderRenameRequest,
    FolderResponse,
)
from backend.app.services.folders import (
    FolderServiceError,
    create_folder,
    delete_folder,
    get_folder_delete_preview,
    list_folders,
    rename_folder,
    sync_folders,
)
from backend.app.services.nessus import NessusConfigError, translate_nessus_error

router = APIRouter(tags=["folders"])


def _translate_folder_error(exc: Exception) -> tuple[int, str]:
    if isinstance(exc, FolderServiceError):
        return 400, str(exc)
    if isinstance(exc, NessusConfigError):
        return 400, str(exc)
    return translate_nessus_error(exc)


@router.get("", response_model=FolderListResponse)
def get_folders(
    search: str = Query(default=""),
    _: object = Depends(require_permissions("folders.view")),
    db: Session = Depends(get_db),
) -> FolderListResponse:
    return FolderListResponse(folders=list_folders(db, search=search))


@router.post("/refresh", response_model=FolderListResponse)
def refresh_folders(
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("folders.view")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> FolderListResponse:
    try:
        folders = sync_folders(
            db,
            actor_session=current_session,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
        return FolderListResponse(folders=folders)
    except Exception as exc:
        status_code, detail = _translate_folder_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("", response_model=FolderResponse)
def create_folder_route(
    payload: FolderCreateRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("folders.create")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> FolderResponse:
    try:
        return create_folder(
            db,
            actor_session=current_session,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_folder_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.put("/{folder_id}", response_model=FolderResponse)
def rename_folder_route(
    folder_id: str,
    payload: FolderRenameRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("folders.rename")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> FolderResponse:
    try:
        return rename_folder(
            db,
            actor_session=current_session,
            folder_id=folder_id,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_folder_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.get("/{folder_id}/delete-preview", response_model=FolderDeletePreviewResponse)
def delete_preview_route(
    folder_id: str,
    _: object = Depends(require_permissions("folders.delete")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> FolderDeletePreviewResponse:
    try:
        return get_folder_delete_preview(db, folder_id=folder_id, client_factory=client_factory)
    except Exception as exc:
        status_code, detail = _translate_folder_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.post("/{folder_id}/delete", response_model=GenericMessage)
def delete_folder_route(
    folder_id: str,
    payload: FolderDeleteRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("folders.delete")),
    db: Session = Depends(get_db),
    client_factory: NessusClientFactory = Depends(get_nessus_client_factory),
) -> GenericMessage:
    try:
        delete_folder(
            db,
            actor_session=current_session,
            folder_id=folder_id,
            payload=payload,
            source_ip=get_source_ip(request),
            client_factory=client_factory,
        )
    except Exception as exc:
        status_code, detail = _translate_folder_error(exc)
        raise HTTPException(status_code=status_code, detail=detail) from exc
    return GenericMessage(message="Folder deleted.")
