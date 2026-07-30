from __future__ import annotations

import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.core.security import verify_password
from backend.app.integrations.nessus.client import FolderSummary, NessusClientFactory
from backend.app.models.auth import UserSession
from backend.app.models.folder import FolderRecord
from backend.app.schemas.folder import FolderCreateRequest, FolderDeleteRequest, FolderDeletePreviewResponse, FolderRenameRequest, FolderResponse
from backend.app.services.audit import write_audit
from backend.app.services.auth import ensure_utc, utc_now
from backend.app.services.nessus import NessusConfigError, build_saved_nessus_client, ensure_nessus_role_access

NESSUS_FOLDER_ROLE_ALLOWLIST = {"BASIC", "SCAN_MANAGER", "SYSTEM_ADMINISTRATOR"}


class FolderServiceError(ValueError):
    pass


FOLDER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def _normalize_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise FolderServiceError("Folder name is required.")
    if not FOLDER_NAME_PATTERN.fullmatch(cleaned):
        raise FolderServiceError("Folder names may contain only letters, numbers, dots, underscores and hyphens.")
    return cleaned


def _to_response(folder: FolderRecord) -> FolderResponse:
    last_sync = ensure_utc(folder.last_synchronized_at)
    deleted_at = ensure_utc(folder.deleted_at)
    return FolderResponse(
        id=folder.id,
        nessus_folder_id=folder.nessus_folder_id,
        name=folder.name,
        folder_type=folder.folder_type,
        is_custom=folder.is_custom,
        owner=folder.owner,
        permission_status=folder.permission_status,
        scan_count=folder.scan_count,
        last_synchronized_at=last_sync.isoformat() if last_sync else None,
        deleted_at=deleted_at.isoformat() if deleted_at else None,
    )


def _upsert_folder(db: Session, remote: FolderSummary, *, scan_count: int, permission_status: str) -> FolderRecord:
    remote_id = str(remote.id)
    existing = db.scalar(select(FolderRecord).where(FolderRecord.nessus_folder_id == remote_id))
    if existing is None:
        existing = FolderRecord(nessus_folder_id=remote_id)
        db.add(existing)
    existing.name = remote.name
    existing.folder_type = remote.type or ""
    existing.is_custom = bool(remote.custom)
    existing.owner = remote.owner or ""
    existing.permission_status = permission_status
    existing.scan_count = scan_count
    existing.last_synchronized_at = utc_now()
    existing.deleted_at = None
    return existing


def sync_folders(
    db: Session,
    *,
    actor_session: UserSession,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> list[FolderResponse]:
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_FOLDER_ROLE_ALLOWLIST)
    remote_folders = client.list_folders()
    remote_scans = client.list_scans()
    remote_ids = {str(folder.id) for folder in remote_folders if folder.id is not None}
    scan_counts: dict[str, int] = {}
    for scan in remote_scans:
        folder_id = str(scan.folder_id) if scan.folder_id is not None else ""
        if folder_id:
            scan_counts[folder_id] = scan_counts.get(folder_id, 0) + 1
    local_folders = db.scalars(select(FolderRecord)).all()
    local_by_remote = {folder.nessus_folder_id: folder for folder in local_folders}
    for remote in remote_folders:
        if remote.id is None:
            continue
        permission_status = "available" if config.capabilities.get("folders.list", False) else "unknown"
        _upsert_folder(db, remote, scan_count=scan_counts.get(str(remote.id), 0), permission_status=permission_status)
    for local in local_folders:
        if local.nessus_folder_id not in remote_ids and local.deleted_at is None:
            local.deleted_at = utc_now()
            local.last_synchronized_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="folders.sync",
        object_type="folder_inventory",
        source_ip=source_ip,
        new_state={"folder_count": len(remote_folders)},
    )
    db.commit()
    folders = db.scalars(select(FolderRecord).order_by(FolderRecord.name)).all()
    return [_to_response(folder) for folder in folders]


def list_folders(db: Session, *, search: str = "") -> list[FolderResponse]:
    statement = select(FolderRecord).order_by(FolderRecord.name)
    cleaned = search.strip()
    if cleaned:
        statement = statement.where(or_(FolderRecord.name.ilike(f"%{cleaned}%"), FolderRecord.nessus_folder_id.ilike(f"%{cleaned}%")))
    folders = db.scalars(statement).all()
    return [_to_response(folder) for folder in folders]


def create_folder(
    db: Session,
    *,
    actor_session: UserSession,
    payload: FolderCreateRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> FolderResponse:
    name = _normalize_name(payload.name)
    duplicate = db.scalar(
        select(FolderRecord).where(FolderRecord.deleted_at.is_(None), FolderRecord.name.ilike(name))
    )
    if duplicate is not None:
        raise FolderServiceError("A folder with that name already exists.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_FOLDER_ROLE_ALLOWLIST)
    remote = client.create_folder(name)
    if remote.id is None:
        raise FolderServiceError("Nessus did not return a folder identifier.")
    folder = _upsert_folder(db, remote, scan_count=0, permission_status="available")
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="folders.create",
        object_type="folder",
        object_id=str(remote.id),
        object_name=name,
        source_ip=source_ip,
        new_state={"name": name, "nessus_folder_id": str(remote.id)},
    )
    db.commit()
    db.refresh(folder)
    return _to_response(folder)


def rename_folder(
    db: Session,
    *,
    actor_session: UserSession,
    folder_id: str,
    payload: FolderRenameRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> FolderResponse:
    folder = db.get(FolderRecord, folder_id)
    if folder is None or folder.deleted_at is not None:
        raise FolderServiceError("Folder not found.")
    if not folder.is_custom:
        raise FolderServiceError("Only custom folders can be renamed.")
    new_name = _normalize_name(payload.name)
    duplicate = db.scalar(
        select(FolderRecord).where(
            FolderRecord.id != folder.id,
            FolderRecord.deleted_at.is_(None),
            FolderRecord.name.ilike(new_name),
        )
    )
    if duplicate is not None:
        raise FolderServiceError("A folder with that name already exists.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_FOLDER_ROLE_ALLOWLIST)
    previous_name = folder.name
    remote = client.rename_folder(folder.nessus_folder_id, new_name)
    folder.name = remote.name or new_name
    folder.folder_type = remote.type or folder.folder_type
    folder.last_synchronized_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="folders.rename",
        object_type="folder",
        object_id=folder.nessus_folder_id,
        object_name=folder.name,
        source_ip=source_ip,
        previous_state={"name": previous_name},
        new_state={"name": folder.name},
    )
    db.commit()
    db.refresh(folder)
    return _to_response(folder)


def get_folder_delete_preview(
    db: Session,
    *,
    folder_id: str,
    client_factory: NessusClientFactory,
) -> FolderDeletePreviewResponse:
    folder = db.get(FolderRecord, folder_id)
    if folder is None or folder.deleted_at is not None:
        raise FolderServiceError("Folder not found.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_FOLDER_ROLE_ALLOWLIST)
    scans = [
        scan.model_dump()
        for scan in client.list_scans()
        if str(scan.folder_id) == folder.nessus_folder_id
    ]
    return FolderDeletePreviewResponse(
        folder=_to_response(folder),
        affected_scans=scans,
        deletion_behavior="Deleting a custom folder moves contained scans to Trash in Tenable Vulnerability Management.",
    )


def delete_folder(
    db: Session,
    *,
    actor_session: UserSession,
    folder_id: str,
    payload: FolderDeleteRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> None:
    folder = db.get(FolderRecord, folder_id)
    if folder is None or folder.deleted_at is not None:
        raise FolderServiceError("Folder not found.")
    if not folder.is_custom:
        raise FolderServiceError("System or protected folders cannot be deleted.")
    if payload.confirmation_name.strip() != folder.name:
        raise FolderServiceError("Folder confirmation name did not match.")
    if not verify_password(payload.current_password, actor_session.user.password_hash):
        raise FolderServiceError("Current password is invalid.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_FOLDER_ROLE_ALLOWLIST)
    affected_scans = [
        scan.model_dump()
        for scan in client.list_scans()
        if str(scan.folder_id) == folder.nessus_folder_id
    ]
    actor_session.reauthenticated_at = utc_now()
    client.delete_folder(folder.nessus_folder_id)
    folder.deleted_at = utc_now()
    folder.last_synchronized_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="folders.delete",
        object_type="folder",
        object_id=folder.nessus_folder_id,
        object_name=folder.name,
        source_ip=source_ip,
        previous_state={"name": folder.name, "affected_scans": affected_scans},
        new_state={"deleted": True},
    )
    db.commit()
