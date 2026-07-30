from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.integrations.nessus.client import NessusClientFactory, ScanHistorySummary
from backend.app.models.auth import UserSession
from backend.app.models.folder import FolderRecord
from backend.app.models.scan import ScanHistoryRecord, ScanRecord
from backend.app.schemas.scan import (
    ScanCloneRequest,
    ScanCreateRequest,
    ScanHistoryDeleteRequest,
    ScanHistoryListResponse,
    PolicyListResponse,
    PolicyResponse,
    ScanHistoryResponse,
    ScanMoveRequest,
    ScanResponse,
    ScanUpdateRequest,
    ScannerListResponse,
    ScannerResponse,
    TemplateListResponse,
    TemplateResponse,
)
from backend.app.services.audit import write_audit
from backend.app.services.auth import ensure_utc, utc_now
from backend.app.services.nessus import NessusConfigError, build_saved_nessus_client, ensure_nessus_role_access

HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
VALID_SCHEDULES = {"on_demand", "once", "daily", "weekly", "monthly"}
RUNNING_STATUSES = {"running", "queued", "pending", "resuming", "pausing"}
STOPPABLE_STATUSES = {"running", "queued", "pending", "resuming"}
NESSUS_SCAN_ROLE_ALLOWLIST = {"BASIC", "SCAN_MANAGER", "SYSTEM_ADMINISTRATOR"}


class ScanServiceError(ValueError):
    pass


SCAN_API_DISABLED_MESSAGE = "The connected Nessus scanner license reports scan_api=false, so scan create, clone, launch, stop, move and delete actions are unavailable on this scanner."


def _normalize_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ScanServiceError("Scan name is required.")
    return cleaned


def _normalize_schedule(schedule_type: str | None) -> str:
    schedule = (schedule_type or "on_demand").strip().lower()
    if schedule not in VALID_SCHEDULES:
        raise ScanServiceError("Unsupported schedule type.")
    return schedule


def _normalize_target(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ScanServiceError("Blank targets are not allowed.")
    try:
        if "/" in candidate:
            return str(ipaddress.ip_network(candidate, strict=False))
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        if "." in candidate:
            parts = candidate.split(".")
            if parts and all(part.isdigit() for part in parts):
                raise ScanServiceError(f"Invalid target '{value}'.")
        if HOSTNAME_PATTERN.match(candidate):
            return candidate.lower()
    raise ScanServiceError(f"Invalid target '{value}'.")


def normalize_targets(targets: list[str]) -> list[str]:
    if not targets:
        raise ScanServiceError("At least one target is required.")
    out: list[str] = []
    seen: set[str] = set()
    for item in targets:
        normalized = _normalize_target(item)
        if normalized not in seen:
            out.append(normalized)
            seen.add(normalized)
    if len(out) > 4096:
        raise ScanServiceError("Target count exceeds the current safety limit.")
    return out


def _from_unix_or_iso(value: Any) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            if value.isdigit():
                return datetime.fromtimestamp(int(value), tz=timezone.utc)
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _scan_to_response(scan: ScanRecord) -> ScanResponse:
    return ScanResponse(
        id=scan.id,
        nessus_scan_id=scan.nessus_scan_id,
        nessus_uuid=scan.nessus_uuid,
        name=scan.name,
        folder_record_id=scan.folder_record_id,
        folder_nessus_id=scan.folder_nessus_id,
        folder_name=scan.folder_name,
        template_uuid=scan.template_uuid,
        scanner_id=scan.scanner_id,
        targets=[item for item in scan.targets_text.split(",") if item],
        target_count=scan.target_count,
        schedule_type=scan.schedule_type,
        owner=scan.owner,
        status=scan.status,
        history_count=scan.history_count,
        permission_status=scan.permission_status,
        last_launch_at=ensure_utc(scan.last_launch_at).isoformat() if ensure_utc(scan.last_launch_at) else None,
        last_completion_at=ensure_utc(scan.last_completion_at).isoformat() if ensure_utc(scan.last_completion_at) else None,
        last_synchronized_at=ensure_utc(scan.last_synchronized_at).isoformat() if ensure_utc(scan.last_synchronized_at) else None,
        deleted_at=ensure_utc(scan.deleted_at).isoformat() if ensure_utc(scan.deleted_at) else None,
    )


def _history_to_response(history: ScanHistoryRecord) -> ScanHistoryResponse:
    started_at = ensure_utc(history.started_at)
    completed_at = ensure_utc(history.completed_at)
    deleted_at = ensure_utc(history.deleted_at)
    return ScanHistoryResponse(
        id=history.id,
        nessus_history_id=history.nessus_history_id,
        status=history.status,
        started_at=started_at.isoformat() if started_at else None,
        completed_at=completed_at.isoformat() if completed_at else None,
        finding_count=history.finding_count,
        is_baseline_locked=history.is_baseline_locked,
        is_evidence_locked=history.is_evidence_locked,
        deleted_at=deleted_at.isoformat() if deleted_at else None,
    )


def _require_folder(db: Session, folder_record_id: str) -> FolderRecord:
    folder = db.get(FolderRecord, folder_record_id)
    if folder is None or folder.deleted_at is not None:
        raise ScanServiceError("Destination folder was not found.")
    return folder


def _require_scan_api(config) -> None:
    if config.capabilities.get("scans.api") is False:
        raise ScanServiceError(SCAN_API_DISABLED_MESSAGE)


def _upsert_scan(db: Session, payload: dict[str, Any]) -> ScanRecord:
    info = payload.get("info") if isinstance(payload.get("info"), dict) else payload
    if not isinstance(info, dict):
        raise ScanServiceError("Nessus did not return scan information.")
    scan_id = info.get("object_id") or info.get("scan_id") or info.get("id")
    if scan_id is None:
        raise ScanServiceError("Nessus did not return a scan identifier.")
    scan_uuid = info.get("uuid") or payload.get("uuid") or ""
    folder_nessus_id = str(info.get("folder_id") or payload.get("folder_id") or "")
    folder = db.scalar(select(FolderRecord).where(FolderRecord.nessus_folder_id == folder_nessus_id))
    existing = db.scalar(select(ScanRecord).where(ScanRecord.nessus_scan_id == str(scan_id)))
    if existing is None:
        existing = ScanRecord(nessus_scan_id=str(scan_id))
        db.add(existing)
    existing.nessus_uuid = str(scan_uuid or "")
    existing.name = str(info.get("name") or payload.get("name") or existing.name or "")
    existing.folder_nessus_id = folder_nessus_id
    existing.folder_record_id = folder.id if folder is not None else None
    existing.folder_name = folder.name if folder is not None else str(info.get("folder_name") or "")
    existing.template_uuid = str(payload.get("template_uuid") or payload.get("uuid") or existing.template_uuid or "")
    existing.scanner_id = str(info.get("scanner_id") or payload.get("scanner_id") or "")
    targets_text = info.get("targets") or info.get("text_targets") or ""
    if isinstance(targets_text, list):
        targets_text = ",".join(str(item).strip() for item in targets_text if str(item).strip())
    existing.targets_text = str(targets_text)
    existing.target_count = len([item for item in existing.targets_text.split(",") if item.strip()])
    existing.schedule_type = str(info.get("schedule_type") or payload.get("schedule_type") or existing.schedule_type or "on_demand")
    existing.owner = str(info.get("owner") or "")
    existing.status = str(info.get("status") or payload.get("status") or existing.status or "unknown").lower()
    history = payload.get("history") or payload.get("histories") or []
    existing.history_count = len(history) if isinstance(history, list) else existing.history_count
    existing.permission_status = "available"
    existing.last_launch_at = _from_unix_or_iso(info.get("last_modification_date") or info.get("last_modification")) or existing.last_launch_at
    existing.last_completion_at = _from_unix_or_iso(info.get("completed_at") or info.get("readable_last_modification_date")) or existing.last_completion_at
    existing.last_synchronized_at = utc_now()
    existing.deleted_at = None
    return existing


def _sync_histories(db: Session, scan: ScanRecord, history_rows: list[ScanHistorySummary]) -> list[ScanHistoryRecord]:
    seen_ids = {str(row.history_id) for row in history_rows if row.history_id is not None}
    for remote in history_rows:
        if remote.history_id is None:
            continue
        existing = db.scalar(
            select(ScanHistoryRecord).where(
                ScanHistoryRecord.scan_record_id == scan.id,
                ScanHistoryRecord.nessus_history_id == str(remote.history_id),
            )
        )
        if existing is None:
            existing = ScanHistoryRecord(scan_record_id=scan.id, nessus_history_id=str(remote.history_id))
            db.add(existing)
        existing.status = str(remote.status or "unknown").lower()
        existing.started_at = _from_unix_or_iso(remote.creation_date)
        existing.completed_at = _from_unix_or_iso(remote.last_modification_date)
        existing.deleted_at = None
    local_rows = db.scalars(select(ScanHistoryRecord).where(ScanHistoryRecord.scan_record_id == scan.id)).all()
    for local in local_rows:
        if local.nessus_history_id not in seen_ids and local.deleted_at is None:
            local.deleted_at = utc_now()
    scan.history_count = len(seen_ids)
    return local_rows


def list_scan_templates(db: Session, *, client_factory: NessusClientFactory) -> TemplateListResponse:
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    templates = [TemplateResponse(uuid=item.uuid, title=item.title or item.name or item.uuid) for item in client.list_templates()]
    return TemplateListResponse(templates=templates)


def list_scan_policies(db: Session, *, client_factory: NessusClientFactory) -> PolicyListResponse:
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    policies = [
        PolicyResponse(
            id=str(item.id or ""),
            name=item.name,
            template_uuid=str(item.template_uuid or ""),
            owner=str(item.owner or ""),
            has_credentials=bool(item.has_credentials),
        )
        for item in client.list_policies()
    ]
    return PolicyListResponse(policies=policies)


def list_scanners(db: Session, *, client_factory: NessusClientFactory) -> ScannerListResponse:
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    scanners = [
        ScannerResponse(id=str(item.id or ""), name=item.name, type=str(item.type or ""), status=str(item.status or "unknown"))
        for item in client.list_scanners()
    ]
    return ScannerListResponse(scanners=scanners)


def refresh_scans(db: Session, *, actor_session: UserSession, source_ip: str, client_factory: NessusClientFactory) -> list[ScanResponse]:
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    remote_scans = client.list_scans()
    remote_ids = {str(item.id) for item in remote_scans if item.id is not None}
    for remote in remote_scans:
        if remote.id is None:
            continue
        details = client.get_scan_details(str(remote.id))
        details["template_uuid"] = ""
        _upsert_scan(db, details)
    local_scans = db.scalars(select(ScanRecord)).all()
    for local in local_scans:
        if local.nessus_scan_id not in remote_ids and local.deleted_at is None:
            local.deleted_at = utc_now()
            local.last_synchronized_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.sync",
        object_type="scan_inventory",
        source_ip=source_ip,
        new_state={"scan_count": len(remote_scans)},
    )
    db.commit()
    return list_scans(db)


def list_scans(db: Session, *, search: str = "") -> list[ScanResponse]:
    statement = select(ScanRecord).order_by(ScanRecord.name)
    cleaned = search.strip()
    if cleaned:
        statement = statement.where(
            or_(
                ScanRecord.name.ilike(f"%{cleaned}%"),
                ScanRecord.nessus_scan_id.ilike(f"%{cleaned}%"),
                ScanRecord.folder_name.ilike(f"%{cleaned}%"),
            )
        )
    scans = db.scalars(statement).all()
    return [_scan_to_response(item) for item in scans]


def _create_settings_payload(*, name: str, remote_folder_id: str, scanner_id: str | None, targets: list[str], schedule_type: str) -> dict[str, Any]:
    settings: dict[str, Any] = {
        "name": name,
        "folder_id": remote_folder_id,
        "text_targets": ",".join(targets),
        "schedule_type": schedule_type,
    }
    if scanner_id:
        settings["scanner_id"] = scanner_id
    return settings


def _create_policy_settings_payload(*, name: str, remote_folder_id: str, policy_id: str, scanner_id: str | None, targets: list[str], schedule_type: str) -> dict[str, Any]:
    settings = _create_settings_payload(
        name=name,
        remote_folder_id=remote_folder_id,
        scanner_id=scanner_id,
        targets=targets,
        schedule_type=schedule_type,
    )
    settings["policy_id"] = int(policy_id)
    settings["enabled"] = schedule_type != "on_demand"
    settings["launch"] = {
        "on_demand": "ON_DEMAND",
        "once": "ON_DEMAND",
        "daily": "DAILY",
        "weekly": "WEEKLY",
        "monthly": "MONTHLY",
    }.get(schedule_type, "ON_DEMAND")
    return settings


def create_scan(db: Session, *, actor_session: UserSession, payload: ScanCreateRequest, source_ip: str, client_factory: NessusClientFactory) -> ScanResponse:
    name = _normalize_name(payload.name)
    create_from_clone = bool(payload.clone_from_scan_record_id)
    create_from_policy = bool(payload.policy_id)
    create_from_template = bool(payload.template_uuid)
    selected_modes = sum(1 for item in (create_from_clone, create_from_policy, create_from_template) if item)
    if selected_modes != 1:
        raise ScanServiceError("Select exactly one scan source: template, policy or master template.")
    folder = _require_folder(db, payload.folder_record_id)
    if create_from_clone:
        return clone_scan(
            db,
            actor_session=actor_session,
            scan_record_id=payload.clone_from_scan_record_id or "",
            payload=ScanCloneRequest(
                name=name,
                folder_record_id=payload.folder_record_id,
                scanner_id=payload.scanner_id,
                launch_now=payload.launch_now,
            ),
            source_ip=source_ip,
            client_factory=client_factory,
        )

    schedule_type = _normalize_schedule(payload.schedule_type)
    targets = normalize_targets(payload.targets)
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)

    selected_template_uuid = payload.template_uuid or ""
    if create_from_policy:
        policies = {str(item.id or ""): item for item in client.list_policies() if item.id is not None}
        selected_policy = policies.get(payload.policy_id or "")
        if selected_policy is None:
            raise ScanServiceError("Selected policy was not found in Nessus.")
        if not selected_policy.template_uuid:
            raise ScanServiceError("Selected policy does not expose a template UUID.")
        selected_template_uuid = str(selected_policy.template_uuid)
        create_payload = {
            "uuid": selected_template_uuid,
            "settings": _create_policy_settings_payload(
                name=name,
                remote_folder_id=folder.nessus_folder_id,
                policy_id=payload.policy_id or "",
                scanner_id=payload.scanner_id,
                targets=targets,
                schedule_type=schedule_type,
            ),
        }
    else:
        create_payload = {
            "uuid": payload.template_uuid,
            "settings": _create_settings_payload(
                name=name,
                remote_folder_id=folder.nessus_folder_id,
                scanner_id=payload.scanner_id,
                targets=targets,
                schedule_type=schedule_type,
            ),
        }
    created = client.create_scan(create_payload)
    scan_id = created.get("scan", {}).get("id") or created.get("scan_id") or created.get("id")
    if scan_id is None:
        raise ScanServiceError("Nessus did not return a scan identifier.")
    details = client.get_scan_details(str(scan_id))
    details["template_uuid"] = selected_template_uuid
    scan = _upsert_scan(db, details)
    if payload.launch_now:
        client.launch_scan(str(scan_id))
        scan.status = "running"
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.create",
        object_type="scan",
        object_id=str(scan_id),
        object_name=name,
        source_ip=source_ip,
        new_state={"folder_nessus_id": folder.nessus_folder_id, "target_count": len(targets), "schedule_type": schedule_type},
    )
    db.commit()
    db.refresh(scan)
    return _scan_to_response(scan)


def update_scan(db: Session, *, actor_session: UserSession, scan_record_id: str, payload: ScanUpdateRequest, source_ip: str, client_factory: NessusClientFactory) -> ScanResponse:
    scan = db.get(ScanRecord, scan_record_id)
    if scan is None or scan.deleted_at is not None:
        raise ScanServiceError("Scan not found.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)
    folder = _require_folder(db, payload.folder_record_id) if payload.folder_record_id else db.get(FolderRecord, scan.folder_record_id) if scan.folder_record_id else None
    name = _normalize_name(payload.name) if payload.name is not None else scan.name
    targets = normalize_targets(payload.targets) if payload.targets is not None else [item for item in scan.targets_text.split(",") if item]
    schedule_type = _normalize_schedule(payload.schedule_type) if payload.schedule_type is not None else scan.schedule_type
    update_payload = {
        "settings": _create_settings_payload(
            name=name,
            remote_folder_id=(folder.nessus_folder_id if folder is not None else scan.folder_nessus_id),
            scanner_id=payload.scanner_id or scan.scanner_id or None,
            targets=targets,
            schedule_type=schedule_type,
        )
    }
    client.update_scan(scan.nessus_scan_id, update_payload)
    details = client.get_scan_details(scan.nessus_scan_id)
    details["template_uuid"] = scan.template_uuid
    previous = {"name": scan.name, "folder_nessus_id": scan.folder_nessus_id, "status": scan.status}
    scan = _upsert_scan(db, details)
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.edit",
        object_type="scan",
        object_id=scan.nessus_scan_id,
        object_name=scan.name,
        source_ip=source_ip,
        previous_state=previous,
        new_state={"name": scan.name, "folder_nessus_id": scan.folder_nessus_id, "schedule_type": scan.schedule_type},
    )
    db.commit()
    db.refresh(scan)
    return _scan_to_response(scan)


def move_scan(db: Session, *, actor_session: UserSession, scan_record_id: str, payload: ScanMoveRequest, source_ip: str, client_factory: NessusClientFactory) -> ScanResponse:
    return update_scan(
        db,
        actor_session=actor_session,
        scan_record_id=scan_record_id,
        payload=ScanUpdateRequest(folder_record_id=payload.folder_record_id),
        source_ip=source_ip,
        client_factory=client_factory,
    )


def clone_scan(db: Session, *, actor_session: UserSession, scan_record_id: str, payload: ScanCloneRequest, source_ip: str, client_factory: NessusClientFactory) -> ScanResponse:
    source_scan = db.get(ScanRecord, scan_record_id)
    if source_scan is None or source_scan.deleted_at is not None:
        raise ScanServiceError("Scan not found.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)
    client.copy_scan(source_scan.nessus_scan_id, {"name": _normalize_name(payload.name)})
    refresh_scans(db, actor_session=actor_session, source_ip=source_ip, client_factory=client_factory)
    cloned = db.scalar(select(ScanRecord).where(ScanRecord.name == payload.name, ScanRecord.deleted_at.is_(None)))
    if cloned is None:
        raise ScanServiceError("Cloned scan could not be synchronized.")
    if payload.folder_record_id or payload.scanner_id:
        cloned = db.get(ScanRecord, cloned.id)
        cloned_response = update_scan(
            db,
            actor_session=actor_session,
            scan_record_id=cloned.id,
            payload=ScanUpdateRequest(folder_record_id=payload.folder_record_id, scanner_id=payload.scanner_id),
            source_ip=source_ip,
            client_factory=client_factory,
        )
    else:
        cloned_response = _scan_to_response(cloned)
    if payload.launch_now:
        launch_scan(db, actor_session=actor_session, scan_record_id=cloned.id, source_ip=source_ip, client_factory=client_factory)
        cloned = db.get(ScanRecord, cloned.id)
        cloned_response = _scan_to_response(cloned)
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.clone",
        object_type="scan",
        object_id=source_scan.nessus_scan_id,
        object_name=source_scan.name,
        source_ip=source_ip,
        new_state={"cloned_name": payload.name},
    )
    db.commit()
    return cloned_response


def launch_scan(db: Session, *, actor_session: UserSession, scan_record_id: str, source_ip: str, client_factory: NessusClientFactory) -> ScanResponse:
    scan = db.get(ScanRecord, scan_record_id)
    if scan is None or scan.deleted_at is not None:
        raise ScanServiceError("Scan not found.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)
    if scan.target_count <= 0:
        details = client.get_scan_details(scan.nessus_scan_id)
        details["template_uuid"] = scan.template_uuid
        scan = _upsert_scan(db, details)
    if scan.target_count <= 0:
        raise ScanServiceError("Scan has no targets configured.")
    if scan.status in RUNNING_STATUSES:
        raise ScanServiceError("Scan is already running or queued.")
    client.launch_scan(scan.nessus_scan_id)
    scan.status = "running"
    scan.last_launch_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.launch",
        object_type="scan",
        object_id=scan.nessus_scan_id,
        object_name=scan.name,
        source_ip=source_ip,
        new_state={"status": "running"},
    )
    db.commit()
    db.refresh(scan)
    return _scan_to_response(scan)


def stop_scan(db: Session, *, actor_session: UserSession, scan_record_id: str, source_ip: str, client_factory: NessusClientFactory) -> ScanResponse:
    scan = db.get(ScanRecord, scan_record_id)
    if scan is None or scan.deleted_at is not None:
        raise ScanServiceError("Scan not found.")
    if scan.status not in STOPPABLE_STATUSES:
        raise ScanServiceError("Only running or queued scans can be stopped.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)
    client.stop_scan(scan.nessus_scan_id)
    scan.status = "stopped"
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.stop",
        object_type="scan",
        object_id=scan.nessus_scan_id,
        object_name=scan.name,
        source_ip=source_ip,
        new_state={"status": "stopped"},
    )
    db.commit()
    db.refresh(scan)
    return _scan_to_response(scan)


def trash_scan(db: Session, *, actor_session: UserSession, scan_record_id: str, source_ip: str, client_factory: NessusClientFactory) -> None:
    scan = db.get(ScanRecord, scan_record_id)
    if scan is None or scan.deleted_at is not None:
        raise ScanServiceError("Scan not found.")
    if scan.status in RUNNING_STATUSES:
        raise ScanServiceError("Running scans cannot be moved to Trash.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)
    client.delete_scan(scan.nessus_scan_id)
    scan.deleted_at = utc_now()
    scan.last_synchronized_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.trash",
        object_type="scan",
        object_id=scan.nessus_scan_id,
        object_name=scan.name,
        source_ip=source_ip,
        previous_state={"status": scan.status},
        new_state={"deleted": True},
    )
    db.commit()


def list_scan_history(db: Session, *, scan_record_id: str, client_factory: NessusClientFactory) -> ScanHistoryListResponse:
    scan = db.get(ScanRecord, scan_record_id)
    if scan is None or scan.deleted_at is not None:
        raise ScanServiceError("Scan not found.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    remote_histories = client.get_scan_history(scan.nessus_scan_id)
    _sync_histories(db, scan, remote_histories)
    db.commit()
    rows = db.scalars(select(ScanHistoryRecord).where(ScanHistoryRecord.scan_record_id == scan.id).order_by(ScanHistoryRecord.started_at.desc())).all()
    return ScanHistoryListResponse(histories=[_history_to_response(row) for row in rows])


def delete_scan_history(
    db: Session,
    *,
    actor_session: UserSession,
    scan_record_id: str,
    history_record_id: str,
    payload: ScanHistoryDeleteRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> None:
    scan = db.get(ScanRecord, scan_record_id)
    history = db.get(ScanHistoryRecord, history_record_id)
    if scan is None or scan.deleted_at is not None or history is None or history.scan_record_id != scan.id:
        raise ScanServiceError("Scan history not found.")
    if history.deleted_at is not None:
        raise ScanServiceError("Scan history is already deleted.")
    if history.is_baseline_locked or history.is_evidence_locked:
        raise ScanServiceError("Protected scan history cannot be deleted.")
    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_SCAN_ROLE_ALLOWLIST)
    _require_scan_api(config)
    client.delete_scan_history(scan.nessus_scan_id, history.nessus_history_id)
    history.deleted_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="scans.history.delete",
        object_type="scan_history",
        object_id=history.nessus_history_id,
        object_name=scan.name,
        source_ip=source_ip,
        justification=payload.justification,
        previous_state={"status": history.status, "finding_count": history.finding_count},
        new_state={"deleted": True},
    )
    db.commit()
