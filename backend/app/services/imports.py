from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.models.asset import AssetRecord
from backend.app.models.auth import UserSession
from backend.app.models.finding import FindingRecord
from backend.app.models.import_job import ImportJob
from backend.app.models.scan import ScanHistoryRecord, ScanRecord
from backend.app.schemas.imports import AssetResponse, FindingResponse, ImportJobListResponse, ImportJobResponse, ImportResultResponse, ImportScanRequest
from backend.app.services.audit import write_audit
from backend.app.services.auth import ensure_utc, utc_now
from backend.app.services.nessus import NessusConfigError, build_saved_nessus_client, ensure_nessus_role_access
from backend.app.services.workflow import queue_ambiguous_asset_reviews, resolve_asset_key

NESSUS_IMPORT_ROLE_ALLOWLIST = {"SCAN_MANAGER", "SYSTEM_ADMINISTRATOR"}


class ImportServiceError(ValueError):
    pass


def _job_to_response(job: ImportJob) -> ImportJobResponse:
    return ImportJobResponse(
        id=job.id,
        scan_record_id=job.scan_record_id,
        scan_history_record_id=job.scan_history_record_id,
        status=job.status,
        progress_percent=job.progress_percent,
        export_format=job.export_format,
        export_file_id=job.export_file_id,
        export_status=job.export_status,
        imported_asset_count=job.imported_asset_count,
        imported_finding_count=job.imported_finding_count,
        error_message=job.error_message,
        last_checkpoint=job.last_checkpoint,
        created_at=ensure_utc(job.created_at).isoformat(),
        started_at=ensure_utc(job.started_at).isoformat() if ensure_utc(job.started_at) else None,
        completed_at=ensure_utc(job.completed_at).isoformat() if ensure_utc(job.completed_at) else None,
    )


def _asset_to_response(asset: AssetRecord) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        stable_asset_key=asset.stable_asset_key,
        hostname=asset.hostname,
        fqdn=asset.fqdn,
        ipv4_address=asset.ipv4_address,
        ipv6_address=asset.ipv6_address,
    )


def _finding_to_response(finding: FindingRecord) -> FindingResponse:
    return FindingResponse(
        id=finding.id,
        finding_key=finding.finding_key,
        asset_record_id=finding.asset_record_id,
        plugin_id=finding.plugin_id,
        plugin_name=finding.plugin_name,
        severity=finding.severity,
        port=finding.port,
        protocol=finding.protocol,
    )


def _scope_key(scan_record_id: str, scan_history_record_id: str | None) -> str:
    return f"{scan_record_id}:{scan_history_record_id or 'latest'}"


def _derive_asset_key(properties: dict[str, str], report_host_name: str) -> str:
    candidates = [
        properties.get("asset-uuid", ""),
        properties.get("agent-uuid", ""),
        properties.get("bios-uuid", ""),
        properties.get("mac-address", ""),
        properties.get("host-fqdn", ""),
        properties.get("hostname", ""),
        properties.get("host-ip", ""),
        report_host_name,
    ]
    for candidate in candidates:
        cleaned = candidate.strip().lower()
        if cleaned:
            return cleaned
    raise ImportServiceError("Asset key could not be determined from the Nessus export.")


def _derive_finding_key(asset_key: str, plugin_id: int, port: int, protocol: str) -> str:
    return f"{asset_key}:{plugin_id}:{port}:{protocol.lower()}"


def _apply_asset_key_overrides(db: Session, asset_rows: list[dict], finding_rows: list[dict]) -> None:
    for asset in asset_rows:
        asset["stable_asset_key"] = resolve_asset_key(db, asset["stable_asset_key"])
    for finding in finding_rows:
        asset_key = resolve_asset_key(db, finding["stable_asset_key"])
        finding["stable_asset_key"] = asset_key
        finding["finding_key"] = _derive_finding_key(asset_key, finding["plugin_id"], finding["port"], finding["protocol"])


def _text_or_empty(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def _parse_nessus_export(payload: bytes) -> tuple[list[dict], list[dict]]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ImportServiceError("The Nessus export could not be parsed.") from exc
    assets: list[dict] = []
    findings: list[dict] = []
    for report_host in root.findall(".//ReportHost"):
        report_host_name = report_host.attrib.get("name", "")
        properties: dict[str, str] = {}
        for tag in report_host.findall("./HostProperties/tag"):
            name = tag.attrib.get("name", "").strip().lower()
            if name:
                properties[name] = _text_or_empty(tag)
        asset_key = _derive_asset_key(properties, report_host_name)
        asset = {
            "stable_asset_key": asset_key,
            "tenable_asset_uuid": properties.get("asset-uuid", ""),
            "agent_uuid": properties.get("agent-uuid", ""),
            "bios_uuid": properties.get("bios-uuid", ""),
            "mac_address": properties.get("mac-address", ""),
            "fqdn": properties.get("host-fqdn", ""),
            "hostname": properties.get("hostname", report_host_name),
            "ipv4_address": properties.get("host-ip", ""),
            "ipv6_address": properties.get("host-ipv6", ""),
            "os_name": properties.get("operating-system", ""),
            "raw_metadata": json.dumps(properties, sort_keys=True),
        }
        assets.append(asset)
        for report_item in report_host.findall("./ReportItem"):
            plugin_id = int(report_item.attrib.get("pluginID", "0") or 0)
            port = int(report_item.attrib.get("port", "0") or 0)
            protocol = report_item.attrib.get("protocol", "")
            finding = {
                "finding_key": _derive_finding_key(asset_key, plugin_id, port, protocol),
                "stable_asset_key": asset_key,
                "plugin_id": plugin_id,
                "plugin_name": report_item.attrib.get("pluginName", ""),
                "severity": int(report_item.attrib.get("severity", "0") or 0),
                "port": port,
                "protocol": protocol,
                "plugin_family": report_item.attrib.get("pluginFamily", ""),
                "risk_factor": _text_or_empty(report_item.find("./risk_factor")),
                "synopsis": _text_or_empty(report_item.find("./synopsis")),
                "plugin_output": _text_or_empty(report_item.find("./plugin_output")),
                "state": "active",
            }
            findings.append(finding)
    return assets, findings


def _get_scan_and_history(db: Session, scan_record_id: str, scan_history_record_id: str | None) -> tuple[ScanRecord, ScanHistoryRecord | None]:
    scan = db.get(ScanRecord, scan_record_id)
    if scan is None or scan.deleted_at is not None:
        raise ImportServiceError("Scan not found.")
    history = None
    if scan_history_record_id:
        history = db.get(ScanHistoryRecord, scan_history_record_id)
        if history is None or history.scan_record_id != scan.id or history.deleted_at is not None:
            raise ImportServiceError("Scan history not found.")
    return scan, history


def list_import_jobs(db: Session) -> ImportJobListResponse:
    jobs = db.scalars(select(ImportJob).order_by(ImportJob.created_at.desc())).all()
    return ImportJobListResponse(jobs=[_job_to_response(job) for job in jobs])


def _mark_failed(job: ImportJob, message: str) -> None:
    job.status = "failed"
    job.error_message = message
    job.completed_at = utc_now()


def _poll_export_ready(client, scan_id: str, file_id: str) -> str:
    payload = client.get_scan_export_status(scan_id, file_id)
    return str(payload.get("status") or payload.get("state") or "unknown").lower()


def run_import_job(
    db: Session,
    *,
    actor_session: UserSession,
    scan_record_id: str,
    request: ImportScanRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> ImportResultResponse:
    scan, history = _get_scan_and_history(db, scan_record_id, request.scan_history_record_id)
    scope_key = _scope_key(scan.id, history.id if history else None)
    existing = db.scalar(select(ImportJob).where(ImportJob.job_scope_key == scope_key))
    if existing is not None and existing.status in {"queued", "running"}:
        raise ImportServiceError("An import for this scan scope is already running.")
    if existing is not None and existing.status == "completed" and not request.force_reimport:
        raise ImportServiceError("This scan scope has already been imported.")

    config, client = build_saved_nessus_client(db, client_factory=client_factory)
    ensure_nessus_role_access(config, NESSUS_IMPORT_ROLE_ALLOWLIST)

    if existing is None or request.force_reimport:
        job = ImportJob(
            scan_record_id=scan.id,
            scan_history_record_id=history.id if history else None,
            created_by_user_id=actor_session.user_id,
            job_scope_key=scope_key if existing is None else f"{scope_key}:{hashlib.sha256(str(utc_now()).encode('utf-8')).hexdigest()[:8]}",
        )
        db.add(job)
        db.flush()
    else:
        job = existing
        if job.status != "failed":
            raise ImportServiceError("Only failed jobs can be resumed without force_reimport.")
        job.status = "queued"
        job.progress_percent = 0
        job.error_message = ""
        job.export_file_id = ""
        job.export_status = ""
        job.imported_asset_count = 0
        job.imported_finding_count = 0
        job.last_checkpoint = ""
        job.started_at = None
        job.completed_at = None

    try:
        job.status = "running"
        job.started_at = utc_now()
        job.last_checkpoint = "request_export"
        job.progress_percent = 5
        db.flush()

        export_response = client.export_scan(scan.nessus_scan_id, history_id=history.nessus_history_id if history else None, export_format=job.export_format)
        file_id = export_response.get("file") or export_response.get("file_id") or export_response.get("export_uuid")
        if not file_id:
            raise ImportServiceError("Nessus did not return an export file identifier.")
        job.export_file_id = str(file_id)
        job.progress_percent = 20
        job.last_checkpoint = "poll_export"
        db.flush()

        export_status = _poll_export_ready(client, scan.nessus_scan_id, job.export_file_id)
        job.export_status = export_status
        if export_status not in {"ready", "completed"}:
            raise ImportServiceError(f"Nessus export is not ready. Current status: {export_status}.")
        job.progress_percent = 35
        job.last_checkpoint = "download_export"
        db.flush()

        export_payload = client.download_scan_export(scan.nessus_scan_id, job.export_file_id)
        job.progress_percent = 50
        job.last_checkpoint = "parse_export"
        db.flush()

        asset_rows, finding_rows = _parse_nessus_export(export_payload)
        _apply_asset_key_overrides(db, asset_rows, finding_rows)
        db.execute(delete(FindingRecord).where(FindingRecord.source_import_job_id == job.id))
        db.execute(delete(AssetRecord).where(AssetRecord.source_import_job_id == job.id))
        assets_by_key: dict[str, AssetRecord] = {}
        for item in asset_rows:
            asset = assets_by_key.get(item["stable_asset_key"])
            if asset is None:
                asset = AssetRecord(
                    stable_asset_key=item["stable_asset_key"],
                    source_import_job_id=job.id,
                    source_scan_record_id=scan.id,
                    source_history_record_id=history.id if history else None,
                )
                db.add(asset)
            asset.tenable_asset_uuid = item["tenable_asset_uuid"]
            asset.agent_uuid = item["agent_uuid"]
            asset.bios_uuid = item["bios_uuid"]
            asset.mac_address = item["mac_address"]
            asset.fqdn = item["fqdn"]
            asset.hostname = item["hostname"]
            asset.ipv4_address = item["ipv4_address"]
            asset.ipv6_address = item["ipv6_address"]
            asset.os_name = item["os_name"]
            asset.raw_metadata = item["raw_metadata"]
            asset.last_seen_at = utc_now()
            db.flush()
            assets_by_key[item["stable_asset_key"]] = asset
        job.progress_percent = 70
        job.last_checkpoint = "normalize_findings"
        db.flush()

        findings_by_key: dict[str, FindingRecord] = {}
        for item in finding_rows:
            asset = assets_by_key[item["stable_asset_key"]]
            finding = findings_by_key.get(item["finding_key"])
            if finding is None:
                finding = FindingRecord(
                    finding_key=item["finding_key"],
                    source_import_job_id=job.id,
                    source_scan_record_id=scan.id,
                    source_history_record_id=history.id if history else None,
                    asset_record_id=asset.id,
                )
                db.add(finding)
            finding.asset_record_id = asset.id
            finding.plugin_id = item["plugin_id"]
            finding.plugin_name = item["plugin_name"]
            finding.severity = item["severity"]
            finding.port = item["port"]
            finding.protocol = item["protocol"]
            finding.plugin_family = item["plugin_family"]
            finding.risk_factor = item["risk_factor"]
            finding.synopsis = item["synopsis"]
            finding.plugin_output = item["plugin_output"]
            finding.state = item["state"]
            finding.last_found_at = utc_now()
            findings_by_key[item["finding_key"]] = finding
        job.imported_asset_count = len(assets_by_key)
        job.imported_finding_count = len(findings_by_key)
        queue_ambiguous_asset_reviews(db, list(assets_by_key.values()))
        job.progress_percent = 100
        job.status = "completed"
        job.last_checkpoint = "completed"
        job.completed_at = utc_now()
        write_audit(
            db,
            actor_user_id=actor_session.user_id,
            action="imports.scan.run",
            object_type="import_job",
            object_id=job.id,
            object_name=scan.name,
            source_ip=source_ip,
            new_state={"asset_count": job.imported_asset_count, "finding_count": job.imported_finding_count},
        )
        db.commit()
    except Exception as exc:
        _mark_failed(job, str(exc))
        db.commit()
        if isinstance(exc, ImportServiceError):
            raise
        raise ImportServiceError(str(exc)) from exc

    job = db.get(ImportJob, job.id)
    assets = db.scalars(select(AssetRecord).where(AssetRecord.source_import_job_id == job.id).order_by(AssetRecord.hostname)).all()
    findings = db.scalars(select(FindingRecord).where(FindingRecord.source_import_job_id == job.id).order_by(FindingRecord.plugin_id)).all()
    return ImportResultResponse(
        job=_job_to_response(job),
        assets=[_asset_to_response(asset) for asset in assets],
        findings=[_finding_to_response(finding) for finding in findings],
    )


def recover_import_job(
    db: Session,
    *,
    actor_session: UserSession,
    job_id: str,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> ImportResultResponse:
    job = db.get(ImportJob, job_id)
    if job is None:
        raise ImportServiceError("Import job not found.")
    if job.status != "failed":
        raise ImportServiceError("Only failed jobs can be recovered.")
    return run_import_job(
        db,
        actor_session=actor_session,
        scan_record_id=job.scan_record_id,
        request=ImportScanRequest(scan_history_record_id=job.scan_history_record_id, force_reimport=False),
        source_ip=source_ip,
        client_factory=client_factory,
    )
