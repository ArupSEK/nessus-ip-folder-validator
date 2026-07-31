from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from openpyxl import Workbook
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetRecord
from backend.app.models.auth import AuditEvent, UserSession
from backend.app.models.comparison import ComparisonResultRecord, ComparisonRun
from backend.app.models.finding import FindingRecord
from backend.app.models.folder import FolderRecord
from backend.app.models.import_job import ImportJob
from backend.app.models.scan import ScanRecord
from backend.app.models.workflow import FindingWorkflow, WorkflowDecision
from backend.app.services.audit import write_audit
from backend.app.services.dashboard import _effective_finding
from backend.app.services.ip_search import run_ip_search
from backend.app.services.workflow import OPEN_WORKFLOW_STATUSES


class ReportServiceError(ValueError):
    pass


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@"}:
        return f"'{text}"
    return text


def _load_metadata(asset: AssetRecord) -> dict[str, str]:
    if not asset.raw_metadata:
        return {}
    try:
        payload = json.loads(asset.raw_metadata)
    except json.JSONDecodeError:
        return {}
    return {str(key): str(value) for key, value in payload.items()}


def _rows_for_workflow_overdue(db: Session) -> tuple[list[str], list[dict[str, object]]]:
    today = datetime.now(timezone.utc).date()
    rows = db.scalars(select(FindingWorkflow).order_by(FindingWorkflow.days_overdue.desc(), FindingWorkflow.finding_key)).all()
    output = []
    for row in rows:
        if row.due_date is None or row.actual_remediation_date is not None:
            continue
        if row.workflow_status not in OPEN_WORKFLOW_STATUSES:
            continue
        if row.due_date >= today:
            continue
        output.append(
            {
                "finding_key": row.finding_key,
                "asset_key": row.asset_key,
                "workflow_status": row.workflow_status,
                "owner": row.owner,
                "remediation_team": row.remediation_team,
                "due_date": row.due_date.isoformat(),
                "days_overdue": row.days_overdue,
                "ticket_number": row.ticket_number,
                "validation_status": row.validation_status,
            }
        )
    return (
        ["finding_key", "asset_key", "workflow_status", "owner", "remediation_team", "due_date", "days_overdue", "ticket_number", "validation_status"],
        output,
    )


def _rows_for_decisions(db: Session, *, decision_type: str, days_until_expiry: int) -> tuple[list[str], list[dict[str, object]]]:
    query = (
        select(WorkflowDecision, FindingWorkflow)
        .join(FindingWorkflow, FindingWorkflow.id == WorkflowDecision.finding_workflow_id)
        .where(WorkflowDecision.decision_type == decision_type, WorkflowDecision.status == "approved")
        .order_by(WorkflowDecision.expiry_date.asc(), WorkflowDecision.approved_at.desc())
    )
    rows = db.execute(query).all()
    today = datetime.now(timezone.utc).date()
    output: list[dict[str, object]] = []
    for decision, workflow in rows:
        if decision_type == "exception":
            if decision.expiry_date is None:
                continue
            if decision.expiry_date > today + timedelta(days=max(days_until_expiry, 0)):
                continue
        output.append(
            {
                "finding_key": workflow.finding_key,
                "asset_key": workflow.asset_key,
                "workflow_status": workflow.workflow_status,
                "status": decision.status,
                "reason": decision.reason,
                "business_justification": decision.business_justification,
                "compensating_controls": decision.compensating_controls,
                "review_date": decision.review_date.isoformat() if decision.review_date else "",
                "expiry_date": decision.expiry_date.isoformat() if decision.expiry_date else "",
                "approved_at": decision.approved_at.isoformat() if decision.approved_at else "",
            }
        )
    return (
        ["finding_key", "asset_key", "workflow_status", "status", "reason", "business_justification", "compensating_controls", "review_date", "expiry_date", "approved_at"],
        output,
    )


def _rows_for_scan_authentication_status(db: Session) -> tuple[list[str], list[dict[str, object]]]:
    latest_jobs = db.scalars(select(ImportJob).where(ImportJob.status == "completed").order_by(ImportJob.created_at.desc())).all()
    by_scan: dict[str, ImportJob] = {}
    for job in latest_jobs:
        by_scan.setdefault(job.scan_record_id, job)
    output: list[dict[str, object]] = []
    for job in by_scan.values():
        scan = db.get(ScanRecord, job.scan_record_id)
        if scan is None:
            continue
        assets = db.scalars(select(AssetRecord).where(AssetRecord.source_import_job_id == job.id).order_by(AssetRecord.hostname, AssetRecord.ipv4_address)).all()
        for asset in assets:
            meta = _load_metadata(asset)
            output.append(
                {
                    "scan_name": scan.name,
                    "scan_id": scan.nessus_scan_id,
                    "asset_key": asset.stable_asset_key,
                    "hostname": asset.hostname,
                    "ipv4_address": asset.ipv4_address,
                    "reachability": meta.get("reachability_status", "unknown"),
                    "authentication_status": meta.get("authentication_status", "unknown"),
                    "credentialed_checks_status": meta.get("credentialed_checks_status", "unknown"),
                    "source_import_job_id": job.id,
                }
            )
    return (
        ["scan_name", "scan_id", "asset_key", "hostname", "ipv4_address", "reachability", "authentication_status", "credentialed_checks_status", "source_import_job_id"],
        output,
    )


def _rows_for_global_ip_search(db: Session, *, entries: list[str], expand_cidr: bool) -> tuple[list[str], list[dict[str, object]]]:
    if not entries:
        raise ReportServiceError("Global IP Search export requires at least one query entry.")
    result = run_ip_search(db, entries, expand_cidr=expand_cidr)
    output: list[dict[str, object]] = []
    for item in result.results:
        if not item.matches:
            output.append(
                {
                    "query": item.query,
                    "normalized_ip": item.normalized_ip or "",
                    "folder_name": "",
                    "scan_name": "",
                    "scan_status": "",
                    "reachability": "",
                    "authentication_status": "",
                    "credentialed_checks_status": "",
                    "last_scan_date": "",
                }
            )
            continue
        for match in item.matches:
            output.append(
                {
                    "query": match.query,
                    "normalized_ip": match.normalized_ip,
                    "folder_name": match.folder_name,
                    "scan_name": match.scan_name,
                    "scan_status": match.scan_status,
                    "reachability": match.reachability,
                    "authentication_status": match.authentication_status,
                    "credentialed_checks_status": match.credentialed_checks_status,
                    "last_scan_date": match.last_scan_date or "",
                }
            )
    return (
        ["query", "normalized_ip", "folder_name", "scan_name", "scan_status", "reachability", "authentication_status", "credentialed_checks_status", "last_scan_date"],
        output,
    )


def _rows_for_report(
    db: Session,
    *,
    report_type: str,
    comparison_run_id: str | None = None,
    ip_search_entries: list[str] | None = None,
    expand_cidr: bool = False,
    days_until_expiry: int = 30,
) -> tuple[list[str], list[dict[str, object]]]:
    normalized = report_type.strip().lower()
    if normalized == "folder_inventory":
        rows = db.scalars(select(FolderRecord).order_by(FolderRecord.name)).all()
        return (
            ["folder_name", "folder_type", "owner", "permission_status", "scan_count", "deleted"],
            [
                {
                    "folder_name": row.name,
                    "folder_type": row.folder_type,
                    "owner": row.owner,
                    "permission_status": row.permission_status,
                    "scan_count": row.scan_count,
                    "deleted": "yes" if row.deleted_at else "no",
                }
                for row in rows
            ],
        )
    if normalized == "scan_inventory":
        rows = db.scalars(select(ScanRecord).order_by(ScanRecord.name)).all()
        return (
            ["scan_name", "status", "folder_name", "target_count", "owner", "permission_status", "deleted", "permanently_deleted"],
            [
                {
                    "scan_name": row.name,
                    "status": row.status,
                    "folder_name": row.folder_name,
                    "target_count": row.target_count,
                    "owner": row.owner,
                    "permission_status": row.permission_status,
                    "deleted": "yes" if row.deleted_at else "no",
                    "permanently_deleted": "yes" if row.permanently_deleted_at else "no",
                }
                for row in rows
            ],
        )
    if normalized in {
        "scan_comparison",
        "new_findings",
        "existing_findings",
        "closed_findings",
        "reopened_findings",
        "not_validated_findings",
    }:
        run = db.get(ComparisonRun, comparison_run_id) if comparison_run_id else db.scalar(select(ComparisonRun).order_by(ComparisonRun.created_at.desc()))
        if run is None:
            raise ReportServiceError("Comparison run not found.")
        rows = db.scalars(
            select(ComparisonResultRecord)
            .where(ComparisonResultRecord.comparison_run_id == run.id)
            .order_by(ComparisonResultRecord.asset_key, ComparisonResultRecord.finding_key)
        ).all()
        lifecycle_map = {
            "new_findings": "New",
            "existing_findings": "Existing",
            "closed_findings": "Closed",
            "reopened_findings": "Reopened",
            "not_validated_findings": "Not Validated",
        }
        required_lifecycle = lifecycle_map.get(normalized)
        output_rows: list[dict[str, object]] = []
        for row in rows:
            if required_lifecycle and row.lifecycle_status != required_lifecycle:
                continue
            finding = _effective_finding(db, row)
            output_rows.append(
                {
                    "asset_key": row.asset_key,
                    "finding_key": row.finding_key,
                    "lifecycle_status": row.lifecycle_status,
                    "comparison_eligibility": row.comparison_eligibility,
                    "severity": finding.severity if finding else 0,
                    "plugin_id": finding.plugin_id if finding else 0,
                    "plugin_name": finding.plugin_name if finding else "",
                    "port": finding.port if finding else 0,
                    "protocol": finding.protocol if finding else "",
                    "reason": row.reason,
                }
            )
        return (
            ["asset_key", "finding_key", "lifecycle_status", "comparison_eligibility", "severity", "plugin_id", "plugin_name", "port", "protocol", "reason"],
            output_rows,
        )
    if normalized == "asset_coverage":
        job = db.get(ImportJob, comparison_run_id) if comparison_run_id else db.scalar(select(ImportJob).order_by(ImportJob.created_at.desc()))
        if job is None:
            raise ReportServiceError("Import job not found.")
        rows = db.scalars(select(FindingRecord).where(FindingRecord.source_import_job_id == job.id).order_by(FindingRecord.finding_key)).all()
        return (
            ["finding_key", "plugin_id", "plugin_name", "severity", "port", "protocol"],
            [
                {
                    "finding_key": row.finding_key,
                    "plugin_id": row.plugin_id,
                    "plugin_name": row.plugin_name,
                    "severity": row.severity,
                    "port": row.port,
                    "protocol": row.protocol,
                }
                for row in rows
            ],
        )
    if normalized == "global_ip_search":
        return _rows_for_global_ip_search(db, entries=ip_search_entries or [], expand_cidr=expand_cidr)
    if normalized == "scan_authentication_status":
        return _rows_for_scan_authentication_status(db)
    if normalized == "sla_overdue":
        return _rows_for_workflow_overdue(db)
    if normalized == "risk_acceptance":
        return _rows_for_decisions(db, decision_type="risk_acceptance", days_until_expiry=days_until_expiry)
    if normalized == "expiring_exceptions":
        return _rows_for_decisions(db, decision_type="exception", days_until_expiry=days_until_expiry)
    if normalized == "deleted_objects_audit":
        rows = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.action.like("%delete%") | AuditEvent.action.like("%trash%"))
            .order_by(AuditEvent.created_at.desc())
        ).all()
        return (
            ["timestamp", "action", "object_type", "object_id", "object_name", "result", "source_ip"],
            [
                {
                    "timestamp": row.created_at.isoformat(),
                    "action": row.action,
                    "object_type": row.object_type,
                    "object_id": row.object_id,
                    "object_name": row.object_name,
                    "result": row.result,
                    "source_ip": row.source_ip,
                }
                for row in rows
            ],
        )
    if normalized == "audit_events":
        rows = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc())).all()
        return (
            ["timestamp", "actor_user_id", "action", "object_type", "object_id", "object_name", "result", "source_ip", "justification", "previous_state", "new_state"],
            [
                {
                    "timestamp": row.created_at.isoformat(),
                    "actor_user_id": row.actor_user_id or "",
                    "action": row.action,
                    "object_type": row.object_type,
                    "object_id": row.object_id,
                    "object_name": row.object_name,
                    "result": row.result,
                    "source_ip": row.source_ip,
                    "justification": row.justification,
                    "previous_state": row.previous_state,
                    "new_state": row.new_state,
                }
                for row in rows
            ],
        )
    raise ReportServiceError("Unsupported report type.")


def build_report_bytes(
    db: Session,
    *,
    actor_session: UserSession,
    report_type: str,
    export_format: str,
    comparison_run_id: str | None,
    source_ip: str,
    ip_search_entries: list[str] | None = None,
    expand_cidr: bool = False,
    days_until_expiry: int = 30,
) -> tuple[str, str, bytes]:
    headers, rows = _rows_for_report(
        db,
        report_type=report_type,
        comparison_run_id=comparison_run_id,
        ip_search_entries=ip_search_entries,
        expand_cidr=expand_cidr,
        days_until_expiry=days_until_expiry,
    )
    normalized_format = export_format.strip().lower()
    if normalized_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _safe_cell(value) for key, value in row.items()})
        payload = buffer.getvalue().encode("utf-8")
        content_type = "text/csv; charset=utf-8"
        extension = "csv"
    elif normalized_format == "xlsx":
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "report"
        sheet.append(headers)
        for row in rows:
            sheet.append([_safe_cell(row.get(header, "")) for header in headers])
        output = io.BytesIO()
        workbook.save(output)
        payload = output.getvalue()
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        extension = "xlsx"
    else:
        raise ReportServiceError("Unsupported export format.")

    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="reports.export",
        object_type="report",
        object_id=report_type,
        object_name=report_type,
        source_ip=source_ip,
        new_state={
            "format": normalized_format,
            "comparison_run_id": comparison_run_id or "",
            "ip_search_entry_count": len(ip_search_entries or []),
            "days_until_expiry": days_until_expiry,
        },
    )
    db.commit()
    return f"{report_type}_{_utc_stamp()}.{extension}", content_type, payload
