from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from openpyxl import Workbook
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.auth import AuditEvent, UserSession
from backend.app.models.comparison import ComparisonResultRecord, ComparisonRun
from backend.app.models.finding import FindingRecord
from backend.app.models.folder import FolderRecord
from backend.app.models.import_job import ImportJob
from backend.app.models.scan import ScanRecord
from backend.app.services.audit import write_audit
from backend.app.services.dashboard import _effective_finding


class ReportServiceError(ValueError):
    pass


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@"}:
        return f"'{text}"
    return text


def _rows_for_report(db: Session, *, report_type: str, comparison_run_id: str | None = None) -> tuple[list[str], list[dict[str, object]]]:
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
            ["scan_name", "status", "folder_name", "target_count", "owner", "permission_status", "deleted"],
            [
                {
                    "scan_name": row.name,
                    "status": row.status,
                    "folder_name": row.folder_name,
                    "target_count": row.target_count,
                    "owner": row.owner,
                    "permission_status": row.permission_status,
                    "deleted": "yes" if row.deleted_at else "no",
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
) -> tuple[str, str, bytes]:
    headers, rows = _rows_for_report(db, report_type=report_type, comparison_run_id=comparison_run_id)
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
        new_state={"format": normalized_format, "comparison_run_id": comparison_run_id or ""},
    )
    db.commit()
    return f"{report_type}_{_utc_stamp()}.{extension}", content_type, payload
