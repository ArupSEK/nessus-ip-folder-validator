from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetRecord
from backend.app.models.comparison import ComparisonResultRecord, ComparisonRun
from backend.app.models.finding import FindingRecord
from backend.app.models.import_job import ImportJob
from backend.app.schemas.dashboard import (
    AssetCoverageSummary,
    DashboardFindingListResponse,
    DashboardFindingResponse,
    DashboardSummaryResponse,
    SeverityBreakdown,
)


class DashboardServiceError(ValueError):
    pass


def _load_metadata(asset: AssetRecord | None) -> dict[str, str]:
    if asset is None or not asset.raw_metadata:
        return {}
    try:
        payload = json.loads(asset.raw_metadata)
    except json.JSONDecodeError:
        return {}
    return {str(key): str(value) for key, value in payload.items()}


def _get_run(db: Session, comparison_run_id: str | None) -> ComparisonRun:
    if comparison_run_id:
        run = db.get(ComparisonRun, comparison_run_id)
    else:
        run = db.scalar(select(ComparisonRun).order_by(ComparisonRun.created_at.desc()))
    if run is None:
        raise DashboardServiceError("Comparison run not found.")
    return run


def _effective_finding(db: Session, row: ComparisonResultRecord) -> FindingRecord | None:
    return db.get(FindingRecord, row.latest_finding_id) if row.latest_finding_id else db.get(FindingRecord, row.previous_finding_id) if row.previous_finding_id else None


def _severity_bucket(value: int) -> str:
    if value >= 4:
        return "critical"
    if value == 3:
        return "high"
    if value == 2:
        return "medium"
    if value == 1:
        return "low"
    return "informational"


def get_dashboard_summary(db: Session, *, comparison_run_id: str | None = None) -> DashboardSummaryResponse:
    run = _get_run(db, comparison_run_id)
    previous_job = db.get(ImportJob, run.previous_import_job_id)
    latest_job = db.get(ImportJob, run.latest_import_job_id)
    if previous_job is None or latest_job is None:
        raise DashboardServiceError("Comparison source jobs were not found.")

    previous_assets = db.scalars(select(AssetRecord).where(AssetRecord.source_import_job_id == previous_job.id)).all()
    latest_assets = db.scalars(select(AssetRecord).where(AssetRecord.source_import_job_id == latest_job.id)).all()
    previous_findings = db.scalars(select(FindingRecord).where(FindingRecord.source_import_job_id == previous_job.id)).all()
    latest_findings = db.scalars(select(FindingRecord).where(FindingRecord.source_import_job_id == latest_job.id)).all()
    latest_assets_by_key = {asset.stable_asset_key: asset for asset in latest_assets}
    previous_asset_keys = {asset.stable_asset_key for asset in previous_assets}
    latest_asset_keys = {asset.stable_asset_key for asset in latest_assets}
    union_asset_keys = previous_asset_keys | latest_asset_keys

    reachable_assets = 0
    unreachable_assets = 0
    authentication_passed = 0
    authentication_failed = 0
    credentialed_checks_passed = 0
    credentialed_checks_failed = 0
    for asset in latest_assets:
        meta = _load_metadata(asset)
        reachability = meta.get("reachability_status", "reachable").lower()
        authentication = meta.get("authentication_status", "successful").lower()
        credentialed = meta.get("credentialed_checks_status", "passed").lower()
        if reachability == "unreachable":
            unreachable_assets += 1
        else:
            reachable_assets += 1
        if authentication == "failed":
            authentication_failed += 1
        else:
            authentication_passed += 1
        if credentialed == "failed":
            credentialed_checks_failed += 1
        else:
            credentialed_checks_passed += 1

    results = db.scalars(select(ComparisonResultRecord).where(ComparisonResultRecord.comparison_run_id == run.id)).all()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for row in results:
        finding = _effective_finding(db, row)
        severity_counts[_severity_bucket(finding.severity if finding else 0)] += 1

    return DashboardSummaryResponse(
        comparison_run_id=run.id,
        previous_total=previous_job.imported_finding_count or len(previous_findings),
        latest_total=latest_job.imported_finding_count or len(latest_findings),
        new=run.new_count,
        existing=run.existing_count,
        closed=run.closed_count,
        reopened=run.reopened_count,
        not_validated=run.not_validated_count,
        severity_changed=run.severity_changed_count,
        accepted_risk=0,
        false_positive=0,
        exceptions=0,
        sla_overdue=0,
        severity_breakdown=SeverityBreakdown(**severity_counts),
        asset_coverage=AssetCoverageSummary(
            total_assets=len(union_asset_keys),
            assets_found=len(latest_asset_keys),
            assets_not_found=len(previous_asset_keys - latest_asset_keys),
            scanned_assets=len(latest_asset_keys),
            unscanned_assets=len(previous_asset_keys - latest_asset_keys),
            reachable_assets=reachable_assets,
            unreachable_assets=unreachable_assets,
            authentication_passed=authentication_passed,
            authentication_failed=authentication_failed,
            credentialed_checks_passed=credentialed_checks_passed,
            credentialed_checks_failed=credentialed_checks_failed,
            comparable_assets=run.comparable_asset_count,
            non_comparable_assets=run.non_comparable_asset_count,
        ),
    )


def list_dashboard_findings(
    db: Session,
    *,
    comparison_run_id: str | None = None,
    lifecycle_status: str = "",
    severity: int | None = None,
    search: str = "",
) -> DashboardFindingListResponse:
    run = _get_run(db, comparison_run_id)
    query = select(ComparisonResultRecord).where(ComparisonResultRecord.comparison_run_id == run.id)
    if lifecycle_status.strip():
        query = query.where(ComparisonResultRecord.lifecycle_status == lifecycle_status.strip())
    rows = db.scalars(query.order_by(ComparisonResultRecord.asset_key, ComparisonResultRecord.finding_key)).all()

    normalized_search = search.strip().lower()
    findings: list[DashboardFindingResponse] = []
    for row in rows:
        finding = _effective_finding(db, row)
        severity_value = finding.severity if finding else 0
        plugin_id = finding.plugin_id if finding else 0
        plugin_name = finding.plugin_name if finding else ""
        port = finding.port if finding else 0
        protocol = finding.protocol if finding else ""
        if severity is not None and severity_value != severity:
            continue
        haystack = " ".join([row.asset_key, row.finding_key, row.lifecycle_status, row.comparison_eligibility, plugin_name]).lower()
        if normalized_search and normalized_search not in haystack:
            continue
        findings.append(
            DashboardFindingResponse(
                result_id=row.id,
                asset_key=row.asset_key,
                finding_key=row.finding_key,
                lifecycle_status=row.lifecycle_status,
                comparison_eligibility=row.comparison_eligibility,
                severity=severity_value,
                plugin_id=plugin_id,
                plugin_name=plugin_name,
                port=port,
                protocol=protocol,
                reason=row.reason,
            )
        )

    return DashboardFindingListResponse(comparison_run_id=run.id, total=len(findings), findings=findings)
