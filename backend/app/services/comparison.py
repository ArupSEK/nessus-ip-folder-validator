from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetRecord
from backend.app.models.auth import UserSession
from backend.app.models.comparison import ComparisonResultRecord, ComparisonRun
from backend.app.models.finding import FindingRecord
from backend.app.models.import_job import ImportJob
from backend.app.models.scan import ScanRecord
from backend.app.schemas.comparison import ComparisonResultResponse, ComparisonRunRequest, ComparisonRunResponse
from backend.app.services.audit import write_audit
from backend.app.services.auth import ensure_utc


class ComparisonServiceError(ValueError):
    pass


def _result_to_response(row: ComparisonResultRecord) -> ComparisonResultResponse:
    return ComparisonResultResponse(
        id=row.id,
        asset_key=row.asset_key,
        finding_key=row.finding_key,
        comparison_eligibility=row.comparison_eligibility,
        lifecycle_status=row.lifecycle_status,
        reason=row.reason,
    )


def _run_to_response(db: Session, run: ComparisonRun) -> ComparisonRunResponse:
    rows = db.scalars(select(ComparisonResultRecord).where(ComparisonResultRecord.comparison_run_id == run.id).order_by(ComparisonResultRecord.asset_key, ComparisonResultRecord.finding_key)).all()
    return ComparisonRunResponse(
        id=run.id,
        previous_import_job_id=run.previous_import_job_id,
        latest_import_job_id=run.latest_import_job_id,
        status=run.status,
        comparable_asset_count=run.comparable_asset_count,
        non_comparable_asset_count=run.non_comparable_asset_count,
        new_count=run.new_count,
        existing_count=run.existing_count,
        closed_count=run.closed_count,
        reopened_count=run.reopened_count,
        not_validated_count=run.not_validated_count,
        severity_changed_count=run.severity_changed_count,
        port_changed_count=run.port_changed_count,
        created_at=ensure_utc(run.created_at).isoformat(),
        results=[_result_to_response(row) for row in rows],
    )


def _logical_key(finding: FindingRecord) -> str:
    return f"{finding.plugin_id}:{finding.protocol.lower()}"


def _latest_closed_result(db: Session, finding_key: str) -> ComparisonResultRecord | None:
    return db.scalar(
        select(ComparisonResultRecord)
        .where(
            ComparisonResultRecord.finding_key == finding_key,
            ComparisonResultRecord.lifecycle_status == "Closed",
        )
        .order_by(ComparisonResultRecord.created_at.desc())
    )


def _load_metadata(asset: AssetRecord) -> dict:
    try:
        return json.loads(asset.raw_metadata or "{}")
    except json.JSONDecodeError:
        return {}


def _eligibility(previous_scan: ScanRecord, latest_scan: ScanRecord, latest_asset: AssetRecord | None) -> tuple[str, str]:
    if latest_asset is None:
        return "asset_absent_from_latest_targets", "Asset absent from latest targets."
    meta = _load_metadata(latest_asset)
    reachability = str(meta.get("reachability_status", "reachable")).lower()
    auth = str(meta.get("authentication_status", "successful")).lower()
    credentialed = str(meta.get("credentialed_checks_status", "passed")).lower()
    if reachability == "unreachable":
        return "host_unreachable", "Latest asset is unreachable."
    if auth == "failed":
        return "authentication_failed", "Latest asset authentication failed."
    if credentialed == "failed":
        return "credentialed_checks_failed", "Latest asset credentialed checks failed."
    if previous_scan.template_uuid and latest_scan.template_uuid and previous_scan.template_uuid != latest_scan.template_uuid:
        return "policy_mismatch", "Scan template or policy did not match."
    return "comparable", "Comparable."


def run_comparison(db: Session, *, actor_session: UserSession, payload: ComparisonRunRequest, source_ip: str) -> ComparisonRunResponse:
    previous_job = db.get(ImportJob, payload.previous_import_job_id)
    latest_job = db.get(ImportJob, payload.latest_import_job_id)
    if previous_job is None or latest_job is None:
        raise ComparisonServiceError("Import jobs were not found.")
    if previous_job.status != "completed" or latest_job.status != "completed":
        raise ComparisonServiceError("Only completed import jobs can be compared.")
    previous_scan = db.get(ScanRecord, previous_job.scan_record_id)
    latest_scan = db.get(ScanRecord, latest_job.scan_record_id)
    if previous_scan is None or latest_scan is None:
        raise ComparisonServiceError("Source scans were not found.")

    run = ComparisonRun(
        previous_import_job_id=previous_job.id,
        latest_import_job_id=latest_job.id,
        created_by_user_id=actor_session.user_id,
        status="running",
    )
    db.add(run)
    db.flush()

    previous_assets = db.scalars(select(AssetRecord).where(AssetRecord.source_import_job_id == previous_job.id)).all()
    latest_assets = db.scalars(select(AssetRecord).where(AssetRecord.source_import_job_id == latest_job.id)).all()
    previous_assets_by_key = {item.stable_asset_key: item for item in previous_assets}
    latest_assets_by_key = {item.stable_asset_key: item for item in latest_assets}
    asset_keys = sorted(set(previous_assets_by_key) | set(latest_assets_by_key))

    previous_findings = db.scalars(select(FindingRecord).where(FindingRecord.source_import_job_id == previous_job.id)).all()
    latest_findings = db.scalars(select(FindingRecord).where(FindingRecord.source_import_job_id == latest_job.id)).all()

    previous_by_key = {item.finding_key: item for item in previous_findings}
    latest_by_key = {item.finding_key: item for item in latest_findings}
    previous_by_logical: dict[str, list[FindingRecord]] = {}
    latest_by_logical: dict[str, list[FindingRecord]] = {}
    for item in previous_findings:
        previous_by_logical.setdefault(_logical_key(item), []).append(item)
    for item in latest_findings:
        latest_by_logical.setdefault(_logical_key(item), []).append(item)

    comparable_assets = 0
    non_comparable_assets = 0

    def add_result(*, asset_key: str, finding_key: str, previous_finding: FindingRecord | None, latest_finding: FindingRecord | None, eligibility: str, lifecycle: str, reason: str) -> None:
        row = ComparisonResultRecord(
            comparison_run_id=run.id,
            asset_key=asset_key,
            finding_key=finding_key,
            previous_finding_id=previous_finding.id if previous_finding else None,
            latest_finding_id=latest_finding.id if latest_finding else None,
            comparison_eligibility=eligibility,
            lifecycle_status=lifecycle,
            reason=reason,
        )
        db.add(row)
        if lifecycle == "New":
            run.new_count += 1
        elif lifecycle == "Existing":
            run.existing_count += 1
        elif lifecycle == "Closed":
            run.closed_count += 1
        elif lifecycle == "Reopened":
            run.reopened_count += 1
        elif lifecycle == "Not Validated":
            run.not_validated_count += 1
        elif lifecycle == "Severity Changed":
            run.severity_changed_count += 1
        elif lifecycle == "Port Changed":
            run.port_changed_count += 1

    for asset_key in asset_keys:
        eligibility, eligibility_reason = _eligibility(previous_scan, latest_scan, latest_assets_by_key.get(asset_key))
        if eligibility == "comparable":
            comparable_assets += 1
        else:
            non_comparable_assets += 1

        previous_for_asset = [item for item in previous_findings if previous_assets_by_key.get(asset_key) and item.asset_record_id == previous_assets_by_key[asset_key].id]
        latest_for_asset = [item for item in latest_findings if latest_assets_by_key.get(asset_key) and item.asset_record_id == latest_assets_by_key[asset_key].id]
        all_keys = {item.finding_key for item in previous_for_asset} | {item.finding_key for item in latest_for_asset}
        handled_prev_keys: set[str] = set()
        handled_latest_keys: set[str] = set()

        for finding_key in sorted(all_keys):
            prev = previous_by_key.get(finding_key)
            latest = latest_by_key.get(finding_key)
            if prev and latest:
                handled_prev_keys.add(prev.finding_key)
                handled_latest_keys.add(latest.finding_key)
                if prev.severity != latest.severity:
                    add_result(asset_key=asset_key, finding_key=finding_key, previous_finding=prev, latest_finding=latest, eligibility=eligibility, lifecycle="Severity Changed", reason="Severity changed between imports.")
                else:
                    prior_closed = _latest_closed_result(db, finding_key)
                    lifecycle = "Reopened" if prior_closed is not None else "Existing"
                    reason = "Finding returned after a previous closure." if lifecycle == "Reopened" else "Finding present in both imports."
                    add_result(asset_key=asset_key, finding_key=finding_key, previous_finding=prev, latest_finding=latest, eligibility=eligibility, lifecycle=lifecycle, reason=reason)

        for prev in previous_for_asset:
            if prev.finding_key in handled_prev_keys:
                continue
            latest_asset = latest_assets_by_key.get(asset_key)
            logical_matches = [
                item for item in latest_by_logical.get(_logical_key(prev), [])
                if latest_asset is not None and item.asset_record_id == latest_asset.id
            ]
            port_change_match = next((item for item in logical_matches if item.finding_key not in handled_latest_keys), None)
            if port_change_match is not None:
                handled_latest_keys.add(port_change_match.finding_key)
                add_result(asset_key=asset_key, finding_key=port_change_match.finding_key, previous_finding=prev, latest_finding=port_change_match, eligibility=eligibility, lifecycle="Port Changed", reason="Finding moved to a different port.")
                continue
            lifecycle = "Closed" if eligibility == "comparable" else "Not Validated"
            reason = "Finding missing from comparable latest import." if lifecycle == "Closed" else eligibility_reason
            add_result(asset_key=asset_key, finding_key=prev.finding_key, previous_finding=prev, latest_finding=None, eligibility=eligibility, lifecycle=lifecycle, reason=reason)

        for latest in latest_for_asset:
            if latest.finding_key in handled_latest_keys:
                continue
            lifecycle = "Reopened" if _latest_closed_result(db, latest.finding_key) is not None else "New"
            reason = "Finding returned after a previous closure." if lifecycle == "Reopened" else "Finding appears only in the latest import."
            add_result(asset_key=asset_key, finding_key=latest.finding_key, previous_finding=None, latest_finding=latest, eligibility=eligibility, lifecycle=lifecycle, reason=reason)

    run.comparable_asset_count = comparable_assets
    run.non_comparable_asset_count = non_comparable_assets
    run.status = "completed"
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="comparisons.run",
        object_type="comparison_run",
        object_id=run.id,
        object_name=f"{previous_job.id}->{latest_job.id}",
        source_ip=source_ip,
        new_state={
            "new": run.new_count,
            "existing": run.existing_count,
            "closed": run.closed_count,
            "reopened": run.reopened_count,
            "not_validated": run.not_validated_count,
        },
    )
    db.commit()
    db.refresh(run)
    return _run_to_response(db, run)
