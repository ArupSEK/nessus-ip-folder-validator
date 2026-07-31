from __future__ import annotations

import json
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetRecord
from backend.app.models.asset_review import AssetKeyOverride, AssetReviewRecord
from backend.app.models.auth import UserSession
from backend.app.models.comparison import ComparisonResultRecord
from backend.app.models.finding import FindingRecord
from backend.app.models.workflow import FindingWorkflow, SlaPolicy, WorkflowDecision
from backend.app.schemas.workflow import (
    AssetMergeRequest,
    AssetReviewAssetSummary,
    AssetReviewListResponse,
    AssetReviewResponse,
    AssetSplitRequest,
    FindingWorkflowResponse,
    FindingWorkflowUpdateRequest,
    WorkflowDecisionApproveRequest,
    WorkflowDecisionListResponse,
    WorkflowDecisionRequest,
    WorkflowDecisionResponse,
    WorkflowMaintenanceResponse,
)
from backend.app.services.audit import write_audit
from backend.app.services.auth import ensure_utc, utc_now

DEFAULT_SLA_POLICIES = {
    "critical": 7,
    "high": 15,
    "medium": 30,
    "low": 60,
    "informational": 90,
}

OPEN_WORKFLOW_STATUSES = {
    "Open",
    "Assigned",
    "Analysis in progress",
    "Remediation in progress",
    "Pending patch",
    "Pending vendor",
    "Pending change",
    "Ready for rescan",
    "Rescan scheduled",
    "Validation in progress",
    "Reopened",
    "Risk accepted",
    "Exception Approved",
    "False positive",
}

AMBIGUOUS_MATCH_FIELDS = {
    "hostname": "hostname",
    "fqdn": "fqdn",
    "ipv4_address": "ipv4",
    "ipv6_address": "ipv6",
    "mac_address": "mac_address",
}


class WorkflowServiceError(ValueError):
    pass


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    return date.fromisoformat(value)


def _date_str(value: date | None) -> str | None:
    return value.isoformat() if value else None


def _severity_name(severity: int) -> str:
    if severity >= 4:
        return "critical"
    if severity == 3:
        return "high"
    if severity == 2:
        return "medium"
    if severity == 1:
        return "low"
    return "informational"


def seed_default_sla_policies(db: Session) -> None:
    existing = {row.severity_name: row for row in db.scalars(select(SlaPolicy)).all()}
    for severity_name, days_to_due in DEFAULT_SLA_POLICIES.items():
        row = existing.get(severity_name)
        if row is None:
            db.add(SlaPolicy(severity_name=severity_name, days_to_due=days_to_due, is_active=True))
        elif row.days_to_due <= 0:
            row.days_to_due = days_to_due
            row.is_active = True
    db.flush()


def _latest_finding(db: Session, finding_key: str) -> FindingRecord:
    rows = db.scalars(select(FindingRecord).where(FindingRecord.finding_key == finding_key).order_by(FindingRecord.last_found_at.desc(), FindingRecord.created_at.desc())).all()
    if not rows:
        raise WorkflowServiceError("Finding not found.")
    return rows[0]


def _latest_comparison_result(db: Session, finding_key: str) -> ComparisonResultRecord | None:
    return db.scalar(
        select(ComparisonResultRecord)
        .where(ComparisonResultRecord.finding_key == finding_key)
        .order_by(ComparisonResultRecord.created_at.desc())
    )


def _due_date_for_finding(db: Session, finding: FindingRecord, sla_start_date: date) -> date:
    seed_default_sla_policies(db)
    severity_name = _severity_name(finding.severity)
    policy = db.scalar(select(SlaPolicy).where(SlaPolicy.severity_name == severity_name))
    if policy is None:
        raise WorkflowServiceError("SLA policy not found.")
    return sla_start_date + timedelta(days=policy.days_to_due)


def _days_overdue(due_date: date | None, actual_remediation_date: date | None) -> int:
    if due_date is None or actual_remediation_date is not None:
        return 0
    today = utc_now().date()
    return max((today - due_date).days, 0)


def _to_workflow_response(row: FindingWorkflow) -> FindingWorkflowResponse:
    return FindingWorkflowResponse(
        id=row.id,
        finding_key=row.finding_key,
        asset_key=row.asset_key,
        workflow_status=row.workflow_status,
        owner=row.owner,
        remediation_team=row.remediation_team,
        sla_start_date=_date_str(row.sla_start_date),
        due_date=_date_str(row.due_date),
        days_overdue=row.days_overdue,
        target_date=_date_str(row.target_date),
        actual_remediation_date=_date_str(row.actual_remediation_date),
        ticket_number=row.ticket_number,
        ticket_url=row.ticket_url,
        comments=row.comments,
        evidence=row.evidence,
        rescan_requested=row.rescan_requested,
        validation_status=row.validation_status,
        is_technically_open=row.workflow_status in OPEN_WORKFLOW_STATUSES,
    )


def _to_decision_response(row: WorkflowDecision) -> WorkflowDecisionResponse:
    return WorkflowDecisionResponse(
        id=row.id,
        finding_workflow_id=row.finding_workflow_id,
        decision_type=row.decision_type,
        reason=row.reason,
        business_justification=row.business_justification,
        compensating_controls=row.compensating_controls,
        start_date=_date_str(row.start_date),
        expiry_date=_date_str(row.expiry_date),
        review_date=_date_str(row.review_date),
        evidence=row.evidence,
        status=row.status,
        renewal_history=row.renewal_history,
        approved_at=ensure_utc(row.approved_at).isoformat() if ensure_utc(row.approved_at) else None,
    )


def resolve_asset_key(db: Session, asset_key: str) -> str:
    current = asset_key.strip().lower()
    for _ in range(10):
        override = db.scalar(select(AssetKeyOverride).where(AssetKeyOverride.source_asset_key == current, AssetKeyOverride.is_active.is_(True)))
        if override is None or not override.resolved_asset_key:
            return current
        next_key = override.resolved_asset_key.strip().lower()
        if next_key == current:
            return current
        current = next_key
    return current


def _asset_summary(asset_key: str, asset: AssetRecord | None) -> AssetReviewAssetSummary:
    if asset is None:
        return AssetReviewAssetSummary(stable_asset_key=asset_key)
    return AssetReviewAssetSummary(
        stable_asset_key=asset_key,
        hostname=asset.hostname,
        fqdn=asset.fqdn,
        ipv4_address=asset.ipv4_address,
        ipv6_address=asset.ipv6_address,
        tenable_asset_uuid=asset.tenable_asset_uuid,
        agent_uuid=asset.agent_uuid,
    )


def _to_asset_review_response(db: Session, row: AssetReviewRecord) -> AssetReviewResponse:
    left_asset = db.scalar(select(AssetRecord).where(AssetRecord.stable_asset_key == row.left_asset_key).order_by(AssetRecord.updated_at.desc()))
    right_asset = db.scalar(select(AssetRecord).where(AssetRecord.stable_asset_key == row.right_asset_key).order_by(AssetRecord.updated_at.desc()))
    return AssetReviewResponse(
        id=row.id,
        left_asset=_asset_summary(row.left_asset_key, left_asset),
        right_asset=_asset_summary(row.right_asset_key, right_asset),
        match_basis=[item for item in row.match_basis.split(",") if item],
        status=row.status,
        canonical_asset_key=row.canonical_asset_key,
        notes=row.notes,
        resolved_at=ensure_utc(row.resolved_at).isoformat() if ensure_utc(row.resolved_at) else None,
    )


def _normalize_review_pair(left_asset_key: str, right_asset_key: str) -> tuple[str, str]:
    left = left_asset_key.strip().lower()
    right = right_asset_key.strip().lower()
    if left == right:
        raise WorkflowServiceError("An asset cannot be reviewed against itself.")
    return (left, right) if left < right else (right, left)


def _match_basis(left: AssetRecord, right: AssetRecord) -> list[str]:
    matches: list[str] = []
    for field_name, label in AMBIGUOUS_MATCH_FIELDS.items():
        left_value = getattr(left, field_name, "").strip().lower()
        right_value = getattr(right, field_name, "").strip().lower()
        if left_value and right_value and left_value == right_value:
            matches.append(label)
    return matches


def queue_ambiguous_asset_reviews(db: Session, assets: list[AssetRecord]) -> None:
    if not assets:
        return
    existing_reviews = {
        (row.left_asset_key, row.right_asset_key): row
        for row in db.scalars(select(AssetReviewRecord)).all()
    }
    historical_assets = db.scalars(select(AssetRecord).order_by(AssetRecord.created_at.asc())).all()
    candidates = historical_assets
    for index, current in enumerate(assets):
        current_key = resolve_asset_key(db, current.stable_asset_key)
        for other in candidates:
            if other.id == current.id:
                continue
            other_key = resolve_asset_key(db, other.stable_asset_key)
            if current_key == other_key:
                continue
            basis = _match_basis(current, other)
            if not basis:
                continue
            left_key, right_key = _normalize_review_pair(current_key, other_key)
            if (left_key, right_key) in existing_reviews:
                continue
            review = AssetReviewRecord(
                left_asset_key=left_key,
                right_asset_key=right_key,
                left_hostname=current.hostname if left_key == current_key else other.hostname,
                right_hostname=other.hostname if right_key == other_key else current.hostname,
                left_ipv4_address=current.ipv4_address if left_key == current_key else other.ipv4_address,
                right_ipv4_address=other.ipv4_address if right_key == other_key else current.ipv4_address,
                left_fqdn=current.fqdn if left_key == current_key else other.fqdn,
                right_fqdn=other.fqdn if right_key == other_key else current.fqdn,
                match_basis=",".join(sorted(set(basis))),
                status="pending",
            )
            db.add(review)
            db.flush()
            existing_reviews[(left_key, right_key)] = review


def list_asset_reviews(db: Session, *, status: str = "pending") -> AssetReviewListResponse:
    query = select(AssetReviewRecord).order_by(AssetReviewRecord.created_at.desc())
    normalized_status = status.strip().lower()
    if normalized_status:
        query = query.where(AssetReviewRecord.status == normalized_status)
    rows = db.scalars(query).all()
    reviews = [_to_asset_review_response(db, row) for row in rows]
    return AssetReviewListResponse(total=len(reviews), reviews=reviews)


def merge_asset_review(
    db: Session,
    *,
    actor_session: UserSession,
    review_id: str,
    payload: AssetMergeRequest,
    source_ip: str,
) -> AssetReviewResponse:
    review = db.get(AssetReviewRecord, review_id)
    if review is None:
        raise WorkflowServiceError("Asset review was not found.")
    if review.status != "pending":
        raise WorkflowServiceError("Only pending asset reviews can be merged.")
    canonical = resolve_asset_key(db, payload.canonical_asset_key)
    allowed_keys = {review.left_asset_key, review.right_asset_key}
    if canonical not in allowed_keys:
        raise WorkflowServiceError("Canonical asset key must match one of the review candidates.")
    source_key = next(item for item in allowed_keys if item != canonical)
    override = db.scalar(select(AssetKeyOverride).where(AssetKeyOverride.source_asset_key == source_key))
    if override is None:
        override = AssetKeyOverride(source_asset_key=source_key)
        db.add(override)
    override.resolved_asset_key = canonical
    override.resolution_type = "merge"
    override.is_active = True
    override.created_by_user_id = actor_session.user_id

    review.status = "merged"
    review.canonical_asset_key = canonical
    review.notes = payload.notes.strip()
    review.resolved_by_user_id = actor_session.user_id
    review.resolved_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="assets.review.merge",
        object_type="asset_review",
        object_id=review.id,
        object_name=f"{review.left_asset_key}|{review.right_asset_key}",
        source_ip=source_ip,
        new_state={"canonical_asset_key": canonical, "notes": review.notes},
    )
    db.commit()
    db.refresh(review)
    return _to_asset_review_response(db, review)


def split_asset_review(
    db: Session,
    *,
    actor_session: UserSession,
    review_id: str,
    payload: AssetSplitRequest,
    source_ip: str,
) -> AssetReviewResponse:
    review = db.get(AssetReviewRecord, review_id)
    if review is None:
        raise WorkflowServiceError("Asset review was not found.")
    if review.status != "pending":
        raise WorkflowServiceError("Only pending asset reviews can be split.")
    review.status = "split"
    review.notes = payload.notes.strip()
    review.resolved_by_user_id = actor_session.user_id
    review.resolved_at = utc_now()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="assets.review.split",
        object_type="asset_review",
        object_id=review.id,
        object_name=f"{review.left_asset_key}|{review.right_asset_key}",
        source_ip=source_ip,
        new_state={"notes": review.notes},
    )
    db.commit()
    db.refresh(review)
    return _to_asset_review_response(db, review)


def _get_or_create_workflow(db: Session, *, finding_key: str, actor_session: UserSession) -> tuple[FindingWorkflow, FindingRecord]:
    finding = _latest_finding(db, finding_key)
    workflow = db.scalar(select(FindingWorkflow).where(FindingWorkflow.finding_key == finding_key))
    comparison_result = _latest_comparison_result(db, finding_key)
    if workflow is None:
        sla_start_date = utc_now().date()
        workflow = FindingWorkflow(
            finding_key=finding_key,
            asset_key=finding.finding_key.rsplit(":", 3)[0],
            current_finding_record_id=finding.id,
            current_comparison_result_id=comparison_result.id if comparison_result else None,
            sla_start_date=sla_start_date,
            due_date=_due_date_for_finding(db, finding, sla_start_date),
            created_by_user_id=actor_session.user_id,
            updated_by_user_id=actor_session.user_id,
        )
        workflow.days_overdue = _days_overdue(workflow.due_date, workflow.actual_remediation_date)
        db.add(workflow)
        db.flush()
    else:
        workflow.current_finding_record_id = finding.id
        workflow.current_comparison_result_id = comparison_result.id if comparison_result else workflow.current_comparison_result_id
    return workflow, finding


def get_finding_workflow(db: Session, *, finding_key: str, actor_session: UserSession) -> FindingWorkflowResponse:
    workflow, _ = _get_or_create_workflow(db, finding_key=finding_key, actor_session=actor_session)
    db.commit()
    db.refresh(workflow)
    return _to_workflow_response(workflow)


def list_workflow_decisions(db: Session, *, finding_key: str, actor_session: UserSession) -> WorkflowDecisionListResponse:
    workflow, _ = _get_or_create_workflow(db, finding_key=finding_key, actor_session=actor_session)
    decisions = db.scalars(
        select(WorkflowDecision)
        .where(WorkflowDecision.finding_workflow_id == workflow.id)
        .order_by(WorkflowDecision.created_at.desc())
    ).all()
    db.commit()
    return WorkflowDecisionListResponse(
        finding_key=finding_key,
        decisions=[_to_decision_response(item) for item in decisions],
    )


def update_finding_workflow(
    db: Session,
    *,
    actor_session: UserSession,
    finding_key: str,
    payload: FindingWorkflowUpdateRequest,
    source_ip: str,
) -> FindingWorkflowResponse:
    workflow, finding = _get_or_create_workflow(db, finding_key=finding_key, actor_session=actor_session)
    previous_state = _to_workflow_response(workflow).model_dump()
    workflow.owner = payload.owner.strip()
    workflow.remediation_team = payload.remediation_team.strip()
    workflow.workflow_status = payload.workflow_status.strip() or "Open"
    workflow.sla_start_date = _parse_date(payload.sla_start_date) or workflow.sla_start_date or utc_now().date()
    workflow.due_date = _due_date_for_finding(db, finding, workflow.sla_start_date)
    workflow.target_date = _parse_date(payload.target_date)
    workflow.actual_remediation_date = _parse_date(payload.actual_remediation_date)
    workflow.ticket_number = payload.ticket_number.strip()
    workflow.ticket_url = payload.ticket_url.strip()
    workflow.comments = payload.comments.strip()
    workflow.evidence = payload.evidence.strip()
    workflow.rescan_requested = payload.rescan_requested
    workflow.validation_status = payload.validation_status.strip()
    workflow.updated_by_user_id = actor_session.user_id
    workflow.days_overdue = _days_overdue(workflow.due_date, workflow.actual_remediation_date)
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="findings.workflow.update",
        object_type="finding_workflow",
        object_id=workflow.id,
        object_name=finding_key,
        source_ip=source_ip,
        previous_state=previous_state,
        new_state=_to_workflow_response(workflow).model_dump(),
    )
    db.commit()
    db.refresh(workflow)
    return _to_workflow_response(workflow)


def request_workflow_decision(
    db: Session,
    *,
    actor_session: UserSession,
    payload: WorkflowDecisionRequest,
    source_ip: str,
) -> WorkflowDecisionResponse:
    normalized_type = payload.decision_type.strip().lower()
    if normalized_type not in {"exception", "risk_acceptance", "false_positive"}:
        raise WorkflowServiceError("Unsupported decision type.")
    workflow, _ = _get_or_create_workflow(db, finding_key=payload.finding_key, actor_session=actor_session)
    decision = WorkflowDecision(
        finding_workflow_id=workflow.id,
        decision_type=normalized_type,
        requester_user_id=actor_session.user_id,
        reason=payload.reason.strip(),
        business_justification=payload.business_justification.strip(),
        compensating_controls=payload.compensating_controls.strip(),
        start_date=_parse_date(payload.start_date),
        expiry_date=_parse_date(payload.expiry_date),
        review_date=_parse_date(payload.review_date),
        evidence=payload.evidence.strip(),
        status="requested",
        renewal_history="[]",
    )
    db.add(decision)
    db.flush()
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action=f"{normalized_type}.request",
        object_type="workflow_decision",
        object_id=decision.id,
        object_name=payload.finding_key,
        source_ip=source_ip,
        new_state=_to_decision_response(decision).model_dump(),
    )
    db.commit()
    db.refresh(decision)
    return _to_decision_response(decision)


def approve_workflow_decision(
    db: Session,
    *,
    actor_session: UserSession,
    decision_id: str,
    payload: WorkflowDecisionApproveRequest,
    source_ip: str,
) -> WorkflowDecisionResponse:
    decision = db.get(WorkflowDecision, decision_id)
    if decision is None:
        raise WorkflowServiceError("Decision not found.")
    workflow = db.get(FindingWorkflow, decision.finding_workflow_id)
    if workflow is None:
        raise WorkflowServiceError("Workflow not found.")
    previous_decision = _to_decision_response(decision).model_dump()
    previous_workflow = _to_workflow_response(workflow).model_dump()
    decision.status = "approved"
    decision.approver_user_id = actor_session.user_id
    decision.approved_at = utc_now()
    if decision.decision_type == "exception":
        workflow.workflow_status = "Exception Approved"
    elif decision.decision_type == "risk_acceptance":
        workflow.workflow_status = "Risk accepted"
    elif decision.decision_type == "false_positive":
        workflow.workflow_status = "False positive"
    workflow.updated_by_user_id = actor_session.user_id
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action=f"{decision.decision_type}.approve",
        object_type="workflow_decision",
        object_id=decision.id,
        object_name=workflow.finding_key,
        source_ip=source_ip,
        previous_state={"decision": previous_decision, "workflow": previous_workflow},
        new_state={"decision": _to_decision_response(decision).model_dump(), "workflow": _to_workflow_response(workflow).model_dump()},
        justification=payload.justification.strip(),
    )
    db.commit()
    db.refresh(decision)
    return _to_decision_response(decision)


def expire_workflow_decisions(
    db: Session,
    *,
    actor_session: UserSession,
    source_ip: str,
) -> WorkflowMaintenanceResponse:
    today = utc_now().date()
    expired = db.scalars(
        select(WorkflowDecision).where(
            WorkflowDecision.status == "approved",
            WorkflowDecision.expiry_date.is_not(None),
            WorkflowDecision.expiry_date < today,
        )
    ).all()
    count = 0
    for decision in expired:
        workflow = db.get(FindingWorkflow, decision.finding_workflow_id)
        if workflow is None:
            continue
        decision.status = "expired"
        renewal_history = json.loads(decision.renewal_history or "[]")
        renewal_history.append({"expired_at": ensure_utc(utc_now()).isoformat(), "status": "expired"})
        decision.renewal_history = json.dumps(renewal_history, sort_keys=True)
        if decision.decision_type in {"exception", "risk_acceptance"} and workflow.workflow_status in {"Exception Approved", "Risk accepted"}:
            workflow.workflow_status = "Open"
            workflow.validation_status = "Expired decision returned finding to the remediation queue."
            workflow.updated_by_user_id = actor_session.user_id
        count += 1
    if count:
        write_audit(
            db,
            actor_user_id=actor_session.user_id,
            action="workflow.decisions.expire",
            object_type="workflow_decision",
            object_name="expired_decisions",
            source_ip=source_ip,
            new_state={"expired_count": count},
        )
    db.commit()
    return WorkflowMaintenanceResponse(expired_count=count)
