from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import get_source_ip, require_csrf, require_permissions
from backend.app.db.session import get_db
from backend.app.models.workflow import WorkflowDecision
from backend.app.schemas.workflow import (
    AssetMergeRequest,
    AssetReviewListResponse,
    AssetReviewResponse,
    AssetSplitRequest,
    FindingWorkflowResponse,
    FindingWorkflowUpdateRequest,
    WorkflowDecisionListResponse,
    WorkflowDecisionApproveRequest,
    WorkflowDecisionRequest,
    WorkflowDecisionResponse,
    WorkflowMaintenanceResponse,
)
from backend.app.services.auth import collect_permissions
from backend.app.services.workflow import (
    WorkflowServiceError,
    approve_workflow_decision,
    expire_workflow_decisions,
    get_finding_workflow,
    list_asset_reviews,
    list_workflow_decisions,
    merge_asset_review,
    request_workflow_decision,
    split_asset_review,
    update_finding_workflow,
)

router = APIRouter(tags=["workflow"])


@router.get("/asset-reviews", response_model=AssetReviewListResponse)
def list_asset_reviews_route(
    status: str = "pending",
    _: object = Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> AssetReviewListResponse:
    return list_asset_reviews(db, status=status)


@router.post("/asset-reviews/{review_id}/merge", response_model=AssetReviewResponse)
def merge_asset_review_route(
    review_id: str,
    payload: AssetMergeRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("findings.override")),
    db: Session = Depends(get_db),
) -> AssetReviewResponse:
    try:
        return merge_asset_review(
            db,
            actor_session=current_session,
            review_id=review_id,
            payload=payload,
            source_ip=get_source_ip(request),
        )
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/asset-reviews/{review_id}/split", response_model=AssetReviewResponse)
def split_asset_review_route(
    review_id: str,
    payload: AssetSplitRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("findings.override")),
    db: Session = Depends(get_db),
) -> AssetReviewResponse:
    try:
        return split_asset_review(
            db,
            actor_session=current_session,
            review_id=review_id,
            payload=payload,
            source_ip=get_source_ip(request),
        )
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/findings/{finding_key}", response_model=FindingWorkflowResponse)
def get_workflow_route(
    finding_key: str,
    current_session=Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> FindingWorkflowResponse:
    try:
        return get_finding_workflow(db, finding_key=finding_key, actor_session=current_session)
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/findings/{finding_key}/decisions", response_model=WorkflowDecisionListResponse)
def list_decisions_route(
    finding_key: str,
    current_session=Depends(require_permissions("findings.view")),
    db: Session = Depends(get_db),
) -> WorkflowDecisionListResponse:
    try:
        return list_workflow_decisions(db, finding_key=finding_key, actor_session=current_session)
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/findings/{finding_key}", response_model=FindingWorkflowResponse)
def update_workflow_route(
    finding_key: str,
    payload: FindingWorkflowUpdateRequest,
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("findings.update")),
    db: Session = Depends(get_db),
) -> FindingWorkflowResponse:
    try:
        return update_finding_workflow(
            db,
            actor_session=current_session,
            finding_key=finding_key,
            payload=payload,
            source_ip=get_source_ip(request),
        )
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/decisions", response_model=WorkflowDecisionResponse)
def request_decision_route(
    payload: WorkflowDecisionRequest,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> WorkflowDecisionResponse:
    decision_permission = {
        "exception": "exceptions.request",
        "risk_acceptance": "risk_acceptance.request",
        "false_positive": "false_positive.request",
    }.get(payload.decision_type.strip().lower())
    permissions = collect_permissions(current_session.user)
    if decision_permission is None or decision_permission not in permissions:
        raise HTTPException(status_code=403, detail="Insufficient permissions.")
    try:
        return request_workflow_decision(
            db,
            actor_session=current_session,
            payload=payload,
            source_ip=get_source_ip(request),
        )
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/decisions/{decision_id}/approve", response_model=WorkflowDecisionResponse)
def approve_decision_route(
    decision_id: str,
    payload: WorkflowDecisionApproveRequest,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> WorkflowDecisionResponse:
    try:
        decision = db.get(WorkflowDecision, decision_id)
        if decision is None:
            raise HTTPException(status_code=404, detail="Decision not found.")
        decision_permission = {
            "exception": "exceptions.approve",
            "risk_acceptance": "risk_acceptance.approve",
            "false_positive": "false_positive.approve",
        }.get(decision.decision_type)
        permissions = collect_permissions(current_session.user)
        if decision_permission is None or decision_permission not in permissions:
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
        return approve_workflow_decision(
            db,
            actor_session=current_session,
            decision_id=decision_id,
            payload=payload,
            source_ip=get_source_ip(request),
        )
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/maintenance/expire", response_model=WorkflowMaintenanceResponse)
def expire_decisions_route(
    request: Request,
    current_session=Depends(require_csrf),
    _: object = Depends(require_permissions("exceptions.approve")),
    db: Session = Depends(get_db),
) -> WorkflowMaintenanceResponse:
    return expire_workflow_decisions(db, actor_session=current_session, source_ip=get_source_ip(request))
