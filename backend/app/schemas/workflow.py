from __future__ import annotations

from pydantic import BaseModel, Field


class FindingWorkflowUpdateRequest(BaseModel):
    owner: str = ""
    remediation_team: str = ""
    workflow_status: str = "Open"
    sla_start_date: str | None = None
    target_date: str | None = None
    actual_remediation_date: str | None = None
    ticket_number: str = ""
    ticket_url: str = ""
    comments: str = ""
    evidence: str = ""
    rescan_requested: bool = False
    validation_status: str = ""


class FindingWorkflowResponse(BaseModel):
    id: str
    finding_key: str
    asset_key: str
    workflow_status: str
    owner: str
    remediation_team: str
    sla_start_date: str | None
    due_date: str | None
    days_overdue: int
    target_date: str | None
    actual_remediation_date: str | None
    ticket_number: str
    ticket_url: str
    comments: str
    evidence: str
    rescan_requested: bool
    validation_status: str
    is_technically_open: bool


class WorkflowDecisionRequest(BaseModel):
    finding_key: str
    decision_type: str
    reason: str
    business_justification: str = ""
    compensating_controls: str = ""
    start_date: str | None = None
    expiry_date: str | None = None
    review_date: str | None = None
    evidence: str = ""


class WorkflowDecisionApproveRequest(BaseModel):
    justification: str = ""


class WorkflowDecisionResponse(BaseModel):
    id: str
    finding_workflow_id: str
    decision_type: str
    reason: str
    business_justification: str
    compensating_controls: str
    start_date: str | None
    expiry_date: str | None
    review_date: str | None
    evidence: str
    status: str
    renewal_history: str
    approved_at: str | None


class WorkflowDecisionListResponse(BaseModel):
    finding_key: str
    decisions: list[WorkflowDecisionResponse]


class WorkflowMaintenanceResponse(BaseModel):
    expired_count: int


class AssetReviewAssetSummary(BaseModel):
    stable_asset_key: str
    hostname: str = ""
    fqdn: str = ""
    ipv4_address: str = ""
    ipv6_address: str = ""
    tenable_asset_uuid: str = ""
    agent_uuid: str = ""


class AssetReviewResponse(BaseModel):
    id: str
    left_asset: AssetReviewAssetSummary
    right_asset: AssetReviewAssetSummary
    match_basis: list[str] = Field(default_factory=list)
    status: str
    canonical_asset_key: str = ""
    notes: str = ""
    resolved_at: str | None = None


class AssetReviewListResponse(BaseModel):
    total: int
    reviews: list[AssetReviewResponse]


class AssetMergeRequest(BaseModel):
    canonical_asset_key: str
    notes: str = ""


class AssetSplitRequest(BaseModel):
    notes: str = ""
