from __future__ import annotations

from pydantic import BaseModel


class ComparisonRunRequest(BaseModel):
    previous_import_job_id: str
    latest_import_job_id: str


class ComparisonResultResponse(BaseModel):
    id: str
    asset_key: str
    finding_key: str
    comparison_eligibility: str
    lifecycle_status: str
    reason: str


class ComparisonRunResponse(BaseModel):
    id: str
    previous_import_job_id: str
    latest_import_job_id: str
    status: str
    comparable_asset_count: int
    non_comparable_asset_count: int
    new_count: int
    existing_count: int
    closed_count: int
    reopened_count: int
    not_validated_count: int
    severity_changed_count: int
    port_changed_count: int
    created_at: str
    results: list[ComparisonResultResponse]
