from __future__ import annotations

from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class AssetCoverageSummary(BaseModel):
    total_assets: int
    assets_found: int
    assets_not_found: int
    scanned_assets: int
    unscanned_assets: int
    reachable_assets: int
    unreachable_assets: int
    authentication_passed: int
    authentication_failed: int
    credentialed_checks_passed: int
    credentialed_checks_failed: int
    comparable_assets: int
    non_comparable_assets: int


class DashboardSummaryResponse(BaseModel):
    comparison_run_id: str
    previous_total: int
    latest_total: int
    new: int
    existing: int
    closed: int
    reopened: int
    not_validated: int
    severity_changed: int
    accepted_risk: int
    false_positive: int
    exceptions: int
    sla_overdue: int
    severity_breakdown: SeverityBreakdown
    asset_coverage: AssetCoverageSummary


class DashboardFindingResponse(BaseModel):
    result_id: str
    asset_key: str
    finding_key: str
    lifecycle_status: str
    comparison_eligibility: str
    severity: int
    plugin_id: int
    plugin_name: str
    port: int
    protocol: str
    reason: str


class DashboardFindingListResponse(BaseModel):
    comparison_run_id: str
    total: int
    findings: list[DashboardFindingResponse]
