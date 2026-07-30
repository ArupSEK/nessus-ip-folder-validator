from __future__ import annotations

from pydantic import BaseModel, Field


class ImportScanRequest(BaseModel):
    scan_history_record_id: str | None = None
    force_reimport: bool = False


class ImportRecoverRequest(BaseModel):
    force_restart: bool = False


class ImportJobResponse(BaseModel):
    id: str
    scan_record_id: str
    scan_history_record_id: str | None = None
    status: str
    progress_percent: int
    export_format: str
    export_file_id: str
    export_status: str
    imported_asset_count: int
    imported_finding_count: int
    error_message: str
    last_checkpoint: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None


class ImportJobListResponse(BaseModel):
    jobs: list[ImportJobResponse]


class AssetResponse(BaseModel):
    id: str
    stable_asset_key: str
    hostname: str
    fqdn: str
    ipv4_address: str
    ipv6_address: str


class FindingResponse(BaseModel):
    id: str
    finding_key: str
    asset_record_id: str
    plugin_id: int
    plugin_name: str
    severity: int
    port: int
    protocol: str


class ImportResultResponse(BaseModel):
    job: ImportJobResponse
    assets: list[AssetResponse] = Field(default_factory=list)
    findings: list[FindingResponse] = Field(default_factory=list)
