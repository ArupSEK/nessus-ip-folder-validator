from __future__ import annotations

from pydantic import BaseModel, Field


class ScanResponse(BaseModel):
    id: str
    nessus_scan_id: str
    nessus_uuid: str
    name: str
    folder_record_id: str | None = None
    folder_nessus_id: str
    folder_name: str
    template_uuid: str
    scanner_id: str
    targets: list[str]
    target_count: int
    schedule_type: str
    owner: str
    status: str
    history_count: int
    permission_status: str
    last_launch_at: str | None = None
    last_completion_at: str | None = None
    last_synchronized_at: str | None = None
    deleted_at: str | None = None


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]


class TemplateResponse(BaseModel):
    uuid: str
    title: str


class TemplateListResponse(BaseModel):
    templates: list[TemplateResponse]


class PolicyResponse(BaseModel):
    id: str
    name: str
    template_uuid: str
    owner: str
    has_credentials: bool


class PolicyListResponse(BaseModel):
    policies: list[PolicyResponse]


class ScannerResponse(BaseModel):
    id: str
    name: str
    type: str
    status: str


class ScannerListResponse(BaseModel):
    scanners: list[ScannerResponse]


class ScanHistoryResponse(BaseModel):
    id: str
    nessus_history_id: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    finding_count: int
    is_baseline_locked: bool
    is_evidence_locked: bool
    deleted_at: str | None = None


class ScanHistoryListResponse(BaseModel):
    histories: list[ScanHistoryResponse]


class ScanCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    folder_record_id: str
    template_uuid: str | None = Field(default=None, min_length=1, max_length=255)
    policy_id: str | None = Field(default=None, min_length=1, max_length=255)
    clone_from_scan_record_id: str | None = Field(default=None, min_length=1, max_length=255)
    scanner_id: str | None = None
    targets: list[str] = Field(default_factory=list)
    schedule_type: str = Field(default="on_demand")
    launch_now: bool = False


class ScanUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    folder_record_id: str | None = None
    scanner_id: str | None = None
    targets: list[str] | None = None
    schedule_type: str | None = None


class ScanCloneRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    folder_record_id: str | None = None
    scanner_id: str | None = None
    launch_now: bool = False


class ScanMoveRequest(BaseModel):
    folder_record_id: str


class ScanHistoryDeleteRequest(BaseModel):
    justification: str = Field(default="", max_length=500)
