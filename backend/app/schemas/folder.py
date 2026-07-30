from __future__ import annotations

from pydantic import BaseModel, Field


class FolderResponse(BaseModel):
    id: str
    nessus_folder_id: str
    name: str
    folder_type: str
    is_custom: bool
    owner: str
    permission_status: str
    scan_count: int
    last_synchronized_at: str | None = None
    deleted_at: str | None = None


class FolderListResponse(BaseModel):
    folders: list[FolderResponse]


class FolderCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class FolderRenameRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class FolderDeletePreviewResponse(BaseModel):
    folder: FolderResponse
    affected_scans: list[dict]
    deletion_behavior: str


class FolderDeleteRequest(BaseModel):
    confirmation_name: str
    current_password: str
