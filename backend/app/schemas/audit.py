from __future__ import annotations

from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    id: str
    actor_username: str
    timestamp: str
    source_ip: str
    action: str
    object_type: str
    object_id: str
    object_name: str
    result: str
    justification: str
    previous_state: str
    new_state: str


class AuditEventListResponse(BaseModel):
    total: int
    events: list[AuditEventResponse]
