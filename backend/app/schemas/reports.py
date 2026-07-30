from __future__ import annotations

from pydantic import BaseModel


class ExportResponse(BaseModel):
    filename: str
    content_type: str
