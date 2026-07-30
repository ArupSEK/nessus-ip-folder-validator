from __future__ import annotations

from pydantic import BaseModel, Field


class IpSearchRequest(BaseModel):
    entries: list[str] = Field(default_factory=list)
    expand_cidr: bool = False


class IpSearchMatch(BaseModel):
    query: str
    normalized_ip: str
    folder_name: str
    scan_name: str
    scan_status: str
    reachability: str
    authentication_status: str
    credentialed_checks_status: str
    last_scan_date: str | None = None


class IpSearchResultItem(BaseModel):
    query: str
    normalized_ip: str | None = None
    matches: list[IpSearchMatch] = Field(default_factory=list)


class IpSearchResponse(BaseModel):
    total_inputs: int
    unique_inputs: int
    invalid_inputs: list[str] = Field(default_factory=list)
    results: list[IpSearchResultItem] = Field(default_factory=list)
