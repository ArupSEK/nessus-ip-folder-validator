from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl, field_validator


class NessusConfigurationBase(BaseModel):
    base_url: HttpUrl
    access_key: str = Field(min_length=8, max_length=255)
    secret_key: str = Field(min_length=8, max_length=255)
    verify_tls: bool = True
    timeout_seconds: int = Field(default=15, ge=1, le=120)
    approved_hosts: list[str] = Field(default_factory=list)

    @field_validator("approved_hosts")
    @classmethod
    def normalize_hosts(cls, value: list[str]) -> list[str]:
        return sorted({item.strip().lower() for item in value if item.strip()})


class NessusConfigurationSaveRequest(NessusConfigurationBase):
    pass


class NessusConfigurationTestRequest(NessusConfigurationBase):
    pass


class NessusConfigurationResetRequest(BaseModel):
    current_password: str
    confirmation_text: str


class NessusConfigurationResponse(BaseModel):
    configured: bool
    base_url: str | None = None
    verify_tls: bool = True
    timeout_seconds: int | None = None
    approved_hosts: list[str] = Field(default_factory=list)
    masked_access_key: str | None = None
    masked_secret_key: str | None = None
    server_info: dict = Field(default_factory=dict)
    api_permissions: list[str] = Field(default_factory=list)
    capabilities: dict = Field(default_factory=dict)
    validated_at: str | None = None


class NessusValidationResponse(BaseModel):
    base_url: str
    verify_tls: bool
    timeout_seconds: int
    approved_hosts: list[str] = Field(default_factory=list)
    server_info: dict = Field(default_factory=dict)
    api_permissions: list[str] = Field(default_factory=list)
    capabilities: dict = Field(default_factory=dict)
