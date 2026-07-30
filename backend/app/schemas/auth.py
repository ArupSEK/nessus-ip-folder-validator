from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    username: str
    roles: list[str]
    permissions: list[str]
    csrf_token: str


class SessionResponse(BaseModel):
    username: str
    roles: list[str]
    permissions: list[str]
    csrf_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class PasswordResetRequest(BaseModel):
    username: str


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str


class GenericMessage(BaseModel):
    message: str


class PasswordResetRequestResponse(GenericMessage):
    reset_token: str | None = None
