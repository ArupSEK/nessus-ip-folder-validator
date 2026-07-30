from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.db.session import get_db
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.models.auth import UserSession
from backend.app.services.auth import AuthError, collect_permissions, validate_session


def get_source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_current_session(
    db: Session = Depends(get_db),
    session_token: str | None = Cookie(default=None, alias=get_settings().session_cookie_name),
) -> UserSession:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    try:
        return validate_session(db, session_token)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


def require_csrf(
    current_session: UserSession = Depends(get_current_session),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> UserSession:
    if not csrf_header or csrf_header != current_session.csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")
    return current_session


def require_permissions(*required: str):
    def dependency(current_session: UserSession = Depends(get_current_session)) -> UserSession:
        permissions = collect_permissions(current_session.user)
        if not set(required).issubset(permissions):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        return current_session

    return dependency


def require_superuser(current_session: UserSession = Depends(get_current_session)) -> UserSession:
    if not current_session.user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access is required.")
    return current_session


def get_nessus_client_factory() -> NessusClientFactory:
    return NessusClientFactory()
