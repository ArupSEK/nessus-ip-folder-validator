from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_session, get_source_ip, require_csrf, require_permissions
from backend.app.core.config import get_settings
from backend.app.db.session import get_db
from backend.app.schemas.auth import (
    ChangePasswordRequest,
    GenericMessage,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    PasswordResetRequestResponse,
    SessionResponse,
)
from backend.app.services.auth import (
    AuthError,
    authenticate_user,
    change_password,
    collect_permissions,
    confirm_password_reset,
    create_session,
    logout_session,
    request_password_reset,
)

router = APIRouter(tags=["auth"])


def _set_auth_cookies(response: Response, session_token: str, csrf_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name,
        session_token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def _clear_auth_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> LoginResponse:
    try:
        user = authenticate_user(db, username=payload.username, password=payload.password, source_ip=get_source_ip(request))
        session_token, csrf_token, _ = create_session(
            db,
            user=user,
            source_ip=get_source_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    permissions = sorted(collect_permissions(user))
    roles = sorted(role.name for role in user.roles)
    _set_auth_cookies(response, session_token, csrf_token)
    return LoginResponse(username=user.username, roles=roles, permissions=permissions, csrf_token=csrf_token)


@router.post("/logout", response_model=GenericMessage)
def logout(
    response: Response,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> GenericMessage:
    logout_session(db, current_session, source_ip=get_source_ip(request))
    _clear_auth_cookies(response)
    return GenericMessage(message="Logged out.")


@router.get("/me", response_model=SessionResponse)
def me(current_session=Depends(get_current_session)) -> SessionResponse:
    user = current_session.user
    return SessionResponse(
        username=user.username,
        roles=sorted(role.name for role in user.roles),
        permissions=sorted(collect_permissions(user)),
        csrf_token=current_session.csrf_token,
    )


@router.post("/change-password", response_model=GenericMessage)
def change_password_route(
    payload: ChangePasswordRequest,
    request: Request,
    current_session=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> GenericMessage:
    try:
        change_password(
            db,
            user=current_session.user,
            current_password=payload.current_password,
            new_password=payload.new_password,
            source_ip=get_source_ip(request),
        )
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return GenericMessage(message="Password changed. Please log in again.")


@router.post("/password-reset/request", response_model=PasswordResetRequestResponse)
def password_reset_request(
    payload: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PasswordResetRequestResponse:
    _, token = request_password_reset(db, username=payload.username, source_ip=get_source_ip(request))
    return PasswordResetRequestResponse(message="If the account exists, a reset token has been generated.", reset_token=token)


@router.post("/password-reset/confirm", response_model=GenericMessage)
def password_reset_confirm(
    payload: PasswordResetConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> GenericMessage:
    try:
        confirm_password_reset(db, token=payload.token, new_password=payload.new_password, source_ip=get_source_ip(request))
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return GenericMessage(message="Password reset completed.")


@router.get("/audit-access-check", response_model=GenericMessage)
def audit_access_check(_=Depends(require_permissions("audit.view"))) -> GenericMessage:
    return GenericMessage(message="Permission granted.")
