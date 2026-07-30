from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.core.config import Settings, get_settings
from backend.app.core.security import hash_password, new_token, token_hash, verify_password
from backend.app.models.auth import PasswordResetToken, Permission, Role, User, UserSession
from backend.app.services.audit import write_audit

PERMISSION_CODES = [
    "folders.view", "folders.create", "folders.rename", "folders.delete",
    "scans.view", "scans.create", "scans.edit", "scans.clone", "scans.move", "scans.launch", "scans.pause", "scans.resume", "scans.stop", "scans.delete", "scans.restore", "scans.permanent_delete", "scan_history.view", "scan_history.delete", "scan_credentials.manage",
    "findings.view", "findings.assign", "findings.update", "findings.close", "findings.override", "exceptions.request", "exceptions.approve", "risk_acceptance.request", "risk_acceptance.approve", "false_positive.request", "false_positive.approve", "reports.export", "audit.view",
]

ROLE_DEFAULTS = [
    "Administrator",
    "Scan Manager",
    "Vulnerability Analyst",
    "Remediation Owner",
    "Reviewer",
    "Auditor",
    "Read-only User",
]


class AuthError(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def normalize_username(username: str) -> str:
    cleaned = username.strip()
    if not cleaned:
        raise AuthError("Username is required.")
    if len(cleaned) > 150:
        raise AuthError("Username is too long.")
    return cleaned


def validate_password_rules(password: str) -> None:
    if len(password) < 12:
        raise AuthError("Password must be at least 12 characters.")


def seed_authorization_data(db: Session) -> None:
    existing_permissions = {perm.code for perm in db.scalars(select(Permission)).all()}
    for code in PERMISSION_CODES:
        if code not in existing_permissions:
            db.add(Permission(code=code, description=code))
    existing_roles = {role.name for role in db.scalars(select(Role)).all()}
    for name in ROLE_DEFAULTS:
        if name not in existing_roles:
            db.add(Role(name=name, description=name))
    db.flush()

    admin_role = db.scalar(select(Role).where(Role.name == "Administrator"))
    if admin_role is not None:
        permissions = db.scalars(select(Permission)).all()
        admin_role.permissions = permissions


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role_names: list[str],
    is_superuser: bool = False,
) -> User:
    username = normalize_username(username)
    validate_password_rules(password)
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise AuthError("Username already exists.")
    seed_authorization_data(db)
    roles = db.scalars(select(Role).where(Role.name.in_(role_names))).all() if role_names else []
    user = User(
        username=username,
        password_hash=hash_password(password),
        is_active=True,
        is_superuser=is_superuser,
        roles=roles,
    )
    db.add(user)
    return user


def bootstrap_admin(db: Session, *, username: str, password: str) -> User:
    existing_admin = db.scalar(select(User).where(User.is_superuser.is_(True)))
    if existing_admin is not None:
        raise AuthError("An administrator already exists.")
    user = create_user(
        db,
        username=username,
        password=password,
        role_names=["Administrator"],
        is_superuser=True,
    )
    write_audit(
        db,
        actor_user_id=user.id,
        action="auth.bootstrap_admin",
        object_type="user",
        object_id=user.id,
        object_name=user.username,
    )
    db.commit()
    db.refresh(user)
    return user


def get_user_with_access(db: Session, username: str) -> User | None:
    return db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(Role.permissions))
        .where(User.username == username)
    )


def collect_permissions(user: User) -> set[str]:
    if user.is_superuser:
        return set(PERMISSION_CODES)
    out: set[str] = set()
    for role in user.roles:
        for permission in role.permissions:
            out.add(permission.code)
    return out


def authenticate_user(db: Session, *, username: str, password: str, source_ip: str = "", settings: Settings | None = None) -> User:
    settings = settings or get_settings()
    user = get_user_with_access(db, username.strip())
    if user is None:
        write_audit(db, actor_user_id=None, action="auth.login", object_type="session", source_ip=source_ip, result="failure")
        db.commit()
        raise AuthError("Invalid credentials.")
    now = utc_now()
    locked_until = ensure_utc(user.locked_until)
    if locked_until and locked_until > now:
        write_audit(db, actor_user_id=user.id, action="auth.login.locked", object_type="user", object_id=user.id, object_name=user.username, source_ip=source_ip, result="failure")
        db.commit()
        raise AuthError("Account is locked.")
    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.login_max_attempts:
            user.failed_login_attempts = 0
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
        write_audit(db, actor_user_id=user.id, action="auth.login", object_type="session", object_id=user.id, object_name=user.username, source_ip=source_ip, result="failure")
        db.commit()
        raise AuthError("Invalid credentials.")
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    write_audit(db, actor_user_id=user.id, action="auth.login", object_type="session", object_id=user.id, object_name=user.username, source_ip=source_ip)
    db.flush()
    return user


def create_session(db: Session, *, user: User, source_ip: str = "", user_agent: str = "", settings: Settings | None = None) -> tuple[str, str, UserSession]:
    settings = settings or get_settings()
    raw_token = new_token()
    csrf_token = new_token()
    session = UserSession(
        user_id=user.id,
        session_token_hash=token_hash(raw_token),
        csrf_token=csrf_token,
        ip_address=source_ip,
        user_agent=user_agent[:255],
        expires_at=utc_now() + timedelta(minutes=settings.session_timeout_minutes),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return raw_token, csrf_token, session


def get_session_by_token(db: Session, raw_token: str) -> UserSession | None:
    hashed = token_hash(raw_token)
    return db.scalar(
        select(UserSession)
        .options(selectinload(UserSession.user).selectinload(User.roles).selectinload(Role.permissions))
        .where(UserSession.session_token_hash == hashed)
    )


def validate_session(db: Session, raw_token: str) -> UserSession:
    session = get_session_by_token(db, raw_token)
    if session is None or session.revoked_at is not None:
        raise AuthError("Authentication required.")
    expires_at = ensure_utc(session.expires_at)
    if expires_at is not None and expires_at <= utc_now():
        session.revoked_at = utc_now()
        db.commit()
        raise AuthError("Session expired.")
    if not session.user.is_active:
        raise AuthError("User is inactive.")
    session.last_seen_at = utc_now()
    db.commit()
    db.refresh(session)
    return session


def logout_session(db: Session, session: UserSession, *, source_ip: str = "") -> None:
    session.revoked_at = utc_now()
    write_audit(db, actor_user_id=session.user_id, action="auth.logout", object_type="session", object_id=session.id, object_name=session.user.username, source_ip=source_ip)
    db.commit()


def change_password(db: Session, *, user: User, current_password: str, new_password: str, source_ip: str = "") -> None:
    if not verify_password(current_password, user.password_hash):
        raise AuthError("Current password is invalid.")
    validate_password_rules(new_password)
    user.password_hash = hash_password(new_password)
    for session in user.sessions:
        session.revoked_at = utc_now()
    write_audit(db, actor_user_id=user.id, action="auth.change_password", object_type="user", object_id=user.id, object_name=user.username, source_ip=source_ip)
    db.commit()


def request_password_reset(db: Session, *, username: str, source_ip: str = "", settings: Settings | None = None) -> tuple[bool, str | None]:
    settings = settings or get_settings()
    user = get_user_with_access(db, username.strip())
    if user is None:
        return False, None
    raw_token = new_token()
    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash(raw_token),
        expires_at=utc_now() + timedelta(minutes=settings.password_reset_token_minutes),
    )
    db.add(reset)
    write_audit(db, actor_user_id=user.id, action="auth.password_reset.request", object_type="user", object_id=user.id, object_name=user.username, source_ip=source_ip)
    db.commit()
    return True, raw_token if settings.app_debug else None


def confirm_password_reset(db: Session, *, token: str, new_password: str, source_ip: str = "") -> None:
    validate_password_rules(new_password)
    reset = db.scalar(
        select(PasswordResetToken)
        .options(selectinload(PasswordResetToken.user).selectinload(User.sessions))
        .where(PasswordResetToken.token_hash == token_hash(token))
    )
    reset_expires_at = ensure_utc(reset.expires_at) if reset is not None else None
    if reset is None or reset.used_at is not None or reset_expires_at is None or reset_expires_at <= utc_now():
        raise AuthError("Reset token is invalid or expired.")
    reset.user.password_hash = hash_password(new_password)
    reset.used_at = utc_now()
    for session in reset.user.sessions:
        session.revoked_at = utc_now()
    write_audit(db, actor_user_id=reset.user.id, action="auth.password_reset.confirm", object_type="user", object_id=reset.user.id, object_name=reset.user.username, source_ip=source_ip)
    db.commit()
