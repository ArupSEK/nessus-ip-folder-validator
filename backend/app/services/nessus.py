from __future__ import annotations

from datetime import timedelta
import ipaddress
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import Settings, get_settings
from backend.app.core.crypto import decrypt_secret, encrypt_secret, mask_secret
from backend.app.core.security import verify_password
from backend.app.integrations.nessus.client import (
    ConnectionValidationResult,
    NessusAuthenticationError,
    NessusClientError,
    NessusClientFactory,
    NessusConnectivityError,
    NessusRateLimitError,
    NessusResponseError,
)
from backend.app.models.auth import UserSession
from backend.app.models.nessus import NessusConfiguration
from backend.app.schemas.nessus import (
    NessusConfigurationResetRequest,
    NessusConfigurationSaveRequest,
    NessusConfigurationTestRequest,
    NessusConfigurationResponse,
    NessusValidationResponse,
)
from backend.app.services.audit import write_audit
from backend.app.services.auth import ensure_utc, utc_now

RESET_CONFIRMATION_TEXT = "RESET NESSUS CREDENTIALS"


class NessusConfigError(ValueError):
    pass


def _normalize_base_url(base_url: str, approved_hosts: list[str]) -> str:
    parsed = urlparse(base_url.strip())
    if parsed.scheme.lower() != "https":
        raise NessusConfigError("Nessus URL must use HTTPS.")
    if parsed.username or parsed.password:
        raise NessusConfigError("Embedded credentials are not allowed in the Nessus URL.")
    if not parsed.hostname:
        raise NessusConfigError("Nessus URL must include a hostname.")
    host = parsed.hostname.lower()
    normalized_allowlist = {item.strip().lower() for item in approved_hosts if item.strip()}
    try:
        ip_value = ipaddress.ip_address(host)
    except ValueError:
        ip_value = None
    if ip_value is not None and (
        ip_value.is_private
        or ip_value.is_loopback
        or ip_value.is_link_local
        or ip_value.is_multicast
        or ip_value.is_unspecified
        or ip_value.is_reserved
    ):
        if host not in normalized_allowlist:
            raise NessusConfigError("The Nessus host is blocked by SSRF protection.")
    if host == "localhost" and host not in normalized_allowlist:
        raise NessusConfigError("The Nessus host is blocked by SSRF protection.")
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{parsed.netloc}{path}"


def _to_response(config: NessusConfiguration | None) -> NessusConfigurationResponse:
    if config is None:
        return NessusConfigurationResponse(configured=False)
    validated_at = ensure_utc(config.validated_at)
    return NessusConfigurationResponse(
        configured=True,
        base_url=config.base_url,
        verify_tls=config.verify_tls,
        timeout_seconds=config.timeout_seconds,
        approved_hosts=config.approved_hosts,
        masked_access_key=config.masked_access_key,
        masked_secret_key=config.masked_secret_key,
        server_info=config.server_info or {},
        api_permissions=config.api_permissions or [],
        capabilities=config.capabilities or {},
        validated_at=validated_at.isoformat() if validated_at else None,
    )


def get_nessus_configuration(db: Session) -> NessusConfigurationResponse:
    config = db.scalar(select(NessusConfiguration).limit(1))
    return _to_response(config)


def get_nessus_configuration_model(db: Session) -> NessusConfiguration | None:
    return db.scalar(select(NessusConfiguration).limit(1))


def _validate_with_client(
    payload: NessusConfigurationSaveRequest | NessusConfigurationTestRequest,
    *,
    client_factory: NessusClientFactory,
) -> ConnectionValidationResult:
    normalized_url = _normalize_base_url(str(payload.base_url), payload.approved_hosts)
    client = client_factory.create(
        base_url=normalized_url,
        access_key=payload.access_key,
        secret_key=payload.secret_key,
        verify_tls=payload.verify_tls,
        timeout_seconds=payload.timeout_seconds,
    )
    return client.validate_connection(approved_hosts=payload.approved_hosts)


def build_saved_nessus_client(db: Session, *, client_factory: NessusClientFactory):
    config = get_nessus_configuration_model(db)
    if config is None:
        raise NessusConfigError("Nessus configuration has not been saved yet.")
    return (
        config,
        client_factory.create(
            base_url=config.base_url,
            access_key=decrypt_secret(config.access_key_encrypted),
            secret_key=decrypt_secret(config.secret_key_encrypted),
            verify_tls=config.verify_tls,
            timeout_seconds=config.timeout_seconds,
        ),
    )


def ensure_nessus_role_access(config: NessusConfiguration, allowed_roles: set[str]) -> None:
    permissions = {item.upper() for item in (config.api_permissions or [])}
    if not permissions:
        return
    if permissions.isdisjoint(allowed_roles):
        raise NessusConfigError("The stored Nessus API account does not have the required Nessus role for this action.")


def test_nessus_configuration(
    db: Session,
    *,
    actor_session: UserSession,
    payload: NessusConfigurationTestRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> NessusValidationResponse:
    result = _validate_with_client(payload, client_factory=client_factory)
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="nessus.configuration.test",
        object_type="nessus_configuration",
        object_name=result.base_url,
        source_ip=source_ip,
        new_state={"base_url": result.base_url, "verify_tls": result.verify_tls, "timeout_seconds": result.timeout_seconds},
    )
    db.commit()
    return NessusValidationResponse.model_validate(result.model_dump())


def save_nessus_configuration(
    db: Session,
    *,
    actor_session: UserSession,
    payload: NessusConfigurationSaveRequest,
    source_ip: str,
    client_factory: NessusClientFactory,
) -> NessusConfigurationResponse:
    result = _validate_with_client(payload, client_factory=client_factory)
    existing = db.scalar(select(NessusConfiguration).limit(1))
    previous_state = existing.server_info if existing is not None else {}
    if existing is None:
        config = NessusConfiguration(
            base_url=result.base_url,
            verify_tls=result.verify_tls,
            timeout_seconds=result.timeout_seconds,
            approved_hosts=result.approved_hosts,
            access_key_encrypted=encrypt_secret(payload.access_key),
            secret_key_encrypted=encrypt_secret(payload.secret_key),
            masked_access_key=mask_secret(payload.access_key),
            masked_secret_key=mask_secret(payload.secret_key),
            server_info=result.server_info,
            api_permissions=result.api_permissions,
            capabilities=result.capabilities,
            validated_at=utc_now(),
            updated_by_user_id=actor_session.user_id,
        )
        db.add(config)
    else:
        config = existing
        config.base_url = result.base_url
        config.verify_tls = result.verify_tls
        config.timeout_seconds = result.timeout_seconds
        config.approved_hosts = result.approved_hosts
        config.access_key_encrypted = encrypt_secret(payload.access_key)
        config.secret_key_encrypted = encrypt_secret(payload.secret_key)
        config.masked_access_key = mask_secret(payload.access_key)
        config.masked_secret_key = mask_secret(payload.secret_key)
        config.server_info = result.server_info
        config.api_permissions = result.api_permissions
        config.capabilities = result.capabilities
        config.validated_at = utc_now()
        config.updated_by_user_id = actor_session.user_id
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="nessus.configuration.save",
        object_type="nessus_configuration",
        object_name=result.base_url,
        source_ip=source_ip,
        previous_state=previous_state,
        new_state={
            "base_url": result.base_url,
            "verify_tls": result.verify_tls,
            "timeout_seconds": result.timeout_seconds,
            "approved_hosts": result.approved_hosts,
            "masked_access_key": mask_secret(payload.access_key),
            "masked_secret_key": mask_secret(payload.secret_key),
            "capabilities": result.capabilities,
        },
    )
    db.commit()
    db.refresh(config)
    return _to_response(config)


def reset_nessus_configuration(
    db: Session,
    *,
    actor_session: UserSession,
    payload: NessusConfigurationResetRequest,
    source_ip: str,
    settings: Settings | None = None,
) -> None:
    settings = settings or get_settings()
    if payload.confirmation_text != RESET_CONFIRMATION_TEXT:
        raise NessusConfigError(f"Confirmation text must be exactly '{RESET_CONFIRMATION_TEXT}'.")
    if not verify_password(payload.current_password, actor_session.user.password_hash):
        raise NessusConfigError("Current password is invalid.")
    now = utc_now()
    recent_reauth = ensure_utc(actor_session.reauthenticated_at)
    if recent_reauth is None or recent_reauth < now - timedelta(minutes=settings.nessus_reauth_window_minutes):
        actor_session.reauthenticated_at = now
    config = db.scalar(select(NessusConfiguration).limit(1))
    previous_state = {} if config is None else {
        "base_url": config.base_url,
        "verify_tls": config.verify_tls,
        "timeout_seconds": config.timeout_seconds,
        "approved_hosts": config.approved_hosts,
        "masked_access_key": config.masked_access_key,
        "masked_secret_key": config.masked_secret_key,
    }
    if config is not None:
        db.delete(config)
    write_audit(
        db,
        actor_user_id=actor_session.user_id,
        action="nessus.configuration.reset",
        object_type="nessus_configuration",
        object_name=previous_state.get("base_url", ""),
        source_ip=source_ip,
        previous_state=previous_state,
        new_state={},
        justification="Administrator initiated Nessus credential reset.",
    )
    db.commit()


def translate_nessus_error(exc: Exception) -> tuple[int, str]:
    if isinstance(exc, NessusConfigError):
        return 400, str(exc)
    if isinstance(exc, NessusAuthenticationError):
        return 400, str(exc)
    if isinstance(exc, NessusRateLimitError):
        return 503, str(exc)
    if isinstance(exc, (NessusConnectivityError, NessusResponseError, NessusClientError)):
        return 502, str(exc)
    return 500, "Nessus integration failed."
