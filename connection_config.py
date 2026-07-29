from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


class ConnectionConfigError(ValueError):
    """Raised when Nessus/Tenable connection settings are incomplete or invalid."""


def validate_connection(
    base_url: object,
    access_key: object,
    secret_key: object,
    verify_ssl: object = True,
    timeout: object = 90,
) -> dict[str, Any]:
    """Return normalized connection settings or raise a user-facing error."""
    url = str(base_url or "").strip().rstrip("/")
    access = str(access_key or "").strip()
    secret = str(secret_key or "").strip()

    if not url:
        raise ConnectionConfigError("Nessus / Tenable Base URL is required.")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConnectionConfigError(
            "Enter a complete URL such as https://cloud.tenable.com or "
            "https://192.168.1.10:8834."
        )
    if parsed.username or parsed.password:
        raise ConnectionConfigError("Do not include a username or password in the URL.")
    if not access:
        raise ConnectionConfigError("Access Key is required.")
    if not secret:
        raise ConnectionConfigError("Secret Key is required.")
    if len(access) > 4096 or len(secret) > 4096:
        raise ConnectionConfigError("The API key value is unexpectedly long.")

    try:
        timeout_value = int(timeout)
    except (TypeError, ValueError) as exc:
        raise ConnectionConfigError("API timeout must be a whole number.") from exc
    if timeout_value < 15 or timeout_value > 300:
        raise ConnectionConfigError("API timeout must be between 15 and 300 seconds.")

    return {
        "base_url": url,
        "access_key": access,
        "secret_key": secret,
        "verify_ssl": bool(verify_ssl),
        "timeout": timeout_value,
    }
