from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

AUTH_ITERATIONS = 310_000
DEFAULT_AUTH_PATH = Path.home() / ".nessus_ip_validator_auth.json"


class LocalAuthError(ValueError):
    """Raised when local login configuration is invalid."""


class LocalAuthManager:
    """Store and verify one local administrator account.

    Only a PBKDF2-HMAC-SHA256 password hash and random salt are written to disk.
    The plaintext password is never stored.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        env_path = os.getenv("NESSUS_VALIDATOR_AUTH_FILE", "").strip()
        self.path = Path(path or env_path or DEFAULT_AUTH_PATH).expanduser()

    def is_configured(self) -> bool:
        payload = self.load()
        return bool(
            payload.get("username")
            and payload.get("salt")
            and payload.get("password_hash")
        )

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def configured_username(self) -> str:
        return str(self.load().get("username", ""))

    @staticmethod
    def _validate_username(username: str) -> str:
        cleaned = username.strip()
        if not cleaned:
            raise LocalAuthError("Username is required.")
        if len(cleaned) > 128:
            raise LocalAuthError("Username must be 128 characters or fewer.")
        return cleaned

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 8:
            raise LocalAuthError("Password must be at least 8 characters.")
        if len(password) > 1024:
            raise LocalAuthError("Password is too long.")

    @staticmethod
    def hash_password(
        password: str,
        salt: bytes,
        iterations: int = AUTH_ITERATIONS,
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

    def configure(self, username: str, password: str) -> None:
        username = self._validate_username(username)
        self._validate_password(password)

        salt = secrets.token_bytes(16)
        password_hash = self.hash_password(password, salt)
        payload = {
            "version": 1,
            "username": username,
            "salt": base64.b64encode(salt).decode("ascii"),
            "password_hash": base64.b64encode(password_hash).decode("ascii"),
            "iterations": AUTH_ITERATIONS,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._write_atomic(payload)

    def _write_atomic(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_name(
            f".{self.path.name}.{secrets.token_hex(6)}.tmp"
        )
        try:
            temporary_path.write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )
            try:
                temporary_path.chmod(0o600)
            except OSError:
                # Windows and some mounted filesystems may not support POSIX mode.
                pass
            os.replace(temporary_path, self.path)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

    def verify(self, username: str, password: str) -> bool:
        payload = self.load()
        stored_username = str(payload.get("username", ""))
        try:
            username_matches = hmac.compare_digest(
                username.strip().encode("utf-8"),
                stored_username.encode("utf-8"),
            )
            salt = base64.b64decode(payload.get("salt", ""), validate=True)
            expected = base64.b64decode(
                payload.get("password_hash", ""),
                validate=True,
            )
            iterations = int(payload.get("iterations", AUTH_ITERATIONS))
            if iterations < 100_000 or iterations > 5_000_000:
                return False
            actual = self.hash_password(password, salt, iterations)
        except (ValueError, TypeError, OverflowError):
            return False
        return username_matches and hmac.compare_digest(actual, expected)
