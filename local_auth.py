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

from cryptography.fernet import Fernet, InvalidToken

AUTH_ITERATIONS = 310_000
VAULT_ITERATIONS = 390_000
DEFAULT_AUTH_PATH = Path.home() / ".nessus_ip_validator_auth.json"


class LocalAuthError(ValueError):
    """Raised when local login or encrypted settings are invalid."""


class LocalAuthManager:
    """Store one local administrator and an encrypted Nessus connection.

    The password is stored only as a salted PBKDF2-HMAC-SHA256 hash. Nessus
    connection details are encrypted with a separate password-derived Fernet
    key and are removed when the local account is reset.
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

    @staticmethod
    def derive_vault_key(
        password: str,
        salt: bytes,
        iterations: int = VAULT_ITERATIONS,
    ) -> bytes:
        raw_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )
        return base64.urlsafe_b64encode(raw_key)

    def configure(self, username: str, password: str) -> None:
        username = self._validate_username(username)
        self._validate_password(password)

        salt = secrets.token_bytes(16)
        vault_salt = secrets.token_bytes(16)
        password_hash = self.hash_password(password, salt)
        payload = {
            "version": 2,
            "username": username,
            "salt": base64.b64encode(salt).decode("ascii"),
            "password_hash": base64.b64encode(password_hash).decode("ascii"),
            "iterations": AUTH_ITERATIONS,
            "vault_salt": base64.b64encode(vault_salt).decode("ascii"),
            "vault_iterations": VAULT_ITERATIONS,
            "encrypted_connection": "",
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

    def unlock(self, password: str) -> tuple[bytes, dict[str, Any]]:
        """Unlock the encrypted connection after password verification.

        Existing version-1 login files are upgraded in place by adding a
        separate vault salt; they continue to use the same username/password.
        """
        payload = self.load()
        if not self.is_configured():
            raise LocalAuthError("The local account is not configured.")

        vault_salt_text = str(payload.get("vault_salt", ""))
        if not vault_salt_text:
            vault_salt = secrets.token_bytes(16)
            payload["version"] = 2
            payload["vault_salt"] = base64.b64encode(vault_salt).decode("ascii")
            payload["vault_iterations"] = VAULT_ITERATIONS
            payload.setdefault("encrypted_connection", "")
            self._write_atomic(payload)
        else:
            try:
                vault_salt = base64.b64decode(vault_salt_text, validate=True)
            except (ValueError, TypeError) as exc:
                raise LocalAuthError("The encrypted settings vault is corrupted.") from exc

        try:
            iterations = int(payload.get("vault_iterations", VAULT_ITERATIONS))
        except (TypeError, ValueError) as exc:
            raise LocalAuthError("The encrypted settings vault is corrupted.") from exc
        if iterations < 100_000 or iterations > 5_000_000:
            raise LocalAuthError("The encrypted settings vault is corrupted.")

        key = self.derive_vault_key(password, vault_salt, iterations)
        encrypted = str(payload.get("encrypted_connection", "") or "").strip()
        if not encrypted:
            return key, {}
        try:
            cleartext = Fernet(key).decrypt(encrypted.encode("ascii"))
            connection = json.loads(cleartext.decode("utf-8"))
        except (InvalidToken, ValueError, TypeError, UnicodeDecodeError) as exc:
            raise LocalAuthError(
                "Saved connection details could not be decrypted. Reset the local "
                "account if its password was changed outside this application."
            ) from exc
        if not isinstance(connection, dict):
            raise LocalAuthError("Saved connection details are invalid.")
        return key, connection

    def save_connection(self, connection: dict[str, Any], vault_key: bytes) -> None:
        payload = self.load()
        if not self.is_configured():
            raise LocalAuthError("The local account is not configured.")
        cleartext = json.dumps(connection, separators=(",", ":")).encode("utf-8")
        payload["version"] = 2
        payload["encrypted_connection"] = Fernet(vault_key).encrypt(cleartext).decode("ascii")
        payload["connection_updated_at"] = datetime.now(timezone.utc).isoformat()
        self._write_atomic(payload)

    def reset_account(self) -> None:
        """Delete the login and encrypted Nessus connection from this device."""
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise LocalAuthError(f"Could not reset the local account: {exc}") from exc
        for temporary_path in self.path.parent.glob(f".{self.path.name}.*.tmp"):
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
