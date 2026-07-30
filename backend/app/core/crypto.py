from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.core.config import Settings, get_settings


class SecretEncryptionError(ValueError):
    pass


def _decode_master_key(settings: Settings | None = None) -> bytes:
    settings = settings or get_settings()
    try:
        key = base64.urlsafe_b64decode(settings.nessus_master_key)
    except Exception as exc:  # pragma: no cover - defensive branch
        raise SecretEncryptionError("Nessus master key is not valid base64.") from exc
    if len(key) != 32:
        raise SecretEncryptionError("Nessus master key must decode to exactly 32 bytes.")
    return key


def encrypt_secret(value: str, *, settings: Settings | None = None) -> str:
    if not value:
        raise SecretEncryptionError("Secret value is required.")
    aesgcm = AESGCM(_decode_master_key(settings))
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
    return json.dumps(
        {
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        },
        sort_keys=True,
    )


def decrypt_secret(payload: str, *, settings: Settings | None = None) -> str:
    try:
        data = json.loads(payload)
        nonce = base64.urlsafe_b64decode(data["nonce"])
        ciphertext = base64.urlsafe_b64decode(data["ciphertext"])
    except Exception as exc:
        raise SecretEncryptionError("Encrypted secret payload is invalid.") from exc
    aesgcm = AESGCM(_decode_master_key(settings))
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"
