"""Application-level secrets encryption for scanner credentials.

Provides AES-256-GCM encryption/decryption for sensitive metadata fields
(headers, body, credentials) stored in connection_registry.

Storage format: "enc:v1:<base64(nonce‖ciphertext‖tag)>"
  - The "enc:v1:" prefix allows detection of encrypted values and future
    versioning of the encryption scheme.
  - nonce: 12 bytes (GCM standard)
  - tag: 16 bytes (appended by GCM)

The encryption key is read from the SECRETS_ENCRYPTION_KEY env var (base64-
encoded, 32 bytes decoded). If the key is absent, encryption is disabled and
a warning is logged — this allows local dev without mandatory key setup.

Enterprise extensibility:
  - SECRETS_BACKEND setting controls which backend is used. Currently only
    "local" (AES-256-GCM) is implemented. Future values: "aws_secrets_manager",
    "hashicorp_vault".
  - SENSITIVE_METADATA_FIELDS controls which metadata keys are encrypted.
  - ENFORCE_HTTPS_ENDPOINTS blocks saving auth headers against http:// URLs.

Usage:
  from app.crypto import encrypt_sensitive_fields, decrypt_sensitive_fields, redact_sensitive_fields
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_ENC_PREFIX = "enc:v1:"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def _load_encryption_key() -> bytes | None:
    """Load the 32-byte AES key from settings (which reads .env).

    Uses the pydantic Settings object so the key source is consistent with
    all other config — no need to separately export to os.environ.
    """
    from .config import settings

    raw = (settings.secrets_encryption_key or "").strip()
    if not raw:
        return None
    try:
        key = base64.b64decode(raw)
        if len(key) != 32:
            logger.error(
                "SECRETS_ENCRYPTION_KEY must decode to exactly 32 bytes (got %d). "
                "Encryption disabled.",
                len(key),
            )
            return None
        return key
    except Exception:
        logger.error("SECRETS_ENCRYPTION_KEY is not valid base64. Encryption disabled.")
        return None


def _get_key() -> bytes | None:
    """Cached key accessor. Re-reads settings on first call only."""
    if not hasattr(_get_key, "_cached"):
        _get_key._cached = _load_encryption_key()
    return _get_key._cached


def is_encryption_enabled() -> bool:
    """Return True if a valid encryption key is configured."""
    return _get_key() is not None


def reset_key_cache() -> None:
    """Force re-read of the encryption key (useful for testing)."""
    if hasattr(_get_key, "_cached"):
        del _get_key._cached


# ---------------------------------------------------------------------------
# Low-level encrypt / decrypt
# ---------------------------------------------------------------------------


def _encrypt_value(plaintext: str) -> str:
    """Encrypt a string value. Returns the enc:v1:... token."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _get_key()
    if key is None:
        raise RuntimeError(
            "Cannot encrypt: SECRETS_ENCRYPTION_KEY is not configured. "
            "Set it in .env to enable secrets encryption."
        )

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # ciphertext includes the 16-byte GCM tag appended by the library
    payload = base64.b64encode(nonce + ciphertext).decode("ascii")
    return f"{_ENC_PREFIX}{payload}"


def _decrypt_value(token: str) -> str:
    """Decrypt an enc:v1:... token back to plaintext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not token.startswith(_ENC_PREFIX):
        raise ValueError(f"Not an encrypted token (missing '{_ENC_PREFIX}' prefix)")

    key = _get_key()
    if key is None:
        raise RuntimeError(
            "Cannot decrypt: SECRETS_ENCRYPTION_KEY is not configured. "
            "Set it in .env to enable secrets decryption."
        )

    payload = base64.b64decode(token[len(_ENC_PREFIX):])
    if len(payload) < 12 + 16:
        raise ValueError("Encrypted payload is too short (corrupt data?)")

    nonce = payload[:12]
    ciphertext = payload[12:]

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")


def is_encrypted(value: Any) -> bool:
    """Check whether a value is an encrypted token."""
    return isinstance(value, str) and value.startswith(_ENC_PREFIX)


# ---------------------------------------------------------------------------
# Sensitive fields configuration
# ---------------------------------------------------------------------------


def get_sensitive_fields() -> list[str]:
    """Return the list of metadata keys considered sensitive.

    Configurable via SENSITIVE_METADATA_FIELDS setting (comma-separated).
    Defaults to: headers, body, credentials
    """
    from .config import settings

    raw = (settings.sensitive_metadata_fields or "").strip()
    if raw:
        return [f.strip() for f in raw.split(",") if f.strip()]
    return ["headers", "body", "credentials"]


def get_enforce_https() -> bool:
    """Whether to block saving auth headers against http:// endpoints."""
    from .config import settings

    return settings.enforce_https_endpoints


# ---------------------------------------------------------------------------
# High-level field operations: encrypt / decrypt / redact
# ---------------------------------------------------------------------------


def encrypt_sensitive_fields(metadata: dict) -> dict:
    """Encrypt sensitive fields in a metadata dict before DB storage.

    Granular encryption strategy:
      - dict values (e.g. headers): each VALUE is encrypted individually,
        keys stay in plaintext. This allows partial updates and lets the UI
        show which headers are configured.
      - scalar/list values (e.g. body, credentials): the whole value is
        encrypted as a single blob.

    Fields that are already encrypted are left as-is (idempotent).
    """
    if not is_encryption_enabled():
        logger.warning(
            "Secrets encryption is DISABLED (no SECRETS_ENCRYPTION_KEY). "
            "Sensitive fields will be stored in plaintext."
        )
        return metadata

    sensitive = set(get_sensitive_fields())
    result = dict(metadata)

    for key in sensitive:
        if key not in result or result[key] is None:
            continue
        value = result[key]

        if isinstance(value, dict):
            # Per-key encryption: encrypt each value, keep keys in plaintext
            encrypted_dict = {}
            for k, v in value.items():
                if v is None:
                    encrypted_dict[k] = None
                elif is_encrypted(v):
                    # Already encrypted — pass through
                    encrypted_dict[k] = v
                else:
                    encrypted_dict[k] = _encrypt_value(str(v))
            result[key] = encrypted_dict
        elif is_encrypted(value):
            # Already encrypted scalar — skip
            continue
        else:
            # Scalar or list: encrypt as a single blob
            if isinstance(value, list):
                plaintext = json.dumps(value, separators=(",", ":"))
            else:
                plaintext = str(value)
            result[key] = _encrypt_value(plaintext)

    return result


def decrypt_sensitive_fields(metadata: dict) -> dict:
    """Decrypt sensitive fields from a metadata dict for runtime use.

    Handles both granular (per-key in dicts) and blob encryption.
    Non-encrypted fields pass through unchanged (backward compat).
    """
    if not metadata:
        return metadata

    sensitive = set(get_sensitive_fields())
    result = dict(metadata)

    for key in sensitive:
        if key not in result or result[key] is None:
            continue
        value = result[key]

        if isinstance(value, dict):
            # Per-key decryption
            decrypted_dict = {}
            for k, v in value.items():
                if v is None:
                    decrypted_dict[k] = None
                elif is_encrypted(v):
                    decrypted_dict[k] = _decrypt_value(v)
                else:
                    # Plaintext value (legacy) — pass through
                    decrypted_dict[k] = v
            result[key] = decrypted_dict
        elif is_encrypted(value):
            # Blob decryption
            plaintext = _decrypt_value(value)
            try:
                result[key] = json.loads(plaintext)
            except (json.JSONDecodeError, ValueError):
                result[key] = plaintext
        # else: plaintext scalar — pass through

    return result


def redact_sensitive_fields(metadata: dict) -> dict:
    """Redact sensitive fields for API responses (never expose secrets to frontend).

    Granular redaction:
      - dict values (e.g. headers): keys are preserved, each value is redacted
        to show last 4 chars. This lets the UI display which headers exist.
      - encrypted blob values: shown as a type-appropriate placeholder.
      - plaintext scalars: redacted with last 4 chars visible.

    Returns a new dict safe to serialize to the client.
    """
    if not metadata:
        return metadata

    sensitive = set(get_sensitive_fields())
    result = dict(metadata)

    for key in sensitive:
        if key not in result or result[key] is None:
            continue
        value = result[key]

        if isinstance(value, dict):
            # Per-key redaction: show keys, redact values
            redacted_dict = {}
            for k, v in value.items():
                if v is None:
                    redacted_dict[k] = None
                elif is_encrypted(v):
                    redacted_dict[k] = "••••••••"
                else:
                    redacted_dict[k] = _redact_string(v)
            result[key] = redacted_dict
        elif is_encrypted(value):
            result[key] = _redacted_placeholder(key)
        elif isinstance(value, str):
            result[key] = _redact_string(value)
        else:
            result[key] = "<redacted>"

    return result


def _redacted_placeholder(field_name: str) -> str:
    """Return a placeholder indicating the field is set but redacted."""
    return f"<{field_name}: configured>"


def _redact_string(value: Any) -> str:
    """Redact a string value, showing last 4 chars if long enough."""
    s = str(value)
    if len(s) <= 8:
        return "****"
    return f"****{s[-4:]}"


# ---------------------------------------------------------------------------
# HTTPS enforcement
# ---------------------------------------------------------------------------


def validate_endpoint_security(endpoint: str, metadata: dict) -> None:
    """Raise ValueError if sensitive auth is configured against an http:// endpoint.

    Only enforced when ENFORCE_HTTPS_ENDPOINTS=true (default).
    Skipped for empty endpoints (file-based scanners) and localhost (dev).
    """
    if not get_enforce_https():
        return
    if not endpoint:
        return

    # Allow localhost / 127.0.0.1 for local dev
    lower = endpoint.lower()
    if lower.startswith("https://"):
        return
    if any(
        lower.startswith(prefix)
        for prefix in ("http://localhost", "http://127.0.0.1", "http://[::1]")
    ):
        return

    # Check if any sensitive field is present and non-empty
    sensitive = set(get_sensitive_fields())
    for key in sensitive:
        value = metadata.get(key)
        if value:
            raise ValueError(
                f"Refusing to save scanner with sensitive field '{key}' against a non-HTTPS "
                f"endpoint ({endpoint}). Use HTTPS or set ENFORCE_HTTPS_ENDPOINTS=false to "
                f"override (not recommended for production)."
            )
