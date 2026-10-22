"""Security utilities for monitoring source authentication, key management,
and payload sanitization.
"""
import hashlib
import json
import secrets
from typing import Any

from app.auth.security import password_hasher

REDACTED = "[REDACTED]"
MAX_PAYLOAD_BYTES = 65536  # 64 KB limit

SENSITIVE_KEY_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "token",
    "jwt",
    "refresh_token",
    "authorization",
    "cookie",
    "totp",
    "recovery_code",
    "private_key",
    "db_password",
    "api_key",
    "access_token",
    "api_secret",
    "privatekey",
)


def generate_source_key(source_code: str) -> tuple[str, str]:
    """Generate a high-entropy monitoring key and its Argon2id hash.

    Format: mon_{source_code}.{random_token}
    The raw key is returned once to the caller and NEVER stored in plaintext.
    """
    token = secrets.token_urlsafe(32)
    raw_key = f"mon_{source_code}.{token}"
    key_hash = password_hasher.hash(raw_key)
    return raw_key, key_hash


def parse_source_key(key: str, header_source: str | None = None) -> tuple[str | None, str]:
    """Extract source_code and the raw key from authentication input.

    Supports:
    - Standard key: mon_{source_code}.{token} -> returns (source_code, key)
    - Separator format: {source_code}:{token} -> returns (source_code, key)
    - Fallback: header X-Monitoring-Source if provided alongside un-prefixed key
    """
    clean_key = key.strip()
    if clean_key.startswith("mon_") and "." in clean_key:
        prefix, _ = clean_key.split(".", 1)
        source_code = prefix[4:]
        if source_code:
            return source_code, clean_key
    elif ":" in clean_key:
        prefix, _ = clean_key.split(":", 1)
        if prefix:
            return prefix, clean_key

    if header_source and header_source.strip():
        return header_source.strip(), clean_key

    return None, clean_key


def verify_source_key(raw_key: str, key_hash: str) -> bool:
    """Verify raw key against Argon2id hash using constant-time verification."""
    try:
        return password_hasher.verify(raw_key, key_hash)
    except Exception:
        return False


def sanitize_payload(obj: Any) -> Any:
    """Recursively redact sensitive credentials in dictionaries, lists, and primitives."""
    if isinstance(obj, dict):
        sanitized = {}
        for key, value in obj.items():
            key_str = str(key).lower().replace("-", "_").strip()
            if any(pattern in key_str for pattern in SENSITIVE_KEY_PATTERNS):
                sanitized[key] = REDACTED
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    elif isinstance(obj, (list, tuple)):
        return [sanitize_payload(item) for item in obj]
    return obj


def validate_payload_size(payload: dict[str, Any]) -> None:
    """Ensure serialized payload JSON does not exceed safety limits."""
    try:
        serialized = json.dumps(payload)
    except (TypeError, ValueError) as err:
        raise ValueError("Payload must be valid JSON-serializable data.") from err
    if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"Payload size exceeds maximum allowed limit ({MAX_PAYLOAD_BYTES} bytes).")


def compute_event_fingerprint(
    source_id: str,
    event_type: str,
    asset_id: int | None,
    title: str,
    message: str,
) -> str:
    """Derive deterministic SHA-256 fingerprint server-side."""
    norm_title = " ".join(title.lower().split())
    norm_msg = " ".join(message.lower().split())[:500]
    raw = f"{source_id}:{event_type}:{asset_id or 0}:{norm_title}:{norm_msg}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
