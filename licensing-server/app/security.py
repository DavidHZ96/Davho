from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import Settings, decode_private_key
from app.models import License

_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso_utc(value: datetime | None) -> str | None:
    normalized = as_utc(value)
    return normalized.isoformat().replace("+00:00", "Z") if normalized else None


def generate_activation_code() -> str:
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(32))
    groups = "-".join(raw[index : index + 4] for index in range(0, len(raw), 4))
    return f"SM-{groups}"


def activation_code_hash(code: str) -> str:
    normalized = "".join(character for character in code if character.isalnum()).upper()
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def load_signing_key(settings: Settings) -> Ed25519PrivateKey:
    if settings.ed25519_private_key:
        return Ed25519PrivateKey.from_private_bytes(
            decode_private_key(settings.ed25519_private_key)
        )
    if settings.app_env == "production":
        raise RuntimeError("ED25519_PRIVATE_KEY is required in production")
    # Development-only key: never persists between process starts.
    return Ed25519PrivateKey.generate()


def public_key_base64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign_license(
    license_record: License, key: Ed25519PrivateKey, key_id: str, issued_at: datetime | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "license_id": license_record.license_id,
        "customer_name": license_record.customer_name,
        "device_id": license_record.registered_device_id,
        "license_type": license_record.license_type,
        "issued_at": iso_utc(issued_at or utc_now()),
        "expires_at": iso_utc(license_record.expires_at),
        "key_id": key_id,
        "version": 1,
    }
    signature = key.sign(canonical_json(payload))
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return {"payload": payload, "signature": encoded_signature}
