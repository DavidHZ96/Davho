from __future__ import annotations

import hashlib
import hmac
import secrets

_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32


def hash_dashboard_password(password: str) -> str:
    """Return a salted scrypt verifier suitable for in-memory application config."""
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEY_BYTES,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_dashboard_password(password: str | None, verifier: str | None) -> bool:
    """Check a password against a supported scrypt verifier without leaking details."""
    if password is None or verifier is None or len(password) > 512:
        return False
    try:
        algorithm, n_text, r_text, p_text, salt_text, expected_text = verifier.split("$")
        n, r, p = int(n_text), int(r_text), int(p_text)
        salt = bytes.fromhex(salt_text)
        expected = bytes.fromhex(expected_text)
        # Fixed parameters and lengths prevent attacker-controlled scrypt resource use.
        if (
            algorithm != "scrypt"
            or (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
            or len(salt) != _SALT_BYTES
            or len(expected) != _KEY_BYTES
        ):
            return False
        supplied = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_KEY_BYTES,
        )
    except (ValueError, TypeError, UnicodeError):
        return False
    return hmac.compare_digest(supplied, expected)

