from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    private_key = Ed25519PrivateKey.generate()
    raw_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print("ED25519_PRIVATE_KEY=" + base64.b64encode(raw_private_key).decode("ascii"))
    print("ADMIN_API_TOKEN=" + secrets.token_urlsafe(48))
    print("SIGNING_KEY_ID=licensing-ed25519-1")
    print("Store these values in Render's secret environment variables; do not commit them.")


if __name__ == "__main__":
    main()
