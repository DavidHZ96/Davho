from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _existing_values(env_path: Path) -> tuple[str, dict[str, str]]:
    if not env_path.is_file():
        return "", {}

    contents = env_path.read_text(encoding="utf-8")
    values: dict[str, str] = {}
    for line in contents.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        values[name.strip()] = value.strip().strip("\"'")
    return contents, values


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    env_path = project_root / ".env.local"
    contents, existing = _existing_values(env_path)
    additions: list[tuple[str, str]] = []

    if not existing.get("ED25519_PRIVATE_KEY"):
        private_key = Ed25519PrivateKey.generate()
        raw_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        additions.append(
            ("ED25519_PRIVATE_KEY", base64.b64encode(raw_private_key).decode("ascii"))
        )

    if not existing.get("ADMIN_API_TOKEN"):
        additions.append(("ADMIN_API_TOKEN", secrets.token_urlsafe(48)))

    if not existing.get("SIGNING_KEY_ID"):
        additions.append(("SIGNING_KEY_ID", "licensing-ed25519-1"))

    if not additions:
        print("Required local licensing values already exist; no values were changed.")
        return

    env_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = "" if not contents or contents.endswith(("\n", "\r")) else "\n"
    with env_path.open("a", encoding="utf-8", newline="\n") as env_file:
        env_file.write(prefix)
        for name, value in additions:
            env_file.write(f"{name}={value}\n")

    if os.name != "nt":
        env_path.chmod(0o600)

    print("Added missing values to the ignored project-root .env.local file.")
    print("Existing values were preserved; secret values were not printed.")


if __name__ == "__main__":
    main()
