from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from app.passwords import hash_dashboard_password


def _load_project_env() -> None:
    """Load the Neon CLI env file for local runs without overriding shell vars."""
    project_root = Path(__file__).resolve().parents[2]
    env_file = project_root / ".env"
    if not env_file.is_file():
        env_file = project_root / ".env.local"
    if env_file.is_file():
        load_dotenv(dotenv_path=env_file, override=False)


_load_project_env()


def normalize_database_url(url: str) -> str:
    """Normalize a PostgreSQL URL (such as Neon's) for psycopg 3 / SQLAlchemy."""
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return url


def decode_private_key(value: str) -> bytes:
    try:
        key = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("ED25519_PRIVATE_KEY must be base64-encoded raw key bytes") from exc
    if len(key) != 32:
        raise ValueError("ED25519_PRIVATE_KEY must decode to exactly 32 bytes")
    return key


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    database_url: str = "sqlite:///./licensing_dev.db"
    admin_api_token: str | None = field(default=None, repr=False)
    ed25519_private_key: str | None = field(default=None, repr=False)
    signing_key_id: str = "dev-ephemeral"
    dashboard_password_hash: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "Settings":
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        dashboard_password = os.getenv("DASHBOARD_PASSWORD") or None
        if app_env == "production" and (
            dashboard_password is None or len(dashboard_password) < 16
        ):
            raise RuntimeError("Production requires DASHBOARD_PASSWORD with at least 16 characters")
        default_database = "" if app_env == "production" else "sqlite:///./licensing_dev.db"
        settings = cls(
            app_env=app_env,
            database_url=normalize_database_url(os.getenv("DATABASE_URL", default_database)),
            admin_api_token=os.getenv("ADMIN_API_TOKEN") or None,
            ed25519_private_key=os.getenv("ED25519_PRIVATE_KEY") or None,
            signing_key_id=os.getenv("SIGNING_KEY_ID", "primary").strip() or "primary",
            dashboard_password_hash=(
                hash_dashboard_password(dashboard_password) if dashboard_password else None
            ),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.app_env != "production":
            return
        if not self.database_url.startswith("postgresql+psycopg://"):
            raise RuntimeError("Production requires DATABASE_URL pointing to PostgreSQL")
        if not self.admin_api_token or len(self.admin_api_token) < 32:
            raise RuntimeError("Production requires an ADMIN_API_TOKEN with at least 32 characters")
        if not self.ed25519_private_key:
            raise RuntimeError("Production requires ED25519_PRIVATE_KEY")
        decode_private_key(self.ed25519_private_key)
        if not self.dashboard_password_hash:
            raise RuntimeError("Production requires DASHBOARD_PASSWORD")


def database_url_from_env() -> str:
    """Prefer Neon's direct URL for Alembic, falling back to app DATABASE_URL."""
    return normalize_database_url(
        os.getenv("DATABASE_URL_UNPOOLED")
        or os.getenv("DATABASE_URL")
        or "sqlite:///./licensing_dev.db"
    )

