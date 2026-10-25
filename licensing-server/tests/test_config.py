from __future__ import annotations

import base64
import secrets

import pytest

from app.config import Settings, database_url_from_env
from app.passwords import verify_dashboard_password


def test_migrations_prefer_neon_direct_database_url(monkeypatch) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://ep-example-pooler.us-east-2.aws.neon.tech/app",
    )
    monkeypatch.setenv(
        "DATABASE_URL_UNPOOLED",
        "postgresql://ep-example.us-east-2.aws.neon.tech/app",
    )

    assert database_url_from_env() == (
        "postgresql+psycopg://ep-example.us-east-2.aws.neon.tech/app"
    )


def test_application_settings_keep_neon_pooled_database_url(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    for name in ("ADMIN_API_TOKEN", "DASHBOARD_PASSWORD", "ED25519_PRIVATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://ep-example-pooler.us-east-2.aws.neon.tech/app",
    )
    monkeypatch.setenv(
        "DATABASE_URL_UNPOOLED",
        "postgresql://ep-example.us-east-2.aws.neon.tech/app",
    )

    assert Settings.from_env().database_url == (
        "postgresql+psycopg://ep-example-pooler.us-east-2.aws.neon.tech/app"
    )


def test_settings_hash_dashboard_password_and_do_not_retain_plaintext(monkeypatch) -> None:
    password = secrets.token_urlsafe(32)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./ignored-test.sqlite")
    monkeypatch.setenv("DASHBOARD_PASSWORD", password)
    monkeypatch.delenv("ADMIN_API_TOKEN", raising=False)
    monkeypatch.delenv("ED25519_PRIVATE_KEY", raising=False)

    settings = Settings.from_env()

    assert settings.dashboard_password_hash is not None
    assert password not in settings.dashboard_password_hash
    assert verify_dashboard_password(password, settings.dashboard_password_hash)
    assert not verify_dashboard_password("wrong-password", settings.dashboard_password_hash)
    assert not hasattr(settings, "dashboard_password")


def test_production_rejects_missing_or_short_dashboard_password(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://localhost/licensing")
    monkeypatch.setenv("ADMIN_API_TOKEN", secrets.token_urlsafe(48))
    monkeypatch.setenv("ED25519_PRIVATE_KEY", base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)

    with pytest.raises(RuntimeError, match="DASHBOARD_PASSWORD"):
        Settings.from_env()

    monkeypatch.setenv("DASHBOARD_PASSWORD", "too-short")
    with pytest.raises(RuntimeError, match="DASHBOARD_PASSWORD"):
        Settings.from_env()

