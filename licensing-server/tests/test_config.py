from __future__ import annotations

from app.config import Settings, database_url_from_env


def test_migrations_prefer_neon_direct_database_url(monkeypatch) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://app_user:secret@ep-example-pooler.us-east-2.aws.neon.tech/app",
    )
    monkeypatch.setenv(
        "DATABASE_URL_UNPOOLED",
        "postgresql://app_user:secret@ep-example.us-east-2.aws.neon.tech/app",
    )

    assert database_url_from_env() == (
        "postgresql+psycopg://app_user:secret@ep-example.us-east-2.aws.neon.tech/app"
    )


def test_application_settings_keep_neon_pooled_database_url(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://app_user:secret@ep-example-pooler.us-east-2.aws.neon.tech/app",
    )
    monkeypatch.setenv(
        "DATABASE_URL_UNPOOLED",
        "postgresql://app_user:secret@ep-example.us-east-2.aws.neon.tech/app",
    )

    assert Settings.from_env().database_url == (
        "postgresql+psycopg://app_user:secret@ep-example-pooler.us-east-2.aws.neon.tech/app"
    )
