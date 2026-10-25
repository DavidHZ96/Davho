from __future__ import annotations

import base64
import hashlib
import re
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.config import Settings
from app.main import create_app
from app.models import License
from app.passwords import hash_dashboard_password
from app.security import activation_code_hash

ADMIN_TOKEN = secrets.token_urlsafe(48)
DASHBOARD_PASSWORD = secrets.token_urlsafe(32)
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
CODE_RE = re.compile(r'<code id="activation-code">(SM-(?:[A-HJ-NP-Z2-9]{4}-){7}[A-HJ-NP-Z2-9]{4})</code>')


@pytest.fixture
def dashboard(tmp_path):
    signing_key = Ed25519PrivateKey.generate()
    raw_key = signing_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    app = create_app(
        Settings(
            app_env="test",
            database_url=f"sqlite:///{(tmp_path / 'dashboard.sqlite').as_posix()}",
            admin_api_token=ADMIN_TOKEN,
            ed25519_private_key=base64.b64encode(raw_key).decode("ascii"),
            signing_key_id="dashboard-test-key",
            dashboard_password_hash=hash_dashboard_password(DASHBOARD_PASSWORD),
        )
    )
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    yield client
    client.close()
    app.state.engine.dispose()


def csrf_from(page) -> str:
    match = CSRF_RE.search(page.text)
    assert match is not None
    return match.group(1)


def login(client: TestClient, password: str = DASHBOARD_PASSWORD):
    page = client.get("/admin")
    response = client.post(
        "/admin/login",
        data={"csrf_token": csrf_from(page), "dashboard_password": password},
    )
    return page, response


def create_from_dashboard(client: TestClient, customer_name: str, license_type: str = "lifetime") -> str:
    page = client.get("/admin")
    response = client.post(
        "/admin/licenses",
        data={
            "csrf_token": csrf_from(page),
            "customer_name": customer_name,
            "license_type": license_type,
        },
    )
    assert response.status_code == 303
    assert "SM-" not in response.headers["location"]
    result_page = client.get("/admin")
    match = CODE_RE.search(result_page.text)
    assert match is not None
    assert 'data-copy="activation-code"' in result_page.text
    return match.group(1)


def license_count(client: TestClient) -> int:
    with client.app.state.session_factory() as db:
        return int(db.scalar(select(func.count()).select_from(License)) or 0)


def test_login_uses_separate_dashboard_password_and_secure_server_side_cookie(dashboard: TestClient) -> None:
    page, response = login(dashboard)

    assert page.status_code == 200
    assert '<html lang="fa" dir="rtl">' in page.text
    assert 'name="dashboard_password" type="password"' in page.text
    assert ADMIN_TOKEN not in page.text
    assert DASHBOARD_PASSWORD not in page.text
    assert response.status_code == 303
    set_cookies = " ".join(response.headers.get_list("set-cookie")).lower()
    assert "nikado_admin_session=" in set_cookies
    assert "httponly" in set_cookies
    assert "secure" in set_cookies
    assert "samesite=strict" in set_cookies
    assert ADMIN_TOKEN not in set_cookies
    assert DASHBOARD_PASSWORD not in set_cookies

    authenticated_page = dashboard.get("/admin")
    assert "مدیریت مجوزهای نیکادو یار" in authenticated_page.text
    assert "یک رایانه" in authenticated_page.text
    assert "activation_code_hash" not in authenticated_page.text
    assert "ED25519_PRIVATE_KEY" not in authenticated_page.text


def test_production_cookies_are_secure_even_if_request_scheme_is_http(tmp_path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    raw_key = signing_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    app = create_app(
        Settings(
            app_env="production",
            database_url="postgresql+psycopg://test:test@localhost/licensing",
            admin_api_token=ADMIN_TOKEN,
            ed25519_private_key=base64.b64encode(raw_key).decode("ascii"),
            signing_key_id="dashboard-test-key",
            dashboard_password_hash=hash_dashboard_password(DASHBOARD_PASSWORD),
        )
    )
    client = TestClient(app, base_url="http://testserver", follow_redirects=False)
    try:
        response = client.get("/admin")
        cookies = " ".join(response.headers.get_list("set-cookie")).lower()
        assert response.status_code == 200
        assert "nikado_admin_login=" in cookies
        assert "httponly" in cookies
        assert "secure" in cookies
        assert "samesite=strict" in cookies
    finally:
        client.close()
        app.state.engine.dispose()


def test_bad_login_is_generic_and_login_is_rate_limited(dashboard: TestClient) -> None:
    page, response = login(dashboard, password="incorrect-dashboard-password")
    assert page.status_code == 200
    assert response.status_code == 401
    assert "ورود ناموفق بود" in response.text
    assert "incorrect-dashboard-password" not in response.text

    for _ in range(4):
        page = dashboard.get("/admin")
        response = dashboard.post(
            "/admin/login",
            data={"csrf_token": csrf_from(page), "dashboard_password": "incorrect-dashboard-password"},
        )
        assert response.status_code == 401

    page = dashboard.get("/admin")
    limited = dashboard.post(
        "/admin/login",
        data={"csrf_token": csrf_from(page), "dashboard_password": "incorrect-dashboard-password"},
    )
    assert limited.status_code == 429


def test_api_admin_token_does_not_log_in_to_dashboard_and_dashboard_password_is_not_api_token(
    dashboard: TestClient,
) -> None:
    page = dashboard.get("/admin")
    api_token_result = dashboard.post(
        "/admin/login",
        data={"csrf_token": csrf_from(page), "dashboard_password": ADMIN_TOKEN},
    )
    assert api_token_result.status_code == 401

    api_result = dashboard.post(
        "/api/v1/admin/licenses",
        headers={"Authorization": f"Bearer {DASHBOARD_PASSWORD}"},
        json={"customer_name": "Wrong Credential", "license_type": "lifetime"},
    )
    assert api_result.status_code == 401
    assert license_count(dashboard) == 0


def test_unauthorized_users_cannot_create_or_list_customer_licenses(dashboard: TestClient) -> None:
    page = dashboard.get("/admin")
    assert 'name="dashboard_password"' in page.text
    assert "Sensitive Shop" not in page.text
    response = dashboard.post(
        "/admin/licenses",
        data={"customer_name": "Sensitive Shop", "license_type": "lifetime"},
    )
    assert response.status_code == 303
    assert license_count(dashboard) == 0


def test_dashboard_creates_license_and_displays_activation_code_once(dashboard: TestClient) -> None:
    _, login_response = login(dashboard)
    assert login_response.status_code == 303
    code = create_from_dashboard(dashboard, "Mehr Shop", "annual")

    shown_page = dashboard.get("/admin")
    assert code not in shown_page.text
    with dashboard.app.state.session_factory() as db:
        record = db.scalar(select(License).where(License.customer_name == "Mehr Shop"))
        assert record is not None
        assert record.license_type == "annual"
        assert record.activation_status == "pending"
        assert record.registered_device_id is None
        assert activation_code_hash(code) == record.activation_code_hash
        assert code != record.activation_code_hash


def test_dashboard_lists_and_filters_licenses(dashboard: TestClient) -> None:
    _, login_response = login(dashboard)
    assert login_response.status_code == 303
    create_from_dashboard(dashboard, "Alpha Boutique", "annual")
    create_from_dashboard(dashboard, "Beta Market", "lifetime")

    filtered = dashboard.get("/admin?q=Alpha%20Boutique&status=pending&type=annual")
    assert filtered.status_code == 200
    assert "Alpha Boutique" in filtered.text
    assert "Beta Market" not in filtered.text
    assert "شناسه مجوز" in filtered.text
    assert "ثبت نشده" in filtered.text


def test_dashboard_revokes_license_after_csrf_protected_confirmation_form(dashboard: TestClient) -> None:
    _, login_response = login(dashboard)
    assert login_response.status_code == 303
    create_from_dashboard(dashboard, "Revoke Shop")
    with dashboard.app.state.session_factory() as db:
        record = db.scalar(select(License).where(License.customer_name == "Revoke Shop"))
        assert record is not None
        license_id = record.license_id

    page = dashboard.get("/admin")
    assert "data-confirm=" in page.text
    response = dashboard.post(
        f"/admin/licenses/{license_id}/revoke",
        data={"csrf_token": csrf_from(page)},
    )
    assert response.status_code == 303
    with dashboard.app.state.session_factory() as db:
        record = db.get(License, license_id)
        assert record is not None
        assert record.activation_status == "revoked"
        assert record.revoked_at is not None
    assert "لغوشده" in dashboard.get("/admin").text


def test_dashboard_rejects_missing_csrf_token_and_expires_sessions(dashboard: TestClient) -> None:
    _, login_response = login(dashboard)
    assert login_response.status_code == 303
    page = dashboard.get("/admin")
    denied = dashboard.post(
        "/admin/licenses",
        data={"customer_name": "No CSRF Shop", "license_type": "lifetime", "csrf_token": "wrong"},
    )
    assert denied.status_code == 403
    assert license_count(dashboard) == 0

    cookie_value = dashboard.cookies.get("nikado_admin_session")
    assert cookie_value
    session_key = hashlib.sha256(cookie_value.encode("utf-8")).hexdigest()
    dashboard.app.state.dashboard_sessions[session_key].expires_at = 0
    expired_page = dashboard.get("/admin")
    assert 'name="dashboard_password"' in expired_page.text
    assert "ساخت مجوز مشتری" not in expired_page.text


def test_process_restart_invalidates_old_dashboard_sessions(dashboard: TestClient) -> None:
    _, response = login(dashboard)
    assert response.status_code == 303
    old_session_id = dashboard.cookies.get("nikado_admin_session")
    assert old_session_id

    restarted_app = create_app(dashboard.app.state.settings)
    restarted_client = TestClient(restarted_app, base_url="https://testserver")
    restarted_client.cookies.set("nikado_admin_session", old_session_id)
    try:
        page = restarted_client.get("/admin")
        assert page.status_code == 200
        assert 'name="dashboard_password"' in page.text
    finally:
        restarted_client.close()
        restarted_app.state.engine.dispose()


