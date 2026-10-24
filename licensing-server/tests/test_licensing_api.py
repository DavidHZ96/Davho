from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ADMIN_TOKEN = "test-admin-token-0123456789-abcdefghijklmnopqrstuvwxyz"


@pytest.fixture
def api(tmp_path):
    signing_key = Ed25519PrivateKey.generate()
    raw_key = signing_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    encoded_key = base64.b64encode(raw_key).decode("ascii")
    database_path = (tmp_path / "licenses.sqlite").as_posix()
    app = create_app(
        Settings(
            app_env="test",
            database_url=f"sqlite:///{database_path}",
            admin_api_token=ADMIN_TOKEN,
            ed25519_private_key=encoded_key,
            signing_key_id="test-key-1",
        )
    )
    client = TestClient(app)
    yield client
    client.close()
    app.state.engine.dispose()


def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def create_pending_license(api: TestClient, license_type: str = "lifetime") -> dict:
    response = api.post(
        "/api/v1/admin/licenses",
        headers=admin_headers(),
        json={"customer_name": "Example Shop", "license_type": license_type},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_health_endpoint_is_preserved(api: TestClient) -> None:
    response = api.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_admin_routes_require_authentication(api: TestClient) -> None:
    response = api.post(
        "/api/v1/admin/licenses",
        json={"customer_name": "Example Shop", "license_type": "lifetime"},
    )
    assert response.status_code == 401


def test_invalid_activation_code_is_rejected_without_echoing_it(api: TestClient) -> None:
    code = "SM-" + "A" * 32
    response = api.post(
        "/api/v1/licenses/activate",
        json={"activation_code": code, "device_id": "computer-device-001"},
    )
    assert response.status_code == 401
    assert code not in response.text


def test_activation_returns_a_verifiable_signed_license(api: TestClient) -> None:
    issued = create_pending_license(api)
    activation = api.post(
        "/api/v1/licenses/activate",
        json={
            "activation_code": issued["activation_code"],
            "device_id": "computer-device-001",
        },
    )
    assert activation.status_code == 200, activation.text
    signed = activation.json()["license"]

    public_key_response = api.get("/api/v1/public-key")
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(public_key_response.json()["public_key"])
    )
    payload_bytes = json.dumps(
        signed["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    encoded_signature = signed["signature"]
    signature = base64.urlsafe_b64decode(
        encoded_signature + "=" * (-len(encoded_signature) % 4)
    )
    public_key.verify(signature, payload_bytes)
    assert signed["payload"]["device_id"] == "computer-device-001"
    assert signed["payload"]["license_type"] == "lifetime"
    assert activation.json()["activation_status"] == "active"


def test_reactivation_on_same_device_is_idempotent(api: TestClient) -> None:
    issued = create_pending_license(api)
    body = {
        "activation_code": issued["activation_code"],
        "device_id": "computer-device-001",
    }
    first = api.post("/api/v1/licenses/activate", json=body)
    assert first.status_code == 200
    before = api.get(
        f"/api/v1/admin/licenses/{issued['license']['license_id']}",
        headers=admin_headers(),
    ).json()["activated_at"]

    second = api.post("/api/v1/licenses/activate", json=body)
    assert second.status_code == 200
    after = api.get(
        f"/api/v1/admin/licenses/{issued['license']['license_id']}",
        headers=admin_headers(),
    ).json()["activated_at"]
    assert before == after


def test_a_license_cannot_be_activated_on_a_second_device(api: TestClient) -> None:
    issued = create_pending_license(api)
    first = api.post(
        "/api/v1/licenses/activate",
        json={"activation_code": issued["activation_code"], "device_id": "computer-device-001"},
    )
    assert first.status_code == 200

    second = api.post(
        "/api/v1/licenses/activate",
        json={"activation_code": issued["activation_code"], "device_id": "computer-device-002"},
    )
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "device_mismatch"

    status = api.post(
        "/api/v1/licenses/status",
        json={
            "license_id": issued["license"]["license_id"],
            "device_id": "computer-device-001",
        },
    )
    assert status.status_code == 200
    assert status.json()["is_active"] is True


def test_annual_license_expires_365_days_after_activation(api: TestClient) -> None:
    issued = create_pending_license(api, "annual")
    response = api.post(
        "/api/v1/licenses/activate",
        json={
            "activation_code": issued["activation_code"],
            "device_id": "computer-device-001",
        },
    )
    assert response.status_code == 200
    expiration = datetime.fromisoformat(
        response.json()["license"]["payload"]["expires_at"].replace("Z", "+00:00")
    )
    now = datetime.now(timezone.utc)
    assert 364 <= (expiration - now).days <= 365


def test_activation_endpoint_is_rate_limited(api: TestClient) -> None:
    body = {"activation_code": "SM-" + "B" * 32, "device_id": "computer-device-001"}
    statuses = [api.post("/api/v1/licenses/activate", json=body).status_code for _ in range(11)]
    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429
