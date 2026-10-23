"""
Integration tests for API Key authentication and Safe Mode target enforcement.
"""

from fastapi.testclient import TestClient
from app.core.config import settings
from app.db.session import init_db
from app.main import app

client = TestClient(app)


def test_safe_mode_blocks_external_url_creation():
    init_db()
    # When target_name looks like an external URL and safe mode is enabled
    payload = {
        "target_name": "https://malicious-external-target.com/api/v1",
        "notes": "Safe mode violation attempt",
    }
    response = client.post("/api/v1/runs", json=payload)
    assert response.status_code == 403
    assert "Safe Mode Violation" in response.json()["detail"]


def test_api_key_authentication_enforcement(monkeypatch):
    init_db()
    # Configure API key in settings
    monkeypatch.setattr(settings, "SENTINEL_API_KEY", "secret-sentinel-test-key-999")

    # 1. Request without key -> 401 Unauthorized
    resp_unauth = client.get("/api/v1/runs")
    assert resp_unauth.status_code == 401

    # 2. Request with invalid key -> 401 Unauthorized
    resp_bad = client.get("/api/v1/runs", headers={"X-Sentinel-API-Key": "wrong-key"})
    assert resp_bad.status_code == 401

    # 3. Request with valid key in header -> 200 OK
    resp_ok = client.get("/api/v1/runs", headers={"X-Sentinel-API-Key": "secret-sentinel-test-key-999"})
    assert resp_ok.status_code == 200

    # 4. Request with valid Bearer token -> 200 OK
    resp_bearer = client.get("/api/v1/runs", headers={"Authorization": "Bearer secret-sentinel-test-key-999"})
    assert resp_bearer.status_code == 200
