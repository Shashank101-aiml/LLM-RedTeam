"""
Unit tests for Health and root endpoints.
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "LLM Sentinel"
    assert data["safe_mode"] is True


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["ok", "degraded"]
    assert data["safe_mode"] is True
    assert "database" in data["components"]
    assert "mock_target" in data["components"]
