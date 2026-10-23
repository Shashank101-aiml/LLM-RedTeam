"""
Integration tests for Evaluation Runs API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.db.session import init_db
from app.main import app
from app.services.run_service import RunService

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


@pytest.mark.asyncio
async def test_create_and_fetch_run_lifecycle():
    # 1. Create Run
    payload = {
        "target_name": "Deterministic Mock Target (Secure)",
        "dataset_version": "v1.0.0",
        "notes": "Integration test run",
    }
    response = client.post("/api/v1/runs", json=payload)
    assert response.status_code == 201
    run_data = response.json()
    run_id = run_data["id"]
    assert run_data["status"] in ["pending", "running"]
    assert run_data["total_tests"] >= 15

    # 2. Retrieve completed Run (TestClient completes background tasks automatically)
    get_resp = client.get(f"/api/v1/runs/{run_id}")
    assert get_resp.status_code == 200
    completed_run = get_resp.json()
    assert completed_run["status"] == "passed"
    assert completed_run["completed_tests"] == completed_run["total_tests"]
    assert completed_run["findings_count"] == 0

    # 4. Fetch metrics
    metrics_resp = client.get(f"/api/v1/runs/{run_id}/metrics")
    assert metrics_resp.status_code == 200
    metrics = metrics_resp.json()
    assert metrics["attack_success_rate"] == 0.0
    assert metrics["security_pass_rate"] == 1.0

    # 5. Fetch findings (should be empty for secure run)
    findings_resp = client.get(f"/api/v1/runs/{run_id}/findings")
    assert findings_resp.status_code == 200
    assert len(findings_resp.json()) == 0

    # 6. List runs
    list_resp = client.get("/api/v1/runs?limit=10")
    assert list_resp.status_code == 200
    runs_list = list_resp.json()
    assert any(r["id"] == run_id for r in runs_list)
