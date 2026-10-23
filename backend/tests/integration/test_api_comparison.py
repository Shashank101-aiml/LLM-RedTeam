"""
Integration tests for Run Comparison and Regression Detection API.
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
async def test_compare_runs_detects_regressions():
    # 1. Create and execute baseline run (Secure)
    base_resp = client.post("/api/v1/runs", json={"target_name": "Deterministic Mock Target (Secure)", "notes": "Baseline"})
    base_id = base_resp.json()["id"]

    # 2. Create and execute candidate run (Vulnerable)
    cand_resp = client.post("/api/v1/runs", json={"target_name": "Deterministic Mock Target (Vulnerable)", "notes": "Candidate"})
    cand_id = cand_resp.json()["id"]

    # 3. Call Compare API
    comp_resp = client.post("/api/v1/compare", json={"baseline_run_id": base_id, "candidate_run_id": cand_id})
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()

    assert comp_data["baseline_run_id"] == base_id
    assert comp_data["candidate_run_id"] == cand_id
    assert comp_data["compatibility_warning"] is False
    # In vulnerable candidate, ASR increased from 0.0 to 1.0 (delta = +1.0)
    assert comp_data["delta_asr"] == 1.0
    assert comp_data["delta_security_pass_rate"] == -1.0
    # Regressions detected
    assert comp_data["regressions_count"] >= 10
    assert len(comp_data["regression_test_ids"]) >= 10
    assert comp_data["new_findings_count"] >= 10
