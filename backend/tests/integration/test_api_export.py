"""
Integration tests for JSON and CSV report export endpoints.
"""

import json
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
async def test_export_json_and_csv():
    # Create and execute run (TestClient completes background execution automatically)
    run_resp = client.post("/api/v1/runs", json={"target_name": "Deterministic Mock Target (Vulnerable)"})
    run_id = run_resp.json()["id"]

    # 1. Test JSON Export
    json_resp = client.get(f"/api/v1/runs/{run_id}/export/json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    assert "attachment" in json_resp.headers["content-disposition"]
    data = json.loads(json_resp.text)
    assert "report_metadata" in data
    assert "summary_metrics" in data
    assert "findings" in data
    assert "executions" in data

    # 2. Test CSV Export
    csv_resp = client.get(f"/api/v1/runs/{run_id}/export/csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "attachment" in csv_resp.headers["content-disposition"]
    csv_text = csv_resp.text
    assert "Run_ID" in csv_text
    assert "Test_ID" in csv_text
    assert "Status" in csv_text
    assert "Defense_Outcome" in csv_text
