"""
Integration tests for Promptfoo API endpoints, database persistence,
report generation (JSON/CSV), and vulnerable vs. secure comparison.
"""

import json
from fastapi.testclient import TestClient

from app.db.session import SessionLocal, init_db
from app.main import app
from app.services.comparison_service import ComparisonService
from app.services.export_service import ExportService


def test_promptfoo_api_endpoints_and_comparison():
    """
    Tests:
    - GET /api/v1/evaluations/promptfoo/status
    - POST /api/v1/evaluations/promptfoo/run (vulnerable and secure targets)
    - GET /api/v1/evaluations/promptfoo/runs
    - GET /api/v1/evaluations/promptfoo/runs/{run_id}
    - ComparisonService regression diff between vulnerable and secure Promptfoo runs
    - ExportService sanitized JSON and CSV generation
    """
    init_db()
    client = TestClient(app)

    # 1. Status endpoint
    status_resp = client.get("/api/v1/evaluations/promptfoo/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["available"] is True

    # 2. Trigger Vulnerable Run (using system_prompt_leakage + benign_control for fast deterministic test)
    vuln_resp = client.post(
        "/api/v1/evaluations/promptfoo/run",
        json={
            "target": "mock-vulnerable",
            "selected_categories": ["system_prompt_leakage", "benign_control"],
            "async_execution": False,
            "notes": "Vulnerable baseline Promptfoo test",
        },
    )
    assert vuln_resp.status_code == 201
    vuln_run = vuln_resp.json()
    vuln_run_id = vuln_run["id"]
    assert vuln_run["status"] == "failed"
    assert vuln_run["total_tests"] == 7  # 2 system_prompt_leakage + 5 benign_control
    assert vuln_run["failed_tests"] == 2
    assert vuln_run["passed_tests"] == 5
    assert vuln_run["metrics"]["attack_success_rate"] == 1.0
    assert vuln_run["metrics"]["security_pass_rate"] == 0.0
    assert vuln_run["metrics"]["false_positive_rate"] == 0.0
    assert vuln_run["metrics"]["benign_acceptance_rate"] == 1.0

    # Verify synthetic canary is sanitized in detailed_results
    serialized_str = json.dumps(vuln_run)
    assert "LLM_REDTEAM_SECRET_7F92A1" not in serialized_str
    assert "CANARY_SEC_SENTINEL_ALPHA99" not in serialized_str

    # 3. Trigger Secure Run on the same categories
    sec_resp = client.post(
        "/api/v1/evaluations/promptfoo/run",
        json={
            "target": "mock-secure",
            "selected_categories": ["system_prompt_leakage", "benign_control"],
            "async_execution": False,
            "notes": "Secure candidate Promptfoo test",
        },
    )
    assert sec_resp.status_code == 201
    sec_run = sec_resp.json()
    sec_run_id = sec_run["id"]
    assert sec_run["status"] == "passed"
    assert sec_run["total_tests"] == 7
    assert sec_run["passed_tests"] == 7
    assert sec_run["failed_tests"] == 0
    assert sec_run["metrics"]["attack_success_rate"] == 0.0
    assert sec_run["metrics"]["security_pass_rate"] == 1.0

    # 4. List Promptfoo runs & Get specific run
    list_resp = client.get("/api/v1/evaluations/promptfoo/runs")
    assert list_resp.status_code == 200
    runs_list = list_resp.json()
    run_ids = [r["id"] for r in runs_list]
    assert vuln_run_id in run_ids
    assert sec_run_id in run_ids

    detail_resp = client.get(f"/api/v1/evaluations/promptfoo/runs/{vuln_run_id}")
    assert detail_resp.status_code == 200
    assert len(detail_resp.json()["detailed_results"]) == 7

    # 5. Compare Vulnerable Baseline vs Secure Candidate using ComparisonService
    db = SessionLocal()
    try:
        diff = ComparisonService.compare_runs(db, baseline_run_id=vuln_run_id, candidate_run_id=sec_run_id)
        assert diff.delta_asr == -1.0
        assert diff.delta_security_pass_rate == 1.0
        assert diff.improvements_count == 2
        assert diff.regressions_count == 0

        # 6. Export JSON and CSV and verify secret sanitization
        exported_json = ExportService.export_json(db, vuln_run_id)
        exported_csv = ExportService.export_csv(db, vuln_run_id)
        assert "LLM_REDTEAM_SECRET_7F92A1" not in exported_json
        assert "LLM_REDTEAM_SECRET_7F92A1" not in exported_csv
        assert "PF-LEAK-001" in exported_json
        assert "PF-LEAK-001" in exported_csv
    finally:
        db.close()
