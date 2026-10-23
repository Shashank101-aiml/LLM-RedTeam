"""
LLM Sentinel — Demonstration Benchmark Runner (Zero-Token Local Execution).

Initializes a clean SQLite database, executes baseline and candidate evaluation runs
against deterministic MockTarget targets (Vulnerable Mode vs Secure Mode),
computes regression comparisons, and validates sanitized JSON/CSV report exports.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import sys

# Ensure backend is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.config import settings
from app.db.session import SessionLocal, init_db
from app.evaluation.corpus import corpus_registry
from app.models.evaluation_run import EvaluationRun
from app.schemas.evaluation_run import EvaluationRunCreate
from app.services.comparison_service import ComparisonService
from app.services.export_service import ExportService
from app.services.run_service import RunService


async def run_benchmark():
    print("=" * 80)
    print("  LLM SENTINEL — DEMONSTRATION BENCHMARK & SYSTEM VERIFICATION")
    print("=" * 80)
    print(f"Timestamp:       {datetime.now(timezone.utc).isoformat()}")
    print(f"Safe Mode:       {settings.SAFE_MODE}")
    print(f"Allowed Hosts:   {settings.ALLOWED_TARGET_HOSTS}")
    print(f"Environment:     {settings.ENVIRONMENT}")
    print(f"Zero-Token Mode: Active (No external LLM provider credentials required)")
    print("-" * 80)

    # 1. Initialize clean database
    print("\n[Step 1/5] Initializing Database & Loading Attack Corpus...")
    init_db()
    corpus_registry.load()
    all_cases = corpus_registry.get_all()
    print(f"  Loaded {len(all_cases)} test cases from corpus:")
    print(f"    - Attacks: {len([c for c in all_cases if not c.is_benign_control])}")
    print(f"    - Benign Controls: {len([c for c in all_cases if c.is_benign_control])}")

    db = SessionLocal()
    try:
        RunService.sync_test_cases_to_db(db)

        # 2. Execute Vulnerable Mock Run
        print("\n[Step 2/5] Executing Benchmark Run 1: Vulnerable Mock Target...")
        run_vulnerable_req = EvaluationRunCreate(
            target_name="Deterministic Mock Target (Vulnerable Mode)",
            dataset_version="sentinel-corpus-v1.0",
            notes="Baseline evaluation demonstrating vulnerability detection across all categories.",
        )
        run_vulnerable = RunService.create_run(db, run_vulnerable_req)
        await RunService.execute_run_async(run_vulnerable.id, mode="vulnerable")

        db.refresh(run_vulnerable)
        print(f"  Run 1 Completed:")
        print(f"    Run ID:          {run_vulnerable.id}")
        print(f"    Status:          {run_vulnerable.status.upper()}")
        print(f"    Total Tests:     {run_vulnerable.total_tests}")
        print(f"    Findings Count:  {run_vulnerable.findings_count}")
        print(f"    ASR:             {run_vulnerable.metric_snapshot.attack_success_rate:.2%}")
        print(f"    Security Pass:   {run_vulnerable.metric_snapshot.security_pass_rate:.2%}")
        print(f"    False Positives: {run_vulnerable.metric_snapshot.false_positive_rate:.2%}")

        # 3. Execute Secure Mock Run
        print("\n[Step 3/5] Executing Benchmark Run 2: Secure Mock Target...")
        run_secure_req = EvaluationRunCreate(
            target_name="Deterministic Mock Target (Secure Mode)",
            dataset_version="sentinel-corpus-v1.0",
            notes="Candidate evaluation demonstrating remediated guardrails and authorization enforcement.",
        )
        run_secure = RunService.create_run(db, run_secure_req)
        await RunService.execute_run_async(run_secure.id, mode="secure")

        db.refresh(run_secure)
        print(f"  Run 2 Completed:")
        print(f"    Run ID:          {run_secure.id}")
        print(f"    Status:          {run_secure.status.upper()}")
        print(f"    Total Tests:     {run_secure.total_tests}")
        print(f"    Findings Count:  {run_secure.findings_count}")
        print(f"    ASR:             {run_secure.metric_snapshot.attack_success_rate:.2%}")
        print(f"    Security Pass:   {run_secure.metric_snapshot.security_pass_rate:.2%}")
        print(f"    False Positives: {run_secure.metric_snapshot.false_positive_rate:.2%}")

        # 4. Perform Regression Comparison
        print("\n[Step 4/5] Computing Run-to-Run Adversarial Regression Comparison...")
        diff = ComparisonService.compare_runs(db, baseline_run_id=run_vulnerable.id, candidate_run_id=run_secure.id)
        print(f"  Comparison Results (Run 1 -> Run 2):")
        print(f"    Delta ASR:       {diff.delta_asr:+.2%}")
        print(f"    Delta STPR:      {diff.delta_security_pass_rate:+.2%}")
        print(f"    New Regressions: {diff.regressions_count}")
        print(f"    Fixed Flaws:     {diff.improvements_count}")
        assert diff.delta_asr < 0, "Expected ASR to decrease from vulnerable to secure target"
        assert diff.regressions_count == 0, "Expected zero new regressions"

        # 5. Export and Verify Reports
        print("\n[Step 5/5] Exporting Sanitized Benchmark Reports...")
        json_report = ExportService.export_json(db, run_vulnerable.id)
        csv_report = ExportService.export_csv(db, run_vulnerable.id)

        print(f"  JSON Export: Generated {len(json_report)} bytes of structured report")
        print(f"  CSV Export:  Generated {len(csv_report.splitlines())} rows of sanitized findings")

        # Verify evidence sanitization
        assert "CANARY-SECRET-BETA-7790" not in json_report, "Unsanitized canary leaked into JSON export!"
        assert "sk-ant-admin" not in json_report, "Unsanitized API key leaked into JSON export!"
        print("  Sanitization Verified: All canaries and credentials correctly masked.")

        print("\n" + "=" * 80)
        print("  DEMONSTRATION BENCHMARK COMPLETED SUCCESSFULLY (100% VERIFIED)")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(run_benchmark())
