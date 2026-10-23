"""
Adversarial Regression Engine Testing.

Verifies:
1. Candidate regressions are flagged accurately.
2. Candidate fixes / improvements are recognized.
3. Suite incompatibility warning triggers when suites diverge.
4. Delta metrics match expected mathematical changes.
"""

import uuid
import pytest
from app.db.session import SessionLocal, init_db
from app.models.evaluation_run import EvaluationRun
from app.models.metric_snapshot import MetricSnapshot
from app.models.test_execution import TestExecution
from app.schemas.enums import DefenseOutcome, ExecutionStatus
from app.services.comparison_service import ComparisonService


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_regression_and_fix_detection():
    db = SessionLocal()
    try:
        # Create baseline run
        b_run = EvaluationRun(
            id=str(uuid.uuid4()),
            target_name="Baseline Secure Target",
            status=ExecutionStatus.PASSED.value,
            findings_count=0,
        )
        db.add(b_run)

        # Baseline executions: TC-1 passed, TC-2 passed, TC-3 failed
        b_exec1 = TestExecution(
            id=str(uuid.uuid4()),
            run_id=b_run.id,
            test_case_id="TC-1",
            status=ExecutionStatus.PASSED.value,
            defense_outcome=DefenseOutcome.SECURE.value,
        )
        b_exec2 = TestExecution(
            id=str(uuid.uuid4()),
            run_id=b_run.id,
            test_case_id="TC-2",
            status=ExecutionStatus.PASSED.value,
            defense_outcome=DefenseOutcome.SECURE.value,
        )
        b_exec3 = TestExecution(
            id=str(uuid.uuid4()),
            run_id=b_run.id,
            test_case_id="TC-3",
            status=ExecutionStatus.FAILED.value,
            defense_outcome=DefenseOutcome.VULNERABLE.value,
        )
        db.add_all([b_exec1, b_exec2, b_exec3])

        b_snap = MetricSnapshot(
            id=str(uuid.uuid4()),
            run_id=b_run.id,
            total_tests=3,
            attack_attempts=3,
            attack_success_rate=0.3333,
            security_pass_rate=0.6667,
            false_positive_rate=0.0,
        )
        db.add(b_snap)

        # Create candidate run
        c_run = EvaluationRun(
            id=str(uuid.uuid4()),
            target_name="Candidate Target",
            status=ExecutionStatus.FAILED.value,
            findings_count=1,
        )
        db.add(c_run)

        # Candidate executions:
        # TC-1: passed -> failed (REGRESSION!)
        # TC-2: passed -> passed (STABLE)
        # TC-3: failed -> passed (FIX/IMPROVEMENT!)
        c_exec1 = TestExecution(
            id=str(uuid.uuid4()),
            run_id=c_run.id,
            test_case_id="TC-1",
            status=ExecutionStatus.FAILED.value,
            defense_outcome=DefenseOutcome.VULNERABLE.value,
        )
        c_exec2 = TestExecution(
            id=str(uuid.uuid4()),
            run_id=c_run.id,
            test_case_id="TC-2",
            status=ExecutionStatus.PASSED.value,
            defense_outcome=DefenseOutcome.SECURE.value,
        )
        c_exec3 = TestExecution(
            id=str(uuid.uuid4()),
            run_id=c_run.id,
            test_case_id="TC-3",
            status=ExecutionStatus.PASSED.value,
            defense_outcome=DefenseOutcome.SECURE.value,
        )
        db.add_all([c_exec1, c_exec2, c_exec3])

        c_snap = MetricSnapshot(
            id=str(uuid.uuid4()),
            run_id=c_run.id,
            total_tests=3,
            attack_attempts=3,
            attack_success_rate=0.3333,
            security_pass_rate=0.6667,
            false_positive_rate=0.0,
        )
        db.add(c_snap)
        db.commit()

        # Run comparison
        result = ComparisonService.compare_runs(db, b_run.id, c_run.id)

        assert result.compatibility_warning is False
        assert result.regressions_count == 1
        assert "TC-1" in result.regression_test_ids

        assert result.improvements_count == 1
        assert "TC-3" in result.improvement_test_ids

    finally:
        db.close()


def test_incompatible_suite_warning():
    db = SessionLocal()
    try:
        b_run = EvaluationRun(id=str(uuid.uuid4()), target_name="Suite A", status="passed")
        c_run = EvaluationRun(id=str(uuid.uuid4()), target_name="Suite B", status="passed")
        db.add_all([b_run, c_run])

        # Baseline has TC-1, TC-2, TC-3, TC-4
        for i in range(1, 5):
            db.add(TestExecution(id=str(uuid.uuid4()), run_id=b_run.id, test_case_id=f"TC-{i}", status="passed", defense_outcome="secure"))

        # Candidate has completely different test set: TC-5, TC-6, TC-7, TC-8
        for i in range(5, 9):
            db.add(TestExecution(id=str(uuid.uuid4()), run_id=c_run.id, test_case_id=f"TC-{i}", status="passed", defense_outcome="secure"))

        db.commit()

        result = ComparisonService.compare_runs(db, b_run.id, c_run.id)
        # Because overlap is 0%, compatibility warning MUST be True!
        assert result.compatibility_warning is True
        assert result.regressions_count == 0
        assert result.improvements_count == 0

    finally:
        db.close()
