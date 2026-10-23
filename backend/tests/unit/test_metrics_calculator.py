"""
Unit tests for MetricsCalculator and statistical functions.

Verifies:
- ASR, STPR, Precision, Recall, FPR, BRAR against known confusion matrices.
- Exact zero-denominator handling returning None.
- Wilson score confidence interval computation.
- Small sample warning detection.
"""

from app.metrics.calculator import MetricsCalculator, compute_wilson_interval
from app.schemas.enums import AttackCategory, DefenseOutcome, ExecutionStatus, Severity
from app.schemas.test_case import ExpectedOutcome, TestCaseBase
from app.schemas.test_execution import TestExecutionBase


def make_test_case(test_id: str, is_benign: bool = False, category: AttackCategory = AttackCategory.DIRECT_PROMPT_INJECTION) -> TestCaseBase:
    return TestCaseBase(
        test_id=test_id,
        category=category,
        name=f"Test {test_id}",
        description="Test description",
        severity=Severity.HIGH,
        is_benign_control=is_benign,
        input_prompt="Test input",
        expected_outcome=ExpectedOutcome(must_block_action=True),
    )


def test_zero_denominator_metrics():
    # When no tests are executed, all ratios should return None
    snapshot = MetricsCalculator.calculate([], [])
    assert snapshot.total_tests == 0
    assert snapshot.attack_success_rate is None
    assert snapshot.security_pass_rate is None
    assert snapshot.detection_precision is None
    assert snapshot.detection_recall is None
    assert snapshot.false_positive_rate is None
    assert snapshot.benign_acceptance_rate is None
    assert snapshot.unauthorized_tool_execution_rate is None
    assert snapshot.canary_leakage_rate is None
    assert snapshot.tenant_isolation_breach_rate is None
    assert snapshot.small_sample_warning is True


def test_known_confusion_matrix_metrics():
    # Fixture:
    # 10 Adversarial attacks:
    #   - 8 Defended (TP = 8)
    #   - 2 Succeeded (FN = 2)
    # 5 Benign controls:
    #   - 4 Allowed (TN = 4)
    #   - 1 Erroneously blocked (FP = 1)
    test_cases = []
    executions = []

    # 8 Defended attacks (TP)
    for i in range(1, 9):
        tc_id = f"ADV-{i}"
        test_cases.append(make_test_case(tc_id, is_benign=False))
        executions.append(TestExecutionBase(
            test_case_id=tc_id,
            status=ExecutionStatus.PASSED,
            defense_outcome=DefenseOutcome.SECURE,
            attack_objective_achieved=False,
            duration_ms=10.0,
        ))

    # 2 Successful attacks (FN)
    for i in range(9, 11):
        tc_id = f"ADV-{i}"
        test_cases.append(make_test_case(tc_id, is_benign=False))
        executions.append(TestExecutionBase(
            test_case_id=tc_id,
            status=ExecutionStatus.FAILED,
            defense_outcome=DefenseOutcome.VULNERABLE,
            attack_objective_achieved=True,
            duration_ms=12.0,
        ))

    # 4 Allowed benign controls (TN)
    for i in range(1, 5):
        tc_id = f"BEN-{i}"
        test_cases.append(make_test_case(tc_id, is_benign=True, category=AttackCategory.BENIGN_CONTROL))
        executions.append(TestExecutionBase(
            test_case_id=tc_id,
            status=ExecutionStatus.PASSED,
            defense_outcome=DefenseOutcome.SECURE,
            attack_objective_achieved=False,
            duration_ms=8.0,
        ))

    # 1 Overblocked benign control (FP)
    test_cases.append(make_test_case("BEN-5", is_benign=True, category=AttackCategory.BENIGN_CONTROL))
    executions.append(TestExecutionBase(
        test_case_id="BEN-5",
        status=ExecutionStatus.FAILED,
        defense_outcome=DefenseOutcome.OVERBLOCKING,
        attack_objective_achieved=False,
        duration_ms=9.0,
    ))

    snapshot = MetricsCalculator.calculate(test_cases, executions)

    # Total counts
    assert snapshot.total_tests == 15
    assert snapshot.attack_attempts == 10
    assert snapshot.benign_controls == 5
    assert snapshot.true_positives == 8
    assert snapshot.false_negatives == 2
    assert snapshot.true_negatives == 4
    assert snapshot.false_positives == 1

    # Ratios
    # ASR = 2 / 10 = 0.20
    assert snapshot.attack_success_rate == 0.20
    # STPR = 8 / 10 = 0.80
    assert snapshot.security_pass_rate == 0.80
    # Precision = TP / (TP + FP) = 8 / (8 + 1) = 8/9 = 0.8889
    assert snapshot.detection_precision == 0.8889
    # Recall = TP / (TP + FN) = 8 / (8 + 2) = 0.80
    assert snapshot.detection_recall == 0.80
    # FPR = FP / (FP + TN) = 1 / (1 + 4) = 0.20
    assert snapshot.false_positive_rate == 0.20
    # BRAR = TN / (FP + TN) = 4 / 5 = 0.80
    assert snapshot.benign_acceptance_rate == 0.80

    # Sample warning (N=15 < 30)
    assert snapshot.small_sample_warning is True
    assert snapshot.asr_confidence_interval is not None
    assert 0.0 <= snapshot.asr_confidence_interval.lower <= 0.20
    assert 0.20 <= snapshot.asr_confidence_interval.upper <= 1.0


def test_wilson_interval():
    # 0 successes out of 10
    ci_zero = compute_wilson_interval(0, 10)
    assert ci_zero is not None
    assert ci_zero.lower == 0.0
    assert ci_zero.upper > 0.0

    # Total 0 returns None
    assert compute_wilson_interval(0, 0) is None
