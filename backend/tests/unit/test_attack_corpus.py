"""
Integration and regression test suite for the complete attack corpus.

Verifies:
- All 6 attack categories and benign controls are loaded and validated.
- Vulnerable MockTarget correctly fails security tests (ASR = 1.0).
- Secure MockTarget defends all attacks (ASR = 0.0, STPR = 1.0, FPR = 0.0).
- Distinguishes secure defense from known vulnerabilities.
"""

import pytest
from app.adapters.mock_adapter import MockTargetAdapter
from app.evaluation.context import ExecutionContext
from app.evaluation.corpus import corpus_registry
from app.evaluation.evaluator import OutcomeEvaluator
from app.metrics.calculator import MetricsCalculator
from app.schemas.enums import AttackCategory


def test_corpus_loading():
    all_cases = corpus_registry.get_all()
    assert len(all_cases) >= 15

    categories = {tc.category for tc in all_cases}
    assert AttackCategory.DIRECT_PROMPT_INJECTION in categories
    assert AttackCategory.INDIRECT_PROMPT_INJECTION in categories
    assert AttackCategory.JAILBREAK in categories
    assert AttackCategory.SYSTEM_PROMPT_LEAKAGE in categories
    assert AttackCategory.UNAUTHORIZED_TOOL_INVOCATION in categories
    assert AttackCategory.TENANT_ISOLATION in categories
    assert AttackCategory.BENIGN_CONTROL in categories

    suites = corpus_registry.get_available_suites()
    assert len(suites) >= 3


@pytest.mark.asyncio
async def test_full_corpus_against_vulnerable_target():
    """
    Vulnerable target fixture must be detected by the evaluator.
    Expects: ASR = 1.0, 0 benign false positives.
    """
    all_cases = corpus_registry.get_all()
    adapter = MockTargetAdapter(mode="vulnerable")
    evaluator = OutcomeEvaluator()

    executions = []
    findings = []

    for tc in all_cases:
        context = ExecutionContext(test_case=tc, correlation_id=f"corr-{tc.test_id}")
        response = await adapter.execute(context)
        exec_res, finding = evaluator.evaluate(tc, response)
        executions.append(exec_res)
        if finding:
            findings.append(finding)

    snapshot = MetricsCalculator.calculate(all_cases, executions)

    # 14 Adversarial attacks, 5 Benign controls
    assert snapshot.total_tests == len(all_cases)
    assert snapshot.attack_attempts == 14
    assert snapshot.benign_controls == 5

    # In vulnerable mode, all 14 attacks succeed
    assert snapshot.attack_success_rate == 1.0
    assert snapshot.security_pass_rate == 0.0
    assert len(findings) == 14

    # Benign requests are NOT overblocked
    assert snapshot.false_positive_rate == 0.0
    assert snapshot.benign_acceptance_rate == 1.0


@pytest.mark.asyncio
async def test_full_corpus_against_secure_target():
    """
    Secure target fixture must defend against all attacks while permitting benign requests.
    Expects: ASR = 0.0, STPR = 1.0, FPR = 0.0, 0 findings.
    """
    all_cases = corpus_registry.get_all()
    adapter = MockTargetAdapter(mode="secure")
    evaluator = OutcomeEvaluator()

    executions = []
    findings = []

    for tc in all_cases:
        context = ExecutionContext(test_case=tc, correlation_id=f"corr-{tc.test_id}")
        response = await adapter.execute(context)
        exec_res, finding = evaluator.evaluate(tc, response)
        executions.append(exec_res)
        if finding:
            findings.append(finding)

    snapshot = MetricsCalculator.calculate(all_cases, executions)

    # In secure mode, 0 attacks succeed, 100% security tests pass
    assert snapshot.attack_success_rate == 0.0
    assert snapshot.security_pass_rate == 1.0
    assert len(findings) == 0

    # All 14 attack tests passed defensively
    assert snapshot.true_positives == 14
    assert snapshot.false_negatives == 0

    # All 5 benign controls allowed
    assert snapshot.true_negatives == 5
    assert snapshot.false_positives == 0
    assert snapshot.false_positive_rate == 0.0
    assert snapshot.benign_acceptance_rate == 1.0
