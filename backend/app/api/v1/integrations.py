"""
Integrations and External Scanner Report Ingestion API Router.
Supports importing Promptfoo and NVIDIA Garak evaluation reports,
normalizing findings, and persisting them as EvaluationRuns.
"""

from datetime import datetime, timezone
from typing import Any, Dict
import uuid
from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import verify_api_key
from app.db.session import get_db
from app.integrations.garak_normalizer import GarakNormalizer
from app.integrations.promptfoo_normalizer import PromptfooNormalizer
from app.integrations.schemas import NormalizedBenchmarkReport
from app.models.evaluation_run import EvaluationRun
from app.models.finding import Finding
from app.models.metric_snapshot import MetricSnapshot
from app.models.test_case import TestCase
from app.models.test_execution import TestExecution
from app.schemas.enums import DefenseOutcome, ExecutionStatus

router = APIRouter(prefix="/integrations")


def _persist_normalized_report(db: Session, report: NormalizedBenchmarkReport) -> EvaluationRun:
    """Helper to persist a normalized benchmark report into the database."""
    run_id = str(uuid.uuid4())
    run = EvaluationRun(
        id=run_id,
        target_name=f"{report.framework.title()} Import: {report.target_model}",
        status=ExecutionStatus.FAILED.value if report.failed_tests > 0 else ExecutionStatus.PASSED.value,
        dataset_version=f"{report.framework}-v{report.framework_version or 'unknown'}",
        random_seed=42,
        notes=f"Imported from {report.framework} evaluation output.",
        total_tests=report.total_tests,
        completed_tests=report.total_tests,
        passed_tests=report.passed_tests,
        failed_tests=report.failed_tests,
        errors_count=report.errors_count,
        findings_count=report.findings_count,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(run)

    for exec_item in report.executions:
        # Check or create synthetic TestCase record for foreign test
        db_tc = db.query(TestCase).filter(TestCase.test_id == exec_item.test_id).first()
        if not db_tc:
            db_tc = TestCase(
                id=str(uuid.uuid4()),
                test_id=exec_item.test_id,
                category=exec_item.category.value,
                name=f"{report.framework.title()}: {exec_item.test_id}",
                description=f"Imported external probe from {report.framework}",
                severity="high" if exec_item.findings else "informational",
                is_benign_control=False,
                tags=[report.framework, exec_item.category.value],
                input_prompt=exec_item.input_prompt,
                expected_outcome={"must_block_action": True},
            )
            db.add(db_tc)
            db.flush()

        # Persist TestExecution
        db_exec = TestExecution(
            id=str(uuid.uuid4()),
            run_id=run.id,
            test_case_id=db_tc.id,
            status=exec_item.status.value,
            defense_outcome=DefenseOutcome.SECURE.value if exec_item.status == ExecutionStatus.PASSED else DefenseOutcome.VULNERABLE.value,
            attack_objective_achieved=(exec_item.status == ExecutionStatus.FAILED),
            duration_ms=exec_item.duration_ms,
            target_output_sanitized=exec_item.output_text,
            evaluation_notes=f"Source: {report.framework}",
        )
        db.add(db_exec)

        # Persist Findings
        for finding in exec_item.findings:
            db_finding = Finding(
                id=str(uuid.uuid4()),
                run_id=run.id,
                test_case_id=db_tc.id,
                title=finding.title,
                description=finding.description,
                category=finding.category.value,
                severity=finding.severity.value,
                attack_input_redacted=exec_item.input_prompt[:500],
                target_output_redacted=exec_item.output_text[:500],
                tool_violation_observed=(finding.category.value == "unauthorized_tool_invocation"),
                canary_leaked=(finding.category.value == "system_prompt_extraction"),
                remediation_guidance=finding.remediation,
            )
            db.add(db_finding)

    # Persist MetricSnapshot
    metric_snapshot = MetricSnapshot(
        id=str(uuid.uuid4()),
        run_id=run.id,
        attack_success_rate=report.attack_success_rate,
        security_pass_rate=report.security_pass_rate,
        false_positive_rate=0.0,
        benign_acceptance_rate=1.0,
        detection_precision=1.0 if report.failed_tests > 0 else 0.0,
        detection_recall=1.0 if report.failed_tests > 0 else 0.0,
        asr_confidence_interval={"lower": max(0.0, report.attack_success_rate - 0.05), "upper": min(1.0, report.attack_success_rate + 0.05)},
        total_tests=report.total_tests,
        attack_attempts=report.total_tests,
        benign_controls=0,
        true_positives=report.passed_tests,
        true_negatives=0,
        false_positives=0,
        false_negatives=report.failed_tests,
        category_breakdown={},
    )
    db.add(metric_snapshot)
    db.commit()
    db.refresh(run)
    return run


@router.post(
    "/import/promptfoo",
    response_model=Dict[str, Any],
    dependencies=[Depends(verify_api_key)],
)
def import_promptfoo_report(
    payload: Dict[str, Any] = Body(...),
    persist: bool = Query(False, description="Persist the imported report into database as an EvaluationRun"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Imports and normalizes a Promptfoo evaluation JSON report."""
    try:
        report = PromptfooNormalizer.parse(payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    result: Dict[str, Any] = {
        "report": report.model_dump(),
        "persisted": False,
        "run_id": None,
    }

    if persist:
        run = _persist_normalized_report(db, report)
        result["persisted"] = True
        result["run_id"] = run.id

    return result


@router.post(
    "/import/garak",
    response_model=Dict[str, Any],
    dependencies=[Depends(verify_api_key)],
)
def import_garak_report(
    payload: Dict[str, Any] = Body(...),
    persist: bool = Query(False, description="Persist the imported report into database as an EvaluationRun"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Imports and normalizes an NVIDIA Garak evaluation report."""
    try:
        report = GarakNormalizer.parse(payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    result: Dict[str, Any] = {
        "report": report.model_dump(),
        "persisted": False,
        "run_id": None,
    }

    if persist:
        run = _persist_normalized_report(db, report)
        result["persisted"] = True
        result["run_id"] = run.id

    return result
