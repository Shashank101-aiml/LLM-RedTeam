"""
Evaluation Run Service orchestrating database persistence and background execution.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from app.adapters.mock_adapter import MockTargetAdapter
from app.core.config import settings
from app.db.session import SessionLocal
from app.evaluation.context import ExecutionContext
from app.evaluation.corpus import corpus_registry
from app.evaluation.evaluator import OutcomeEvaluator
from app.metrics.calculator import MetricsCalculator
from app.models.evaluation_run import EvaluationRun
from app.models.finding import Finding
from app.models.metric_snapshot import MetricSnapshot
from app.models.test_case import TestCase
from app.models.test_execution import TestExecution
from app.schemas.enums import ExecutionStatus
from app.schemas.evaluation_run import EvaluationRunCreate


class RunService:
    """Manages creation, execution, and persistence of EvaluationRuns."""

    @staticmethod
    def sync_test_cases_to_db(db: Session) -> None:
        """Ensures all test cases from the corpus exist in the database."""
        corpus_cases = corpus_registry.get_all()
        for tc in corpus_cases:
            existing = db.query(TestCase).filter(TestCase.test_id == tc.test_id).first()
            if not existing:
                db_tc = TestCase(
                    id=str(uuid.uuid4()),
                    test_id=tc.test_id,
                    category=tc.category.value,
                    name=tc.name,
                    description=tc.description,
                    severity=tc.severity.value,
                    is_benign_control=tc.is_benign_control,
                    requires_human_review=tc.requires_human_review,
                    tags=tc.tags,
                    input_prompt=tc.input_prompt,
                    system_prompt=tc.system_prompt,
                    retrieved_context=tc.retrieved_context,
                    mock_tool_output=tc.mock_tool_output,
                    synthetic_canary=tc.synthetic_canary,
                    tenant_id=tc.tenant_id,
                    user_role=tc.user_role,
                    target_tool_name=tc.target_tool_name,
                    expected_outcome=tc.expected_outcome.model_dump(),
                )
                db.add(db_tc)
        db.commit()

    @staticmethod
    def create_run(db: Session, run_in: EvaluationRunCreate) -> EvaluationRun:
        """Creates a pending EvaluationRun record in the database."""
        RunService.sync_test_cases_to_db(db)
        
        all_cases = corpus_registry.get_all()
        if run_in.selected_categories:
            selected_set = set(run_in.selected_categories)
            eligible_cases = [tc for tc in all_cases if tc.category.value in selected_set]
        else:
            eligible_cases = all_cases

        run = EvaluationRun(
            id=str(uuid.uuid4()),
            target_name=run_in.target_name,
            status=ExecutionStatus.PENDING.value,
            dataset_version=run_in.dataset_version,
            random_seed=run_in.random_seed,
            notes=run_in.notes,
            total_tests=len(eligible_cases),
            completed_tests=0,
            passed_tests=0,
            failed_tests=0,
            errors_count=0,
            findings_count=0,
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    async def execute_run_async(run_id: str, mode: str = "secure") -> None:
        """Executes the evaluation run against the target and persists results."""
        db: Session = SessionLocal()
        try:
            run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
            if not run or run.status in [ExecutionStatus.PASSED.value, ExecutionStatus.FAILED.value]:
                return

            run.status = ExecutionStatus.RUNNING.value
            db.commit()

            # Determine mode from target name if specified
            target_mode = "vulnerable" if "vulnerable" in run.target_name.lower() else mode
            adapter = MockTargetAdapter(mode=target_mode, name=run.target_name)
            evaluator = OutcomeEvaluator()

            all_cases = corpus_registry.get_all()
            tc_db_map = {tc.test_id: tc.id for tc in db.query(TestCase).all()}

            executions = []
            executed_pydantic_list = []
            findings = []

            for tc in all_cases:
                context = ExecutionContext(
                    test_case=tc,
                    correlation_id=f"run-{run.id}-{tc.test_id}",
                    timeout_seconds=settings.DEFAULT_TEST_TIMEOUT_SECONDS,
                )

                response = await adapter.execute(context)
                exec_res, finding_res = evaluator.evaluate(tc, response)
                executed_pydantic_list.append(exec_res)

                # Persist TestExecution
                db_exec = TestExecution(
                    id=str(uuid.uuid4()),
                    run_id=run.id,
                    test_case_id=tc_db_map.get(tc.test_id, tc.test_id),
                    status=exec_res.status.value,
                    defense_outcome=exec_res.defense_outcome.value,
                    attack_objective_achieved=exec_res.attack_objective_achieved,
                    duration_ms=exec_res.duration_ms,
                    error_message=exec_res.error_message,
                    target_output_sanitized=exec_res.target_output_sanitized,
                    tool_calls_attempted=exec_res.tool_calls_attempted,
                    canary_detected=exec_res.canary_detected,
                    tenant_boundary_violated=exec_res.tenant_boundary_violated,
                    evaluation_notes=exec_res.evaluation_notes,
                )
                db.add(db_exec)
                executions.append(db_exec)

                if exec_res.status == ExecutionStatus.PASSED:
                    run.passed_tests += 1
                elif exec_res.status == ExecutionStatus.FAILED:
                    run.failed_tests += 1
                elif exec_res.status == ExecutionStatus.ERROR:
                    run.errors_count += 1

                run.completed_tests += 1

                # Persist Finding if security breach detected
                if finding_res:
                    db_finding = Finding(
                        id=str(uuid.uuid4()),
                        run_id=run.id,
                        test_case_id=tc_db_map.get(tc.test_id, tc.test_id),
                        title=finding_res.title,
                        description=finding_res.description,
                        category=finding_res.category.value,
                        severity=finding_res.severity.value,
                        attack_input_redacted=finding_res.attack_input_redacted,
                        target_output_redacted=finding_res.target_output_redacted,
                        tool_violation_observed=finding_res.tool_violation_observed,
                        canary_leaked=finding_res.canary_leaked,
                        tenant_isolation_breached=finding_res.tenant_isolation_breached,
                        remediation_guidance=finding_res.remediation_guidance,
                    )
                    db.add(db_finding)
                    findings.append(db_finding)
                    run.findings_count += 1

                db.commit()

            # Calculate and persist aggregate metrics
            snapshot = MetricsCalculator.calculate(all_cases, executed_pydantic_list)
            existing_snap = db.query(MetricSnapshot).filter(MetricSnapshot.run_id == run.id).first()
            if existing_snap:
                db.delete(existing_snap)
                db.commit()

            db_snapshot = MetricSnapshot(
                id=str(uuid.uuid4()),
                run_id=run.id,
                total_tests=snapshot.total_tests,
                attack_attempts=snapshot.attack_attempts,
                benign_controls=snapshot.benign_controls,
                attack_success_rate=snapshot.attack_success_rate,
                security_pass_rate=snapshot.security_pass_rate,
                detection_precision=snapshot.detection_precision,
                detection_recall=snapshot.detection_recall,
                false_positive_rate=snapshot.false_positive_rate,
                benign_acceptance_rate=snapshot.benign_acceptance_rate,
                unauthorized_tool_execution_rate=snapshot.unauthorized_tool_execution_rate,
                canary_leakage_rate=snapshot.canary_leakage_rate,
                tenant_isolation_breach_rate=snapshot.tenant_isolation_breach_rate,
                true_positives=snapshot.true_positives,
                false_positives=snapshot.false_positives,
                true_negatives=snapshot.true_negatives,
                false_negatives=snapshot.false_negatives,
                errors_count=snapshot.errors_count,
                skipped_count=snapshot.skipped_count,
                median_latency_ms=snapshot.median_latency_ms,
                p95_latency_ms=snapshot.p95_latency_ms,
                small_sample_warning=snapshot.small_sample_warning,
                asr_confidence_interval=snapshot.asr_confidence_interval.model_dump() if snapshot.asr_confidence_interval else None,
                category_breakdown=snapshot.category_breakdown,
            )
            db.add(db_snapshot)

            run.status = ExecutionStatus.PASSED.value if run.findings_count == 0 else ExecutionStatus.FAILED.value
            run.completed_at = datetime.now(timezone.utc)
            db.commit()

        except Exception as e:
            if run:
                run.status = ExecutionStatus.ERROR.value
                run.notes = f"Run execution failed: {str(e)}"
                db.commit()
        finally:
            db.close()
