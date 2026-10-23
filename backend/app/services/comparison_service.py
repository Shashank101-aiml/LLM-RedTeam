"""
Run-to-Run Comparison and Regression Detection Service.

Calculates mathematical deltas, highlights newly introduced findings,
and detects regressions (passed -> failed) without fabricating comparisons.
"""

from typing import Dict, List, Set
from sqlalchemy.orm import Session
from app.models.evaluation_run import EvaluationRun
from app.schemas.enums import ExecutionStatus
from app.schemas.evaluation_run import RunComparisonResult


class ComparisonService:
    """Computes reproducible comparisons and regressions between evaluation runs."""

    @staticmethod
    def compare_runs(db: Session, baseline_run_id: str, candidate_run_id: str) -> RunComparisonResult:
        baseline = db.query(EvaluationRun).filter(EvaluationRun.id == baseline_run_id).first()
        candidate = db.query(EvaluationRun).filter(EvaluationRun.id == candidate_run_id).first()

        if not baseline or not candidate:
            raise ValueError("One or both specified runs could not be found.")

        # Executions map: test_case_id -> status
        b_execs: Dict[str, str] = {e.test_case_id: e.status for e in baseline.executions}
        c_execs: Dict[str, str] = {e.test_case_id: e.status for e in candidate.executions}

        b_ids: Set[str] = set(b_execs.keys())
        c_ids: Set[str] = set(c_execs.keys())

        # Suite compatibility check: intersection over union
        union_ids = b_ids.union(c_ids)
        intersection_ids = b_ids.intersection(c_ids)
        compatibility_ratio = len(intersection_ids) / len(union_ids) if union_ids else 1.0
        compatibility_warning = compatibility_ratio < 0.80

        # Regressions and Improvements
        regressions: List[str] = []
        improvements: List[str] = []

        for tc_id in intersection_ids:
            b_status = b_execs[tc_id]
            c_status = c_execs[tc_id]

            if b_status == ExecutionStatus.PASSED.value and c_status == ExecutionStatus.FAILED.value:
                regressions.append(tc_id)
            elif b_status == ExecutionStatus.FAILED.value and c_status == ExecutionStatus.PASSED.value:
                improvements.append(tc_id)

        # Delta metrics
        b_m = baseline.metric_snapshot
        c_m = candidate.metric_snapshot

        delta_asr = None
        delta_stpr = None
        delta_fpr = None

        if b_m and c_m:
            if b_m.attack_success_rate is not None and c_m.attack_success_rate is not None:
                delta_asr = round(c_m.attack_success_rate - b_m.attack_success_rate, 4)
            if b_m.security_pass_rate is not None and c_m.security_pass_rate is not None:
                delta_stpr = round(c_m.security_pass_rate - b_m.security_pass_rate, 4)
            if b_m.false_positive_rate is not None and c_m.false_positive_rate is not None:
                delta_fpr = round(c_m.false_positive_rate - b_m.false_positive_rate, 4)

        new_findings = max(0, candidate.findings_count - baseline.findings_count)

        return RunComparisonResult(
            baseline_run_id=baseline_run_id,
            candidate_run_id=candidate_run_id,
            compatibility_warning=compatibility_warning,
            delta_asr=delta_asr,
            delta_security_pass_rate=delta_stpr,
            delta_fpr=delta_fpr,
            new_findings_count=new_findings,
            regressions_count=len(regressions),
            improvements_count=len(improvements),
            regression_test_ids=regressions,
            improvement_test_ids=improvements,
            category_diffs={},
        )
