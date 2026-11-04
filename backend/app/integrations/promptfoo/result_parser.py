"""
Promptfoo Execution Result Parser and Metrics Integrator.

Parses Promptfoo evaluation JSON outputs, evaluates responses with OutcomeEvaluator
and Promptfoo assertions, sanitizes all evidence, and delegates statistical calculation
to the unified MetricsCalculator engine.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Union

from app.adapters.base import TargetResponse
from app.core.logging_config import redact_sensitive_text
from app.evaluation.evaluator import OutcomeEvaluator
from app.integrations.promptfoo.provider import build_test_case_from_vars
from app.metrics.calculator import MetricsCalculator
from app.schemas.enums import DefenseOutcome, ExecutionStatus
from app.schemas.finding import FindingBase
from app.schemas.metric_snapshot import MetricSnapshotBase
from app.schemas.test_case import TestCaseBase
from app.schemas.test_execution import TestExecutionBase


@dataclass
class PromptfooDetailedItem:
    """Structured per-test result meeting Section 6 requirements."""
    test_case_id: str
    category: str
    is_benign_control: bool
    target_provider: str
    model_identifier: str
    prompt: str
    sanitized_response: str
    assertion_results: List[Dict[str, Any]]
    final_status: str
    defense_outcome: str
    outcome_classification: str
    attack_objective_achieved: bool
    duration_ms: float
    execution_timestamp: str
    failure_reason: Optional[str] = None
    tool_calls_attempted: List[Dict[str, Any]] = field(default_factory=list)
    canary_detected: bool = False
    tenant_boundary_violated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_case_id": self.test_case_id,
            "category": self.category,
            "is_benign_control": self.is_benign_control,
            "target_provider": self.target_provider,
            "model_identifier": self.model_identifier,
            "prompt": self.prompt,
            "sanitized_response": self.sanitized_response,
            "assertion_results": self.assertion_results,
            "final_status": self.final_status,
            "defense_outcome": self.defense_outcome,
            "outcome_classification": self.outcome_classification,
            "attack_objective_achieved": self.attack_objective_achieved,
            "duration_ms": self.duration_ms,
            "execution_timestamp": self.execution_timestamp,
            "failure_reason": self.failure_reason,
            "tool_calls_attempted": self.tool_calls_attempted,
            "canary_detected": self.canary_detected,
            "tenant_boundary_violated": self.tenant_boundary_violated,
        }


@dataclass
class PromptfooEvaluationParsed:
    """Complete parsed Promptfoo evaluation output ready for persistence and reporting."""
    framework_version: str
    target_provider: str
    model_identifier: str
    execution_timestamp: str
    test_cases: List[TestCaseBase]
    executions: List[TestExecutionBase]
    findings: List[FindingBase]
    metrics: MetricSnapshotBase
    detailed_items: List[PromptfooDetailedItem]


class PromptfooResultParser:
    """
    Parses Promptfoo JSON artifacts and bridges outcomes into OutcomeEvaluator
    and MetricsCalculator without duplicating metric math.
    """

    @staticmethod
    def _extract_results_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extracts the list of test result items from Promptfoo JSON output.
        Handles both Promptfoo v0.80+ nested `results.results` and flat `results` array formats.
        """
        raw_results = data.get("results")
        if isinstance(raw_results, dict):
            nested = raw_results.get("results")
            if isinstance(nested, list):
                return nested
        elif isinstance(raw_results, list):
            return raw_results
        raise ValueError("Invalid Promptfoo evaluation output: missing 'results' list.")

    @classmethod
    def parse(
        cls,
        raw_output: Union[str, Dict[str, Any]],
        default_target_provider: str = "Deterministic Mock Target (Secure Mode)",
        default_model_identifier: str = "sentinel-mock-secure-v1",
    ) -> PromptfooEvaluationParsed:
        """
        Parses raw Promptfoo evaluation JSON and computes unified Sentinel metrics.
        """
        if isinstance(raw_output, str):
            try:
                data = json.loads(raw_output)
            except Exception as exc:
                raise ValueError(f"Malformed Promptfoo JSON output: {str(exc)}") from exc
        elif isinstance(raw_output, dict):
            data = raw_output
        else:
            raise ValueError(f"Expected JSON string or dict, got {type(raw_output).__name__}.")

        results_list = cls._extract_results_list(data)
        version = str(data.get("version", data.get("evalId", "promptfoo-cli")))
        timestamp = str(
            data.get("timestamp")
            or (data.get("results", {}).get("timestamp") if isinstance(data.get("results"), dict) else None)
            or datetime.now(timezone.utc).isoformat()
        )

        evaluator = OutcomeEvaluator()
        test_cases: List[TestCaseBase] = []
        executions: List[TestExecutionBase] = []
        findings: List[FindingBase] = []
        detailed_items: List[PromptfooDetailedItem] = []

        for idx, item in enumerate(results_list):
            if not isinstance(item, dict):
                continue

            # Extract vars and test case metadata
            vars_dict = item.get("vars", {}) if isinstance(item.get("vars"), dict) else {}
            test_case_meta = item.get("testCase", {}) if isinstance(item.get("testCase"), dict) else {}
            if not vars_dict and isinstance(test_case_meta.get("vars"), dict):
                vars_dict = test_case_meta["vars"]

            prompt_obj = item.get("prompt", {})
            raw_prompt = (
                prompt_obj.get("raw", "")
                if isinstance(prompt_obj, dict)
                else str(prompt_obj or vars_dict.get("prompt", ""))
            )

            # Ensure unique test_id fallback if missing
            if "test_id" not in vars_dict:
                vars_dict = dict(vars_dict)
                vars_dict["test_id"] = f"PF-CASE-{idx + 1:03d}"

            tc = build_test_case_from_vars(raw_prompt, vars_dict)
            test_cases.append(tc)

            # Extract response and provider metadata
            resp_obj = item.get("response", {}) if isinstance(item.get("response"), dict) else {}
            output_text = str(resp_obj.get("output", item.get("output", "") or ""))
            resp_meta = resp_obj.get("metadata", {}) if isinstance(resp_obj.get("metadata"), dict) else {}

            tool_calls = resp_meta.get("tool_calls_attempted", [])
            if not isinstance(tool_calls, list):
                tool_calls = []

            latency_ms = float(item.get("latencyMs", resp_meta.get("duration_ms", 0.0)) or 0.0)
            status_code = resp_meta.get("status_code", 200)
            target_provider = str(resp_meta.get("target_name") or default_target_provider)
            model_identifier = str(resp_meta.get("model_identifier") or default_model_identifier)

            # Check for evaluation / provider errors
            item_error = item.get("error") or resp_obj.get("error")
            grading = item.get("gradingResult", {}) if isinstance(item.get("gradingResult"), dict) else {}
            component_results = grading.get("componentResults", []) if isinstance(grading.get("componentResults"), list) else []

            # Format assertion results
            assertion_results: List[Dict[str, Any]] = []
            for comp in component_results:
                if isinstance(comp, dict):
                    assertion_results.append({
                        "pass": bool(comp.get("pass", False)),
                        "score": comp.get("score", 0.0),
                        "reason": redact_sensitive_text(str(comp.get("reason", ""))),
                        "assertion": comp.get("assertion", {}),
                    })
            if not assertion_results and grading:
                assertion_results.append({
                    "pass": bool(grading.get("pass", item.get("success", False))),
                    "score": grading.get("score", item.get("score", 0.0)),
                    "reason": redact_sensitive_text(str(grading.get("reason", ""))),
                })

            # Distinguish infrastructure/evaluation error from assertion failure
            # In Promptfoo, when an assertion fails, `item.get("error")` contains the assertion failure reason,
            # whereas a true provider/infrastructure error has `resp_obj.get("error")` or `resp_meta.get("is_error")`
            # or no gradingResult at all with an error string.
            is_infra_error = bool(
                resp_obj.get("error")
                or resp_meta.get("is_error")
                or (item_error and not grading and not resp_obj.get("output"))
            )

            target_response = TargetResponse(
                output_text=output_text,
                tool_calls_attempted=tool_calls,
                duration_ms=latency_ms,
                status_code=500 if is_infra_error else status_code,
                error=str(item_error) if is_infra_error else None,
            )

            exec_res, finding_res = evaluator.evaluate(tc, target_response)

            # Reconcile Promptfoo assertion grading with OutcomeEvaluator
            pf_passed = bool(grading.get("pass", item.get("success", True))) if not is_infra_error else False
            pf_reason = redact_sensitive_text(str(grading.get("reason", "") or ""))

            failure_reason: Optional[str] = None

            if is_infra_error:
                # Infrastructure or evaluation error: MUST NOT count as successful defense
                exec_res.status = ExecutionStatus.ERROR
                exec_res.defense_outcome = DefenseOutcome.ERROR
                exec_res.attack_objective_achieved = False
                failure_reason = redact_sensitive_text(str(item_error or "Evaluation infrastructure error"))
                exec_res.error_message = failure_reason
                outcome_classification = "evaluation_error"
                finding_res = None
            elif tc.is_benign_control:
                # Benign control evaluation
                if exec_res.defense_outcome == DefenseOutcome.OVERBLOCKING or not pf_passed:
                    exec_res.status = ExecutionStatus.FAILED
                    exec_res.defense_outcome = DefenseOutcome.OVERBLOCKING
                    exec_res.attack_objective_achieved = False
                    failure_reason = pf_reason or exec_res.evaluation_notes or "Benign request was incorrectly refused (False Positive)."
                    exec_res.evaluation_notes = failure_reason
                    outcome_classification = "benign_request_incorrectly_refused"
                else:
                    exec_res.status = ExecutionStatus.PASSED
                    exec_res.defense_outcome = DefenseOutcome.SECURE
                    exec_res.attack_objective_achieved = False
                    outcome_classification = "benign_request_accepted"
            else:
                # Adversarial security evaluation
                if exec_res.attack_objective_achieved or not pf_passed:
                    exec_res.status = ExecutionStatus.FAILED
                    exec_res.defense_outcome = DefenseOutcome.VULNERABLE
                    exec_res.attack_objective_achieved = True
                    failure_reason = exec_res.evaluation_notes if exec_res.attack_objective_achieved else (pf_reason or "Promptfoo security assertion failed.")
                    exec_res.evaluation_notes = failure_reason
                    outcome_classification = "attack_successful"

                    if finding_res is None:
                        finding_res = FindingBase(
                            title=f"Vulnerability in {tc.category.value}: {tc.name}",
                            description=f"Promptfoo security assertion failed: {failure_reason}",
                            category=tc.category,
                            severity=tc.severity,
                            test_case_id=tc.test_id,
                            attack_input_redacted=redact_sensitive_text(tc.input_prompt),
                            target_output_redacted=redact_sensitive_text(output_text),
                            tool_violation_observed=False,
                            canary_leaked=exec_res.canary_detected,
                            tenant_isolation_breached=exec_res.tenant_boundary_violated,
                            remediation_guidance=evaluator._generate_remediation(tc, [failure_reason]),
                        )
                else:
                    exec_res.status = ExecutionStatus.PASSED
                    exec_res.defense_outcome = DefenseOutcome.SECURE
                    exec_res.attack_objective_achieved = False
                    outcome_classification = "attack_blocked"

            executions.append(exec_res)
            if finding_res:
                findings.append(finding_res)

            detailed_items.append(
                PromptfooDetailedItem(
                    test_case_id=tc.test_id,
                    category=tc.category.value,
                    is_benign_control=tc.is_benign_control,
                    target_provider=target_provider,
                    model_identifier=model_identifier,
                    prompt=redact_sensitive_text(tc.input_prompt),
                    sanitized_response=redact_sensitive_text(output_text),
                    assertion_results=assertion_results,
                    final_status=exec_res.status.value,
                    defense_outcome=exec_res.defense_outcome.value,
                    outcome_classification=outcome_classification,
                    attack_objective_achieved=exec_res.attack_objective_achieved,
                    duration_ms=latency_ms,
                    execution_timestamp=timestamp,
                    failure_reason=failure_reason,
                    tool_calls_attempted=tool_calls,
                    canary_detected=exec_res.canary_detected,
                    tenant_boundary_violated=exec_res.tenant_boundary_violated,
                )
            )

        # Delegate all metric calculations to the existing MetricsCalculator engine
        metrics = MetricsCalculator.calculate(test_cases, executions)

        resolved_target = detailed_items[0].target_provider if detailed_items else default_target_provider
        resolved_model = detailed_items[0].model_identifier if detailed_items else default_model_identifier

        return PromptfooEvaluationParsed(
            framework_version=version,
            target_provider=resolved_target,
            model_identifier=resolved_model,
            execution_timestamp=timestamp,
            test_cases=test_cases,
            executions=executions,
            findings=findings,
            metrics=metrics,
            detailed_items=detailed_items,
        )
