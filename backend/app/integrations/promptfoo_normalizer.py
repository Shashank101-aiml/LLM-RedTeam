"""
Promptfoo Evaluation Report Normalizer.

Parses Promptfoo evaluation JSON exports into LLM Sentinel's unified schema,
normalizing findings, mapping threat categories, and preserving full provenance.
"""

import json
from typing import Any, Dict, List, Union
import uuid

from app.integrations.schemas import (
    NormalizedBenchmarkReport,
    NormalizedExecution,
    NormalizedFinding,
)
from app.schemas.enums import AttackCategory, ExecutionStatus, Severity


class PromptfooNormalizer:
    """Normalizes Promptfoo evaluation results into unified Sentinel benchmark schemas."""

    @staticmethod
    def _categorize(text_sample: str) -> AttackCategory:
        s = text_sample.lower()
        if any(k in s for k in ["rag", "retrieval", "document", "external context", "indirect"]):
            return AttackCategory.INDIRECT_PROMPT_INJECTION
        if any(k in s for k in ["jailbreak", "dan", "harmful", "adversarial roleplay", "unfiltered"]):
            return AttackCategory.JAILBREAK
        if any(k in s for k in ["canary", "system-prompt", "leak", "system prompt", "instruction extraction"]):
            return AttackCategory.SYSTEM_PROMPT_LEAKAGE
        if any(k in s for k in ["tool", "function", "exec", "database", "sql", "unauthorized"]):
            return AttackCategory.UNAUTHORIZED_TOOL_INVOCATION
        if any(k in s for k in ["tenant", "isolation", "pii", "exfiltration", "cross-tenant"]):
            return AttackCategory.TENANT_ISOLATION
        return AttackCategory.DIRECT_PROMPT_INJECTION

    @classmethod
    def parse(cls, raw_data: Union[str, Dict[str, Any]]) -> NormalizedBenchmarkReport:
        """Parses a Promptfoo JSON export into NormalizedBenchmarkReport."""
        if isinstance(raw_data, str):
            try:
                data = json.loads(raw_data)
            except Exception as e:
                raise ValueError(f"Invalid JSON provided for Promptfoo normalizer: {str(e)}") from e
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            raise ValueError(f"Expected JSON string or dict, got {type(raw_data).__name__}")

        version = data.get("version", "unknown")
        results = data.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Promptfoo report is missing valid 'results' list.")

        target_model = "unknown"
        if "config" in data and isinstance(data["config"], dict):
            providers = data["config"].get("providers", [])
            if providers and isinstance(providers, list):
                target_model = str(providers[0])

        executions: List[NormalizedExecution] = []
        total_findings = 0
        passed_count = 0
        failed_count = 0
        error_count = 0

        for idx, item in enumerate(results):
            test_id = f"promptfoo-{idx + 1}"
            prompt_obj = item.get("prompt", {})
            input_prompt = prompt_obj.get("raw", "") if isinstance(prompt_obj, dict) else str(prompt_obj)

            response_obj = item.get("response", {})
            output_text = response_obj.get("output", "") if isinstance(response_obj, dict) else str(response_obj)

            grading = item.get("gradingResult", {})
            success = item.get("success", False)
            latency_ms = item.get("latencyMs", 0.0)

            category = cls._categorize(f"{input_prompt} {str(grading)}")

            findings_list: List[NormalizedFinding] = []
            if not success:
                failed_count += 1
                status = ExecutionStatus.FAILED

                # Create normalized finding
                severity = Severity.HIGH
                if category in [AttackCategory.UNAUTHORIZED_TOOL_INVOCATION, AttackCategory.TENANT_ISOLATION]:
                    severity = Severity.CRITICAL

                reason = grading.get("reason", "Promptfoo assertion check failed.") if isinstance(grading, dict) else "Assertion failed"
                finding_id = f"find-pf-{idx + 1}-{uuid.uuid4().hex[:6]}"

                finding = NormalizedFinding(
                    finding_id=finding_id,
                    category=category,
                    severity=severity,
                    title=f"Promptfoo Vulnerability: {category.value.replace('_', ' ').title()}",
                    description=f"Promptfoo assertion failed: {reason}",
                    evidence=f"Input: {input_prompt[:200]}... | Output: {output_text[:300]}...",
                    remediation=f"Strengthen guardrails against {category.value.replace('_', ' ')} attacks.",
                    source_framework="promptfoo",
                    source_test_id=test_id,
                    raw_metadata={
                        "grading_result": grading,
                        "vars": item.get("vars", {}),
                        "score": item.get("score"),
                    },
                )
                findings_list.append(finding)
                total_findings += 1
            else:
                passed_count += 1
                status = ExecutionStatus.PASSED

            exec_record = NormalizedExecution(
                test_id=test_id,
                category=category,
                status=status,
                input_prompt=input_prompt,
                output_text=output_text,
                duration_ms=float(latency_ms),
                findings=findings_list,
                source_framework="promptfoo",
                provenance={
                    "promptfoo_index": idx,
                    "score": item.get("score"),
                    "named_scores": item.get("namedScores", {}),
                },
            )
            executions.append(exec_record)

        total_tests = len(executions)
        asr = round(failed_count / total_tests, 4) if total_tests > 0 else 0.0
        stpr = round(passed_count / total_tests, 4) if total_tests > 0 else 1.0

        return NormalizedBenchmarkReport(
            framework="promptfoo",
            framework_version=version,
            target_model=target_model,
            total_tests=total_tests,
            passed_tests=passed_count,
            failed_tests=failed_count,
            errors_count=error_count,
            findings_count=total_findings,
            attack_success_rate=asr,
            security_pass_rate=stpr,
            executions=executions,
            provenance={
                "source": "promptfoo",
                "version": version,
                "config": data.get("config", {}),
                "shareable_url": data.get("shareableUrl"),
            },
        )
