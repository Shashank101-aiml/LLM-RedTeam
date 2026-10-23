"""
NVIDIA Garak Evaluation Report Normalizer.

Parses NVIDIA Garak JSON and JSONL report outputs into LLM Sentinel's unified schema,
normalizing probe attempts, mapping detector scores, extracting findings, and preserving provenance.
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


class GarakNormalizer:
    """Normalizes NVIDIA Garak probe evaluations into unified Sentinel benchmark schemas."""

    PROBE_CATEGORY_MAP: Dict[str, AttackCategory] = {
        "promptinject": AttackCategory.DIRECT_PROMPT_INJECTION,
        "encoding": AttackCategory.DIRECT_PROMPT_INJECTION,
        "visual_jailbreak": AttackCategory.DIRECT_PROMPT_INJECTION,
        "continuation": AttackCategory.INDIRECT_PROMPT_INJECTION,
        "rag": AttackCategory.INDIRECT_PROMPT_INJECTION,
        "dan": AttackCategory.JAILBREAK,
        "goodside": AttackCategory.JAILBREAK,
        "realtoxicityprompts": AttackCategory.JAILBREAK,
        "atkgen": AttackCategory.JAILBREAK,
        "leakvec": AttackCategory.SYSTEM_PROMPT_LEAKAGE,
        "systemprompt": AttackCategory.SYSTEM_PROMPT_LEAKAGE,
        "knownbadsignatures": AttackCategory.SYSTEM_PROMPT_LEAKAGE,
        "xss": AttackCategory.UNAUTHORIZED_TOOL_INVOCATION,
        "sql": AttackCategory.UNAUTHORIZED_TOOL_INVOCATION,
        "commandinjection": AttackCategory.UNAUTHORIZED_TOOL_INVOCATION,
        "packagehallucination": AttackCategory.TENANT_ISOLATION,
        "pii": AttackCategory.TENANT_ISOLATION,
    }

    @classmethod
    def _map_category(cls, probe_name: str) -> AttackCategory:
        probe_lower = probe_name.lower().replace("garak.probes.", "")
        for key, cat in cls.PROBE_CATEGORY_MAP.items():
            if key in probe_lower:
                return cat
        if any(k in probe_lower for k in ["leak", "canary", "secret"]):
            return AttackCategory.SYSTEM_PROMPT_LEAKAGE
        if any(k in probe_lower for k in ["jailbreak", "bypass"]):
            return AttackCategory.JAILBREAK
        if any(k in probe_lower for k in ["tool", "exec", "function"]):
            return AttackCategory.UNAUTHORIZED_TOOL_INVOCATION
        return AttackCategory.DIRECT_PROMPT_INJECTION

    @classmethod
    def parse(cls, raw_content: Union[str, Dict[str, Any], List[Dict[str, Any]]]) -> NormalizedBenchmarkReport:
        """Parses Garak JSON or JSONL report into NormalizedBenchmarkReport."""
        entries: List[Dict[str, Any]] = []

        if isinstance(raw_content, str):
            trimmed = raw_content.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    obj = json.loads(trimmed)
                    if "attempts" in obj and isinstance(obj["attempts"], list):
                        entries = obj["attempts"]
                    else:
                        entries = [obj]
                except Exception:
                    entries = []
            if not entries:
                for line in trimmed.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            continue
        elif isinstance(raw_content, dict):
            if "attempts" in raw_content and isinstance(raw_content["attempts"], list):
                entries = raw_content["attempts"]
            else:
                entries = [raw_content]
        elif isinstance(raw_content, list):
            entries = raw_content
        else:
            raise ValueError(f"Unsupported content type for Garak report: {type(raw_content).__name__}")

        if not entries:
            raise ValueError("No valid probe attempts found in Garak report content.")

        garak_version = "unknown"
        target_model = "unknown"
        executions: List[NormalizedExecution] = []
        passed_count = 0
        failed_count = 0
        error_count = 0
        total_findings = 0

        # Scan for config / header entry
        for entry in entries:
            if entry.get("entry_type") == "config":
                garak_version = entry.get("version", garak_version)
                target_model = entry.get("generator", target_model)

        attempt_idx = 0
        for entry in entries:
            entry_type = entry.get("entry_type", "attempt")
            if entry_type != "attempt" and "probe" not in entry:
                continue

            attempt_idx += 1
            probe_name = entry.get("probe", "unknown_probe")
            detector_name = entry.get("detector", "unknown_detector")
            prompt = entry.get("prompt", "")
            outputs = entry.get("outputs", [])
            output_text = outputs[0] if outputs and isinstance(outputs, list) else str(outputs)

            category = cls._map_category(probe_name)

            # In Garak, score 0.0 or trigger indicates vulnerable outcome (attack passed detector)
            scores = entry.get("scores", [])
            is_vulnerable = False
            if scores and isinstance(scores, list):
                if any(s == 0.0 for s in scores) or entry.get("status") in ["FAIL", "failed", 0]:
                    is_vulnerable = True
            elif entry.get("status") in ["FAIL", "failed", 0]:
                is_vulnerable = True

            findings_list: List[NormalizedFinding] = []
            test_id = f"garak-{attempt_idx}"

            if is_vulnerable:
                failed_count += 1
                status = ExecutionStatus.FAILED
                finding_id = f"find-gk-{attempt_idx}-{uuid.uuid4().hex[:6]}"

                finding = NormalizedFinding(
                    finding_id=finding_id,
                    category=category,
                    severity=Severity.HIGH,
                    title=f"Garak Probe Detected Flaw: {probe_name}",
                    description=f"Probe '{probe_name}' triggered detector '{detector_name}' with failure score.",
                    evidence=f"Prompt: {prompt[:200]}... | Target Output: {output_text[:300]}...",
                    remediation=f"Apply filtering and adversarial alignment for probe pattern '{probe_name}'.",
                    source_framework="garak",
                    source_test_id=test_id,
                    raw_metadata={
                        "probe": probe_name,
                        "detector": detector_name,
                        "scores": scores,
                        "notes": entry.get("notes", {}),
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
                input_prompt=prompt,
                output_text=output_text,
                duration_ms=0.0,
                findings=findings_list,
                source_framework="garak",
                provenance={
                    "probe": probe_name,
                    "detector": detector_name,
                    "scores": scores,
                    "attempt_id": entry.get("attempt_id"),
                },
            )
            executions.append(exec_record)

        total_tests = len(executions)
        asr = round(failed_count / total_tests, 4) if total_tests > 0 else 0.0
        stpr = round(passed_count / total_tests, 4) if total_tests > 0 else 1.0

        return NormalizedBenchmarkReport(
            framework="garak",
            framework_version=garak_version,
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
                "source": "garak",
                "version": garak_version,
                "target_model": target_model,
                "total_entries_parsed": len(entries),
            },
        )
