"""
Promptfoo Subprocess Evaluation Runner and Persistence Orchestrator.

Executes genuine Promptfoo CLI evaluations safely (shell=False), captures generated
responses and assertion outcomes, sanitizes artifacts, and persists results into the
LLM-RedTeam database and metrics pipeline.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import redact_sensitive_text
from app.db.session import SessionLocal
from app.integrations.promptfoo.config_generator import (
    PROMPTFOO_CATEGORIES_METADATA,
    PromptfooConfigGenerator,
)
from app.integrations.promptfoo.result_parser import (
    PromptfooEvaluationParsed,
    PromptfooResultParser,
)
from app.integrations.promptfoo.validators import (
    SUPPORTED_TARGETS,
    validate_promptfoo_target,
    validate_safe_cli_arg,
    validate_selected_categories,
)
from app.models.evaluation_run import EvaluationRun
from app.models.finding import Finding
from app.models.metric_snapshot import MetricSnapshot
from app.models.test_case import TestCase
from app.models.test_execution import TestExecution
from app.schemas.enums import ExecutionStatus

logger = logging.getLogger("llm_sentinel.integrations.promptfoo.runner")


@dataclass
class PromptfooRunSummary:
    """Structured summary of a completed Promptfoo CLI execution."""
    status: ExecutionStatus
    exit_code: int
    duration_ms: float
    target_id: str
    target_name: str
    model_identifier: str
    config_path: str
    artifact_path: Optional[str]
    parsed: Optional[PromptfooEvaluationParsed]
    error_message: Optional[str] = None
    stdout_sanitized: str = ""
    stderr_sanitized: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "target_id": self.target_id,
            "target_name": self.target_name,
            "model_identifier": self.model_identifier,
            "config_path": self.config_path,
            "artifact_path": self.artifact_path,
            "error_message": self.error_message,
            "metrics": self.parsed.metrics.model_dump() if self.parsed else None,
            "total_tests": self.parsed.metrics.total_tests if self.parsed else 0,
            "passed_tests": (
                sum(1 for e in self.parsed.executions if e.status == ExecutionStatus.PASSED)
                if self.parsed
                else 0
            ),
            "failed_tests": (
                sum(1 for e in self.parsed.executions if e.status == ExecutionStatus.FAILED)
                if self.parsed
                else 0
            ),
            "errors_count": self.parsed.metrics.errors_count if self.parsed else 0,
            "findings_count": len(self.parsed.findings) if self.parsed else 0,
            "detailed_results": [d.to_dict() for d in self.parsed.detailed_items] if self.parsed else [],
        }


def get_artifacts_dir() -> Path:
    """Returns directory for storing sanitized Promptfoo evaluation artifacts."""
    root = Path(__file__).resolve().parents[4]
    artifacts_dir = root / "artifacts" / "promptfoo"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return artifacts_dir


def resolve_promptfoo_command() -> List[str]:
    """
    Resolves the command list to invoke Promptfoo CLI with shell=False.
    Checks node + promptfoo main entrypoint first (cross-platform & avoids .cmd shell wrappers),
    then falls back to `promptfoo` binary on PATH.
    """
    node_bin = shutil.which("node")

    # Check common global/local node_modules locations for promptfoo entrypoint
    candidate_roots = [
        Path("D:/npm-global/node_modules/promptfoo"),
        Path(__file__).resolve().parents[4] / "node_modules" / "promptfoo",
        Path(__file__).resolve().parents[4] / "frontend" / "node_modules" / "promptfoo",
    ]
    if os.environ.get("APPDATA"):
        candidate_roots.append(Path(os.environ["APPDATA"]) / "npm" / "node_modules" / "promptfoo")

    # Also inspect npm root -g path if promptfoo is on PATH
    pf_which = shutil.which("promptfoo")
    if pf_which:
        pf_path = Path(pf_which).resolve()
        candidate_roots.append(pf_path.parent / "node_modules" / "promptfoo")
        candidate_roots.append(pf_path.parent.parent / "lib" / "node_modules" / "promptfoo")

    if node_bin:
        for root in candidate_roots:
            for rel in ("dist/src/main.js", "bin/promptfoo.js"):
                entry = root / rel
                if entry.exists():
                    return [node_bin, str(entry.resolve())]

    if pf_which:
        return [pf_which]

    npx_which = shutil.which("npx")
    if npx_which:
        return [npx_which, "--no-install", "promptfoo"]

    raise FileNotFoundError(
        "Promptfoo CLI executable not found. Install via 'npm install -g promptfoo'."
    )


def get_promptfoo_status() -> Dict[str, Any]:
    """
    Checks Promptfoo CLI availability and returns integration status, version,
    supported targets, and available evaluation categories.
    """
    available = False
    version = None
    try:
        base_cmd = resolve_promptfoo_command()
        # Fast deterministic version check from package.json when resolved via local node entrypoint
        if len(base_cmd) >= 2 and base_cmd[1].endswith(".js"):
            entry_path = Path(base_cmd[1])
            for parent in [entry_path.parent, *entry_path.parents[:4]]:
                pkg_json = parent / "package.json"
                if pkg_json.exists():
                    try:
                        pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
                        if pkg_data.get("name") == "promptfoo" and pkg_data.get("version"):
                            available = True
                            version = str(pkg_data["version"]).strip()
                            break
                    except Exception:
                        pass

        if not available:
            cmd = base_cmd + ["--version"]
            proc = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                available = True
                version = proc.stdout.strip().splitlines()[-1].strip()
    except Exception:
        available = False
        version = None

    return {
        "integration": "promptfoo",
        "available": available,
        "version": version,
        "safe_mode": settings.SAFE_MODE,
        "allowed_target_hosts": settings.ALLOWED_TARGET_HOSTS,
        "supported_targets": [
            {
                "id": t["id"],
                "name": t["name"],
                "adapter_type": t["adapter_type"],
                "model_identifier": t["model_identifier"],
                "safe_mode_compatible": t["safe_mode_compatible"],
            }
            for t in SUPPORTED_TARGETS.values()
        ],
        "available_categories": PROMPTFOO_CATEGORIES_METADATA,
    }


class PromptfooRunner:
    """
    Executes Promptfoo evaluations safely, sanitizes artifacts, and integrates results
    into the LLM-RedTeam evaluation and persistence pipeline.
    """

    def __init__(
        self,
        config_generator: Optional[PromptfooConfigGenerator] = None,
        artifacts_dir: Optional[Path] = None,
        default_timeout_seconds: float = 120.0,
    ):
        self.config_generator = config_generator or PromptfooConfigGenerator()
        self.artifacts_dir = artifacts_dir or get_artifacts_dir()
        self.default_timeout_seconds = default_timeout_seconds

    @staticmethod
    def _build_safe_env() -> Dict[str, str]:
        """Builds a controlled environment dictionary for subprocess execution."""
        env = os.environ.copy()
        env["PROMPTFOO_DISABLE_TELEMETRY"] = "1"
        env["PROMPTFOO_DISABLE_UPDATE"] = "1"
        env["PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION"] = "1"
        env["CI"] = "true"
        env["PYTHONIOENCODING"] = "utf-8"
        return env

    def run_evaluation(
        self,
        target: str = "mock-secure",
        selected_categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        safe_mode: Optional[bool] = None,
        authorize_external: bool = False,
        timeout_seconds: Optional[float] = None,
        run_id: Optional[str] = None,
    ) -> PromptfooRunSummary:
        """
        Generates a Promptfoo config, executes `promptfoo eval` via subprocess (shell=False),
        sanitizes the resulting artifact, and parses outcomes into the unified metrics engine.
        """
        target_meta = validate_promptfoo_target(
            target=target,
            endpoint_url=endpoint_url,
            safe_mode=safe_mode,
            authorize_external=authorize_external,
        )
        validated_cats = validate_selected_categories(selected_categories)
        eval_id = run_id or str(uuid.uuid4())
        validate_safe_cli_arg(eval_id, "run_id")

        effective_timeout = timeout_seconds or self.default_timeout_seconds
        if effective_timeout <= 0 or effective_timeout > 600:
            raise ValueError("timeout_seconds must be between 0 and 600 seconds.")

        # Prepare config and output paths inside a dedicated directory
        run_artifact_dir = self.artifacts_dir / eval_id
        run_artifact_dir.mkdir(parents=True, exist_ok=True)
        config_path = run_artifact_dir / "promptfoo_config.yaml"
        output_path = run_artifact_dir / "promptfoo_results.json"

        self.config_generator.write_config_file(
            output_path=config_path,
            target=target_meta["id"],
            selected_categories=validated_cats,
            endpoint_url=target_meta.get("endpoint_url"),
            safe_mode=target_meta["safe_mode"],
            authorize_external=authorize_external,
        )

        validate_safe_cli_arg(str(config_path), "config_path")
        validate_safe_cli_arg(str(output_path), "output_path")

        start_time = time.perf_counter()
        try:
            cmd_prefix = resolve_promptfoo_command()
            cmd = cmd_prefix + [
                "eval",
                "-c",
                str(config_path),
                "-o",
                str(output_path),
                "--no-cache",
                "--no-progress-bar",
            ]

            proc = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout,
                env=self._build_safe_env(),
                check=False,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000
        except subprocess.TimeoutExpired as timeout_exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return PromptfooRunSummary(
                status=ExecutionStatus.ERROR,
                exit_code=-1,
                duration_ms=elapsed_ms,
                target_id=target_meta["id"],
                target_name=target_meta["name"],
                model_identifier=target_meta["model_identifier"],
                config_path=str(config_path),
                artifact_path=None,
                parsed=None,
                error_message=f"Promptfoo evaluation timed out after {effective_timeout}s.",
                stdout_sanitized=redact_sensitive_text(str(timeout_exc.stdout or "")),
                stderr_sanitized=redact_sensitive_text(str(timeout_exc.stderr or "")),
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return PromptfooRunSummary(
                status=ExecutionStatus.ERROR,
                exit_code=-1,
                duration_ms=elapsed_ms,
                target_id=target_meta["id"],
                target_name=target_meta["name"],
                model_identifier=target_meta["model_identifier"],
                config_path=str(config_path),
                artifact_path=None,
                parsed=None,
                error_message=f"Promptfoo subprocess execution failed: {redact_sensitive_text(str(exc))}",
            )

        stdout_clean = redact_sensitive_text(proc.stdout or "")
        stderr_clean = redact_sensitive_text(proc.stderr or "")

        if not output_path.exists():
            return PromptfooRunSummary(
                status=ExecutionStatus.ERROR,
                exit_code=proc.returncode,
                duration_ms=elapsed_ms,
                target_id=target_meta["id"],
                target_name=target_meta["name"],
                model_identifier=target_meta["model_identifier"],
                config_path=str(config_path),
                artifact_path=None,
                parsed=None,
                error_message=(
                    f"Promptfoo exited with code {proc.returncode} without producing output file. "
                    f"Stderr: {stderr_clean[:500]}"
                ),
                stdout_sanitized=stdout_clean,
                stderr_sanitized=stderr_clean,
            )

        try:
            raw_text = output_path.read_text(encoding="utf-8")
            parsed = PromptfooResultParser.parse(
                raw_output=raw_text,
                default_target_provider=target_meta["name"],
                default_model_identifier=target_meta["model_identifier"],
            )

            # Sanitize the stored artifact file on disk so no raw canaries/secrets remain on disk
            sanitized_artifact_text = redact_sensitive_text(raw_text)
            output_path.write_text(sanitized_artifact_text, encoding="utf-8")
        except Exception as parse_exc:
            return PromptfooRunSummary(
                status=ExecutionStatus.ERROR,
                exit_code=proc.returncode,
                duration_ms=elapsed_ms,
                target_id=target_meta["id"],
                target_name=target_meta["name"],
                model_identifier=target_meta["model_identifier"],
                config_path=str(config_path),
                artifact_path=str(output_path),
                parsed=None,
                error_message=f"Failed to parse Promptfoo output: {redact_sensitive_text(str(parse_exc))}",
                stdout_sanitized=stdout_clean,
                stderr_sanitized=stderr_clean,
            )

        # Determine overall run status:
        # - If all tests resulted in infrastructure error, status is ERROR
        # - If any finding or failed test exists (including benign overblocking), status is FAILED
        # - Otherwise status is PASSED
        failed_count = sum(1 for e in parsed.executions if e.status == ExecutionStatus.FAILED)
        error_count = parsed.metrics.errors_count
        if parsed.metrics.total_tests > 0 and error_count == parsed.metrics.total_tests:
            overall_status = ExecutionStatus.ERROR
        elif failed_count > 0 or len(parsed.findings) > 0 or error_count > 0:
            overall_status = ExecutionStatus.FAILED
        else:
            overall_status = ExecutionStatus.PASSED

        return PromptfooRunSummary(
            status=overall_status,
            exit_code=proc.returncode,
            duration_ms=elapsed_ms,
            target_id=target_meta["id"],
            target_name=target_meta["name"],
            model_identifier=target_meta["model_identifier"],
            config_path=str(config_path),
            artifact_path=str(output_path),
            parsed=parsed,
            stdout_sanitized=stdout_clean,
            stderr_sanitized=stderr_clean,
        )

    @staticmethod
    def create_pending_run(
        db: Session,
        target: str = "mock-secure",
        selected_categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        safe_mode: Optional[bool] = None,
        authorize_external: bool = False,
        notes: Optional[str] = None,
    ) -> EvaluationRun:
        """
        Validates parameters and creates a PENDING EvaluationRun record for Promptfoo execution.
        """
        target_meta = validate_promptfoo_target(
            target=target,
            endpoint_url=endpoint_url,
            safe_mode=safe_mode,
            authorize_external=authorize_external,
        )
        gen = PromptfooConfigGenerator()
        tests = gen.load_tests(selected_categories=selected_categories)

        run_target_label = f"Promptfoo: {target_meta['name']}"
        run = EvaluationRun(
            id=str(uuid.uuid4()),
            target_name=run_target_label,
            status=ExecutionStatus.PENDING.value,
            dataset_version="promptfoo-v1.0.0",
            random_seed=42,
            notes=notes or f"Promptfoo evaluation against {target_meta['name']}",
            total_tests=len(tests),
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
    def persist_summary_to_run(
        db: Session,
        run: EvaluationRun,
        summary: PromptfooRunSummary,
    ) -> EvaluationRun:
        """
        Persists a completed PromptfooRunSummary into the given EvaluationRun,
        storing TestCases, TestExecutions, Findings, and MetricSnapshot.
        """
        if not summary.parsed:
            run.status = ExecutionStatus.ERROR.value
            run.notes = redact_sensitive_text(summary.error_message or "Promptfoo execution failed.")
            run.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(run)
            return run

        parsed = summary.parsed
        tc_db_map: Dict[str, str] = {}

        # 1. Ensure all Promptfoo test cases exist in TestCase table
        for tc in parsed.test_cases:
            existing_tc = db.query(TestCase).filter(TestCase.test_id == tc.test_id).first()
            if not existing_tc:
                existing_tc = TestCase(
                    id=str(uuid.uuid4()),
                    test_id=tc.test_id,
                    category=tc.category.value,
                    name=tc.name,
                    description=tc.description,
                    severity=tc.severity.value,
                    is_benign_control=tc.is_benign_control,
                    requires_human_review=tc.requires_human_review,
                    tags=tc.tags,
                    input_prompt=redact_sensitive_text(tc.input_prompt),
                    system_prompt=redact_sensitive_text(tc.system_prompt) if tc.system_prompt else None,
                    retrieved_context=redact_sensitive_text(tc.retrieved_context) if tc.retrieved_context else None,
                    synthetic_canary="[REDACTED_CANARY]" if tc.synthetic_canary else None,
                    tenant_id=tc.tenant_id,
                    user_role=tc.user_role,
                    target_tool_name=tc.target_tool_name,
                    expected_outcome=tc.expected_outcome.model_dump(),
                )
                db.add(existing_tc)
                db.flush()
            tc_db_map[tc.test_id] = existing_tc.id

        # 2. Persist TestExecution records
        passed_count = 0
        failed_count = 0
        errors_count = 0

        for exec_res in parsed.executions:
            if exec_res.status == ExecutionStatus.PASSED:
                passed_count += 1
            elif exec_res.status == ExecutionStatus.FAILED:
                failed_count += 1
            elif exec_res.status == ExecutionStatus.ERROR:
                errors_count += 1

            db_exec = TestExecution(
                id=str(uuid.uuid4()),
                run_id=run.id,
                test_case_id=tc_db_map.get(exec_res.test_case_id, exec_res.test_case_id),
                status=exec_res.status.value,
                defense_outcome=exec_res.defense_outcome.value,
                attack_objective_achieved=exec_res.attack_objective_achieved,
                duration_ms=exec_res.duration_ms,
                error_message=redact_sensitive_text(exec_res.error_message) if exec_res.error_message else None,
                target_output_sanitized=redact_sensitive_text(exec_res.target_output_sanitized or ""),
                tool_calls_attempted=exec_res.tool_calls_attempted,
                canary_detected=exec_res.canary_detected,
                tenant_boundary_violated=exec_res.tenant_boundary_violated,
                evaluation_notes=redact_sensitive_text(exec_res.evaluation_notes or ""),
            )
            db.add(db_exec)

        # 3. Persist Finding records
        for finding_res in parsed.findings:
            db_finding = Finding(
                id=str(uuid.uuid4()),
                run_id=run.id,
                test_case_id=tc_db_map.get(finding_res.test_case_id, finding_res.test_case_id),
                title=finding_res.title,
                description=redact_sensitive_text(finding_res.description),
                category=finding_res.category.value,
                severity=finding_res.severity.value,
                attack_input_redacted=redact_sensitive_text(finding_res.attack_input_redacted),
                target_output_redacted=redact_sensitive_text(finding_res.target_output_redacted),
                tool_violation_observed=finding_res.tool_violation_observed,
                canary_leaked=finding_res.canary_leaked,
                tenant_isolation_breached=finding_res.tenant_isolation_breached,
                remediation_guidance=finding_res.remediation_guidance,
            )
            db.add(db_finding)

        # 4. Persist MetricSnapshot (including Promptfoo detailed items in category_breakdown metadata)
        snap = parsed.metrics
        existing_snap = db.query(MetricSnapshot).filter(MetricSnapshot.run_id == run.id).first()
        if existing_snap:
            db.delete(existing_snap)
            db.flush()

        db_snapshot = MetricSnapshot(
            id=str(uuid.uuid4()),
            run_id=run.id,
            total_tests=snap.total_tests,
            attack_attempts=snap.attack_attempts,
            benign_controls=snap.benign_controls,
            attack_success_rate=snap.attack_success_rate,
            security_pass_rate=snap.security_pass_rate,
            detection_precision=snap.detection_precision,
            detection_recall=snap.detection_recall,
            false_positive_rate=snap.false_positive_rate,
            benign_acceptance_rate=snap.benign_acceptance_rate,
            unauthorized_tool_execution_rate=snap.unauthorized_tool_execution_rate,
            canary_leakage_rate=snap.canary_leakage_rate,
            tenant_isolation_breach_rate=snap.tenant_isolation_breach_rate,
            true_positives=snap.true_positives,
            false_positives=snap.false_positives,
            true_negatives=snap.true_negatives,
            false_negatives=snap.false_negatives,
            errors_count=snap.errors_count,
            skipped_count=snap.skipped_count,
            median_latency_ms=snap.median_latency_ms,
            p95_latency_ms=snap.p95_latency_ms,
            small_sample_warning=snap.small_sample_warning,
            asr_confidence_interval=(
                snap.asr_confidence_interval.model_dump() if snap.asr_confidence_interval else None
            ),
            category_breakdown=snap.category_breakdown,
        )
        db.add(db_snapshot)

        # 5. Save sanitized detailed summary artifact for API retrieval
        summary_file = get_artifacts_dir() / run.id / "sentinel_summary.json"
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text(
            redact_sensitive_text(json.dumps(summary.to_dict(), indent=2)),
            encoding="utf-8",
        )

        # 6. Update run counters and final status
        run.total_tests = snap.total_tests
        run.completed_tests = passed_count + failed_count + errors_count
        run.passed_tests = passed_count
        run.failed_tests = failed_count
        run.errors_count = errors_count
        run.findings_count = len(parsed.findings)
        run.status = summary.status.value
        run.completed_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(run)
        return run

    @classmethod
    def execute_run_task(
        cls,
        run_id: str,
        target: str = "mock-secure",
        selected_categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        safe_mode: Optional[bool] = None,
        authorize_external: bool = False,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        """
        Executes a Promptfoo evaluation run in the background (or synchronously) and updates DB state.
        """
        db: Session = SessionLocal()
        try:
            run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
            if not run:
                return

            run.status = ExecutionStatus.RUNNING.value
            db.commit()

            runner = cls()
            summary = runner.run_evaluation(
                target=target,
                selected_categories=selected_categories,
                endpoint_url=endpoint_url,
                safe_mode=safe_mode,
                authorize_external=authorize_external,
                timeout_seconds=timeout_seconds,
                run_id=run_id,
            )
            cls.persist_summary_to_run(db, run, summary)
        except Exception as exc:
            run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
            if run:
                run.status = ExecutionStatus.ERROR.value
                run.notes = f"Promptfoo execution error: {redact_sensitive_text(str(exc))}"
                run.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
