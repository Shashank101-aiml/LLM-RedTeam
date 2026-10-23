"""
Report Exporter Service for JSON and CSV downloads.

Sanitizes canaries, secrets, and raw outputs in all exports.
"""

import io
import json
import pandas as pd
from sqlalchemy.orm import Session
from app.core.logging_config import redact_sensitive_text
from app.models.evaluation_run import EvaluationRun


class ExportService:
    """Exports completed evaluation runs to sanitized JSON and CSV formats."""

    @staticmethod
    def export_json(db: Session, run_id: str) -> str:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
        if not run:
            raise ValueError("Run not found")

        metrics_data = {}
        if run.metric_snapshot:
            m = run.metric_snapshot
            metrics_data = {
                "total_tests": m.total_tests,
                "attack_attempts": m.attack_attempts,
                "benign_controls": m.benign_controls,
                "attack_success_rate": m.attack_success_rate,
                "security_pass_rate": m.security_pass_rate,
                "detection_precision": m.detection_precision,
                "detection_recall": m.detection_recall,
                "false_positive_rate": m.false_positive_rate,
                "unauthorized_tool_execution_rate": m.unauthorized_tool_execution_rate,
                "canary_leakage_rate": m.canary_leakage_rate,
                "median_latency_ms": m.median_latency_ms,
                "p95_latency_ms": m.p95_latency_ms,
                "small_sample_warning": m.small_sample_warning,
                "category_breakdown": m.category_breakdown,
            }

        findings_data = []
        for f in run.findings:
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "attack_input": redact_sensitive_text(f.attack_input_redacted),
                "target_output": redact_sensitive_text(f.target_output_redacted),
                "remediation": f.remediation_guidance,
            })

        executions_data = []
        for e in run.executions:
            executions_data.append({
                "id": e.id,
                "test_case_id": e.test_case.test_id if e.test_case else e.test_case_id,
                "status": e.status,
                "defense_outcome": e.defense_outcome,
                "attack_objective_achieved": e.attack_objective_achieved,
                "duration_ms": e.duration_ms,
                "target_output": redact_sensitive_text(e.target_output_sanitized or ""),
            })

        report = {
            "report_metadata": {
                "framework": "LLM Sentinel",
                "version": "0.1.0",
                "run_id": run.id,
                "target_name": run.target_name,
                "dataset_version": run.dataset_version,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            },
            "summary_metrics": metrics_data,
            "findings_count": len(findings_data),
            "findings": findings_data,
            "executions": executions_data,
        }

        return json.dumps(report, indent=2)

    @staticmethod
    def export_csv(db: Session, run_id: str) -> str:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
        if not run:
            raise ValueError("Run not found")

        records = []
        for e in run.executions:
            records.append({
                "Run_ID": run.id,
                "Target_Name": run.target_name,
                "Test_ID": e.test_case.test_id if e.test_case else e.test_case_id,
                "Category": e.test_case.category if e.test_case else "unknown",
                "Severity": e.test_case.severity if e.test_case else "medium",
                "Status": e.status,
                "Defense_Outcome": e.defense_outcome,
                "Attack_Achieved": e.attack_objective_achieved,
                "Duration_ms": e.duration_ms,
                "Target_Output_Sanitized": redact_sensitive_text(e.target_output_sanitized or ""),
            })

        df = pd.DataFrame(records)
        output = io.StringIO()
        df.to_csv(output, index=False)
        return output.getvalue()
