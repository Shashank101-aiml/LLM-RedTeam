"""
LLM-RedTeam — Deterministic Promptfoo Security Evaluation & Regression Runner.

Executes real Promptfoo CLI evaluations against the LLM-RedTeam MockTarget
(Vulnerable Baseline vs. Secure Candidate), validates configurations, processes
outcomes through the unified MetricsCalculator, verifies zero regressions on the
defended target, and exports sanitized JSON, CSV, and HTML evaluation reports.
"""

import argparse
from datetime import UTC, datetime
import html
import json
import os
from pathlib import Path
import sys

# Ensure backend is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.config import settings
from app.core.logging_config import redact_sensitive_text
from app.db.session import SessionLocal, init_db
from app.integrations.promptfoo.config_generator import PromptfooConfigGenerator
from app.integrations.promptfoo.runner import PromptfooRunner, get_promptfoo_status
from app.integrations.promptfoo.validators import validate_promptfoo_config_dict
from app.services.comparison_service import ComparisonService
from app.services.export_service import ExportService


def generate_sanitized_html_report(json_report_str: str) -> str:
    """Generates a self-contained sanitized HTML report from the exported JSON report."""
    data = json.loads(redact_sensitive_text(json_report_str))
    meta = data.get("report_metadata", {})
    metrics = data.get("summary_metrics", {})
    findings = data.get("findings", [])
    executions = data.get("executions", [])

    rows_html = []
    for ex in executions:
        status_val = html.escape(str(ex.get("status", "")))
        badge_color = "#10b981" if status_val == "passed" else "#f43f5e"
        rows_html.append(
            f"<tr>"
            f"<td><code>{html.escape(str(ex.get('test_case_id', '')))}</code></td>"
            f"<td><span style='color:{badge_color};font-weight:bold'>{status_val.upper()}</span></td>"
            f"<td>{html.escape(str(ex.get('defense_outcome', '')))}</td>"
            f"<td>{html.escape(str(ex.get('duration_ms', 0.0)))} ms</td>"
            f"<td><code>{html.escape(str(ex.get('target_output', '')))}</code></td>"
            f"</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>LLM-RedTeam Sanitized Promptfoo Security Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #f1f5f9; padding: 2rem; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 1.25rem; margin-bottom: 1.5rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th, td {{ text-align: left; padding: 0.65rem; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; }}
    code {{ font-family: monospace; color: #38bdf8; }}
  </style>
</head>
<body>
  <h1>LLM-RedTeam — Promptfoo Security Evaluation Report (Sanitized)</h1>
  <div class="card">
    <p><strong>Run ID:</strong> <code>{html.escape(str(meta.get("run_id", "")))}</code></p>
    <p><strong>Target:</strong> {html.escape(str(meta.get("target_name", "")))}</p>
    <p><strong>Dataset Version:</strong> {html.escape(str(meta.get("dataset_version", "")))}</p>
    <p><strong>Total Tests:</strong> {metrics.get("total_tests", 0)} |
       <strong>ASR:</strong> {metrics.get("attack_success_rate")} |
       <strong>STPR:</strong> {metrics.get("security_pass_rate")} |
       <strong>FPR:</strong> {metrics.get("false_positive_rate")} |
       <strong>Findings:</strong> {len(findings)}</p>
  </div>
  <div class="card">
    <h2>Test Case Executions</h2>
    <table>
      <thead>
        <tr><th>Test ID</th><th>Status</th><th>Defense Outcome</th><th>Duration</th><th>Sanitized Output</th></tr>
      </thead>
      <tbody>
        {"".join(rows_html)}
      </tbody>
    </table>
  </div>
</body>
</html>"""


def run_cli(
    target: str = "both",
    categories: list[str] | None = None,
    output_dir: str = "artifacts/promptfoo/reports",
    fail_on_regression: bool = True,
) -> int:
    print("=" * 80)
    print("  LLM-REDTEAM — PROMPTFOO EXECUTABLE SECURITY EVALUATION RUNNER")
    print("=" * 80)
    status_info = get_promptfoo_status()
    print(f"Timestamp:         {datetime.now(UTC).isoformat()}")
    print(f"Promptfoo CLI:     {'Available' if status_info['available'] else 'NOT FOUND'} (v{status_info['version']})")
    print(f"Safe Mode:         {settings.SAFE_MODE}")
    print(f"Selected Target:   {target}")
    print(f"Categories:        {categories if categories else 'ALL (6 Security & Benign Categories)'}")
    print("-" * 80)

    if not status_info["available"]:
        print("ERROR: Promptfoo CLI is not available. Install via 'npm install -g promptfoo'.")
        return 1

    # 1. Validate Promptfoo configuration
    print("\n[Step 1/4] Validating Promptfoo YAML Configuration & Test Corpus...")
    gen = PromptfooConfigGenerator()
    cfg = gen.generate_config(target="mock-secure", selected_categories=categories)
    validate_promptfoo_config_dict(cfg)
    print(f"  Validated {len(cfg['tests'])} Promptfoo test cases across configured YAML suites.")

    init_db()
    db = SessionLocal()
    runner = PromptfooRunner()
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    try:
        if target == "both":
            # Execute Vulnerable Baseline + Secure Candidate and compare
            print("\n[Step 2/4] Executing Promptfoo Evaluation against Vulnerable Mock Target...")
            vuln_run = PromptfooRunner.create_pending_run(
                db, target="mock-vulnerable", selected_categories=categories
            )
            vuln_summary = runner.run_evaluation(
                target="mock-vulnerable",
                selected_categories=categories,
                run_id=vuln_run.id,
            )
            vuln_run = PromptfooRunner.persist_summary_to_run(db, vuln_run, vuln_summary)
            vm = vuln_run.metric_snapshot
            print(f"  Vulnerable Run ID: {vuln_run.id}")
            print(f"  Status:            {vuln_run.status.upper()} (Exit Code: {vuln_summary.exit_code})")
            print(f"  Passed / Failed:   {vuln_run.passed_tests}P / {vuln_run.failed_tests}F")
            print(f"  ASR:               {vm.attack_success_rate:.2%}" if vm and vm.attack_success_rate is not None else "  ASR: N/A")
            print(f"  STPR:              {vm.security_pass_rate:.2%}" if vm and vm.security_pass_rate is not None else "  STPR: N/A")
            print(f"  FPR / BRAR:        {vm.false_positive_rate:.2%} / {vm.benign_acceptance_rate:.2%}" if vm and vm.false_positive_rate is not None else "  FPR: N/A")

            print("\n[Step 3/4] Executing Promptfoo Evaluation against Secure Mock Target...")
            sec_run = PromptfooRunner.create_pending_run(
                db, target="mock-secure", selected_categories=categories
            )
            sec_summary = runner.run_evaluation(
                target="mock-secure",
                selected_categories=categories,
                run_id=sec_run.id,
            )
            sec_run = PromptfooRunner.persist_summary_to_run(db, sec_run, sec_summary)
            sm = sec_run.metric_snapshot
            print(f"  Secure Run ID:     {sec_run.id}")
            print(f"  Status:            {sec_run.status.upper()} (Exit Code: {sec_summary.exit_code})")
            print(f"  Passed / Failed:   {sec_run.passed_tests}P / {sec_run.failed_tests}F")
            print(f"  ASR:               {sm.attack_success_rate:.2%}" if sm and sm.attack_success_rate is not None else "  ASR: N/A")
            print(f"  STPR:              {sm.security_pass_rate:.2%}" if sm and sm.security_pass_rate is not None else "  STPR: N/A")
            print(f"  FPR / BRAR:        {sm.false_positive_rate:.2%} / {sm.benign_acceptance_rate:.2%}" if sm and sm.false_positive_rate is not None else "  FPR: N/A")

            print("\n[Step 4/4] Computing Regression Comparison & Exporting Sanitized Reports...")
            diff = ComparisonService.compare_runs(db, baseline_run_id=vuln_run.id, candidate_run_id=sec_run.id)
            print(f"  Delta ASR:         {diff.delta_asr:+.2%}" if diff.delta_asr is not None else "  Delta ASR: N/A")
            print(f"  Delta STPR:        {diff.delta_security_pass_rate:+.2%}" if diff.delta_security_pass_rate is not None else "  Delta STPR: N/A")
            print(f"  Regressions:       {diff.regressions_count}")
            print(f"  Improvements:      {diff.improvements_count}")

            # Export sanitized reports
            for label, r_obj in [("vulnerable", vuln_run), ("secure", sec_run)]:
                j_str = ExportService.export_json(db, r_obj.id)
                c_str = ExportService.export_csv(db, r_obj.id)
                h_str = generate_sanitized_html_report(j_str)

                (out_path / f"promptfoo_{label}_report.json").write_text(j_str, encoding="utf-8")
                (out_path / f"promptfoo_{label}_report.csv").write_text(c_str, encoding="utf-8")
                (out_path / f"promptfoo_{label}_report.html").write_text(h_str, encoding="utf-8")

            comparison_out = out_path / "promptfoo_comparison.json"
            comparison_out.write_text(json.dumps(diff.model_dump(), indent=2), encoding="utf-8")
            print(f"  Reports written to: {out_path.resolve()}")

            if fail_on_regression and (sec_run.failed_tests > 0 or diff.regressions_count > 0):
                print("ERROR: Security regression detected on Secure Target!")
                return 1
            return 0
        else:
            print(f"\n[Step 2/3] Executing Promptfoo Evaluation against '{target}'...")
            single_run = PromptfooRunner.create_pending_run(
                db, target=target, selected_categories=categories
            )
            summary = runner.run_evaluation(
                target=target,
                selected_categories=categories,
                run_id=single_run.id,
            )
            single_run = PromptfooRunner.persist_summary_to_run(db, single_run, summary)
            m = single_run.metric_snapshot
            print(f"  Run ID:            {single_run.id}")
            print(f"  Status:            {single_run.status.upper()} (Exit Code: {summary.exit_code})")
            print(f"  Passed / Failed:   {single_run.passed_tests}P / {single_run.failed_tests}F")
            if m:
                print(f"  ASR:               {m.attack_success_rate}")
                print(f"  STPR:              {m.security_pass_rate}")
                print(f"  FPR / BRAR:        {m.false_positive_rate} / {m.benign_acceptance_rate}")

            print("\n[Step 3/3] Exporting Sanitized Reports...")
            j_str = ExportService.export_json(db, single_run.id)
            c_str = ExportService.export_csv(db, single_run.id)
            h_str = generate_sanitized_html_report(j_str)

            (out_path / "promptfoo_report.json").write_text(j_str, encoding="utf-8")
            (out_path / "promptfoo_report.csv").write_text(c_str, encoding="utf-8")
            (out_path / "promptfoo_report.html").write_text(h_str, encoding="utf-8")
            print(f"  Reports written to: {out_path.resolve()}")

            if fail_on_regression and target == "mock-secure" and single_run.failed_tests > 0:
                return 1
            return 0
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Promptfoo Security Evaluations in LLM-RedTeam")
    parser.add_argument(
        "--target",
        default="both",
        help="Target to evaluate ('mock-secure', 'mock-vulnerable', 'ai-iam-local', or 'both')",
    )
    parser.add_argument(
        "--categories",
        nargs="*",
        default=None,
        help="Optional list of evaluation categories to run",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/promptfoo/reports",
        help="Directory to write sanitized JSON/CSV/HTML reports",
    )
    parser.add_argument(
        "--no-fail-on-regression",
        action="store_true",
        help="Do not exit non-zero when vulnerabilities are found",
    )
    args = parser.parse_args()
    sys.exit(
        run_cli(
            target=args.target,
            categories=args.categories,
            output_dir=args.output_dir,
            fail_on_regression=not args.no_fail_on_regression,
        )
    )
