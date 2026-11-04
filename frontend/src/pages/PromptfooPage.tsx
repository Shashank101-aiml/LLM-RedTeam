import { useEffect, useState } from "react";
import {
  Terminal,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  FileCode,
  FileSpreadsheet,
  RefreshCw,
  Layers,
  Flame,
  Timer,
} from "lucide-react";
import {
  PromptfooEvaluationRun,
  PromptfooIntegrationStatus,
} from "../types";
import {
  fetchPromptfooRunDetails,
  fetchPromptfooRuns,
  fetchPromptfooStatus,
  getExportCsvUrl,
  getExportJsonUrl,
  triggerPromptfooRun,
} from "../api/client";
import { LoadingState } from "../components/LoadingState";
import { ErrorBanner } from "../components/ErrorBanner";
import { EmptyState } from "../components/EmptyState";

interface PromptfooPageProps {
  onRunCompleted?: () => void;
}

export function PromptfooPage({ onRunCompleted }: PromptfooPageProps) {
  const [status, setStatus] = useState<PromptfooIntegrationStatus | null>(null);
  const [runs, setRuns] = useState<PromptfooEvaluationRun[]>([]);
  const [activeRun, setActiveRun] = useState<PromptfooEvaluationRun | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [executing, setExecuting] = useState<boolean>(false);
  const [executionStateLabel, setExecutionStateLabel] = useState<
    "Idle" | "Queued" | "Running" | "Completed" | "Failed"
  >("Idle");
  const [error, setError] = useState<string | null>(null);

  const [selectedTarget, setSelectedTarget] = useState<string>("mock-secure");
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);

  useEffect(() => {
    loadPromptfooData();
  }, []);

  const loadPromptfooData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statusData, runsData] = await Promise.all([
        fetchPromptfooStatus(),
        fetchPromptfooRuns(),
      ]);
      setStatus(statusData);
      setRuns(runsData);
      if (runsData.length > 0 && !activeRun) {
        setActiveRun(runsData[0]);
        updateStateFromRun(runsData[0]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load Promptfoo integration status");
    } finally {
      setLoading(false);
    }
  };

  const updateStateFromRun = (run: PromptfooEvaluationRun) => {
    if (run.status === "pending") {
      setExecutionStateLabel("Queued");
    } else if (run.status === "running") {
      setExecutionStateLabel("Running");
    } else if (run.status === "error") {
      setExecutionStateLabel("Failed");
    } else {
      setExecutionStateLabel("Completed");
    }
  };

  const toggleCategory = (categoryId: string) => {
    setSelectedCategories((prev) =>
      prev.includes(categoryId)
        ? prev.filter((c) => c !== categoryId)
        : [...prev, categoryId]
    );
  };

  const handleLaunchEvaluation = async () => {
    setExecuting(true);
    setExecutionStateLabel("Queued");
    setError(null);
    try {
      setExecutionStateLabel("Running");
      const completedRun = await triggerPromptfooRun({
        target: selectedTarget,
        selected_categories: selectedCategories,
        async_execution: false,
        notes: "Triggered from Promptfoo Evaluation Dashboard",
      });
      setActiveRun(completedRun);
      updateStateFromRun(completedRun);
      const updatedRuns = await fetchPromptfooRuns();
      setRuns(updatedRuns);
      if (onRunCompleted) {
        onRunCompleted();
      }
    } catch (err: any) {
      setExecutionStateLabel("Failed");
      setError(err.message || "Promptfoo evaluation failed");
    } finally {
      setExecuting(false);
    }
  };

  const handleSelectHistoricalRun = async (runId: string) => {
    try {
      const details = await fetchPromptfooRunDetails(runId);
      setActiveRun(details);
      updateStateFromRun(details);
    } catch (err: any) {
      setError(err.message || "Failed to load Promptfoo run details");
    }
  };

  if (loading) {
    return <LoadingState message="Checking Promptfoo CLI integration and loading runs..." />;
  }

  const metrics = activeRun?.metrics;
  const formatPct = (val: number | null | undefined) =>
    val !== null && val !== undefined ? `${(val * 100).toFixed(1)}%` : "N/A";

  const stateBadgeStyle = (state: string) => {
    switch (state) {
      case "Queued":
        return "bg-slate-800 border-slate-700 text-slate-300";
      case "Running":
        return "bg-amber-500/10 border-amber-500/30 text-amber-400";
      case "Completed":
        return "bg-emerald-500/10 border-emerald-500/30 text-emerald-400";
      case "Failed":
        return "bg-rose-500/10 border-rose-500/30 text-rose-400";
      default:
        return "bg-slate-800 border-slate-700 text-slate-400";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Integration Status */}
      <div className="p-6 bg-gradient-to-r from-slate-900 via-slate-900/90 to-sky-950/40 border border-slate-800 rounded-2xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-5 h-5 text-sky-400" />
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              Promptfoo Security Evaluation Engine
            </h2>
            {status?.available ? (
              <span className="px-2.5 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-full text-[11px] font-bold">
                CLI Active (v{status.version})
              </span>
            ) : (
              <span className="px-2.5 py-0.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-full text-[11px] font-bold">
                CLI Unavailable
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Execute live Promptfoo YAML test suites against LLM-RedTeam target adapters, verify security assertions, and feed sanitized results into the unified metrics engine.
          </p>
        </div>

        {/* Execution Status Pill */}
        <div className="flex items-center gap-3">
          <div
            className={`px-3 py-1.5 rounded-lg border text-xs font-bold flex items-center gap-2 ${stateBadgeStyle(
              executionStateLabel
            )}`}
          >
            {executionStateLabel === "Running" && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            {executionStateLabel === "Queued" && <Clock className="w-3.5 h-3.5" />}
            {executionStateLabel === "Completed" && <CheckCircle2 className="w-3.5 h-3.5" />}
            {executionStateLabel === "Failed" && <AlertTriangle className="w-3.5 h-3.5" />}
            <span>Execution State: {executionStateLabel}</span>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadPromptfooData} />}

      {/* Configuration & Launch Controls */}
      <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
          <div className="space-y-1.5 md:col-span-2">
            <label className="text-xs font-semibold text-slate-300 block">
              Selected Target / Provider Adapter
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              disabled={executing}
              className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-semibold text-slate-200 focus:outline-none focus:border-sky-500"
            >
              {(status?.supported_targets || []).map((t) => (
                <option key={t.id} value={t.id} disabled={status?.safe_mode && !t.safe_mode_compatible}>
                  {t.name} [{t.model_identifier}]{!t.safe_mode_compatible ? " (Requires SAFE_MODE=false)" : ""}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleLaunchEvaluation}
            disabled={executing || !status?.available}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-md shadow-sky-500/20"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${executing ? "animate-spin" : ""}`} />
            <span>{executing ? "Running Promptfoo Eval..." : "Run Promptfoo Evaluation"}</span>
          </button>
        </div>

        {/* Available Evaluation Categories */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">
              Evaluation Categories ({selectedCategories.length === 0 ? "All 6 Categories Selected" : `${selectedCategories.length} Selected`})
            </span>
            {selectedCategories.length > 0 && (
              <button
                onClick={() => setSelectedCategories([])}
                className="text-[11px] text-sky-400 hover:underline font-medium"
              >
                Reset to All Categories
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {(status?.available_categories || []).map((cat) => {
              const isSelected = selectedCategories.includes(cat.id);
              return (
                <button
                  key={cat.id}
                  onClick={() => toggleCategory(cat.id)}
                  disabled={executing}
                  title={cat.description}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                    isSelected
                      ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                      : "bg-slate-950/70 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                  }`}
                >
                  {cat.name}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Results & Metrics Display */}
      {!activeRun ? (
        <EmptyState
          title="No Promptfoo Evaluations Executed Yet"
          description="Select a target adapter and click 'Run Promptfoo Evaluation' to execute the Promptfoo YAML adversarial suites and compute security metrics."
          actionText="Execute Default Secure Evaluation"
          onAction={handleLaunchEvaluation}
          icon={<Terminal className="w-8 h-8 text-sky-400" />}
        />
      ) : (
        <div className="space-y-6">
          {/* Run Selector & Export Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
            <div className="flex items-center gap-3">
              <div>
                <div className="text-xs text-slate-400 font-medium">Active Promptfoo Run</div>
                <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>{activeRun.target_name}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      activeRun.status === "passed"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : activeRun.status === "failed"
                        ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                        : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    }`}
                  >
                    {activeRun.status === "passed"
                      ? "COMPLETED (SECURE)"
                      : activeRun.status === "failed"
                      ? "COMPLETED (VULNERABILITIES DETECTED)"
                      : activeRun.status.toUpperCase()}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2.5 flex-wrap">
              {runs.length > 1 && (
                <select
                  value={activeRun.id}
                  onChange={(e) => handleSelectHistoricalRun(e.target.value)}
                  className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 font-medium"
                >
                  {runs.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.target_name} ({r.id.slice(0, 8)}) — {r.passed_tests}P/{r.failed_tests}F
                    </option>
                  ))}
                </select>
              )}

              <a
                href={getExportJsonUrl(activeRun.id)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
              >
                <FileCode className="w-3.5 h-3.5 text-sky-400" />
                <span>Export JSON</span>
              </a>

              <a
                href={getExportCsvUrl(activeRun.id)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                <span>Export CSV</span>
              </a>
            </div>
          </div>

          {/* KPI Metric Grid (All Required Metrics from Section 7) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Total Tests</span>
                <Layers className="w-3.5 h-3.5 text-sky-400" />
              </div>
              <div className="text-xl font-bold text-slate-100">{activeRun.total_tests}</div>
              <div className="text-[10px] text-slate-500">Promptfoo cases</div>
            </div>

            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Passed / Failed</span>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              </div>
              <div className="text-xl font-bold flex items-center gap-1.5">
                <span className="text-emerald-400">{activeRun.passed_tests}P</span>
                <span className="text-slate-600">/</span>
                <span className="text-rose-400">{activeRun.failed_tests}F</span>
              </div>
              <div className="text-[10px] text-slate-500">{activeRun.errors_count} Errors</div>
            </div>

            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Attack Success (ASR)</span>
                <Flame className="w-3.5 h-3.5 text-rose-400" />
              </div>
              <div className="text-xl font-bold text-rose-400">
                {formatPct(metrics?.attack_success_rate)}
              </div>
              <div className="text-[10px] text-slate-500">Lower is safer</div>
            </div>

            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Security Pass (STPR)</span>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              </div>
              <div className="text-xl font-bold text-emerald-400">
                {formatPct(metrics?.security_pass_rate)}
              </div>
              <div className="text-[10px] text-slate-500">Attacks blocked</div>
            </div>

            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>False Positive (FPR)</span>
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              </div>
              <div className="text-xl font-bold text-amber-400">
                {formatPct(metrics?.false_positive_rate)}
              </div>
              <div className="text-[10px] text-slate-500">Overblocking rate</div>
            </div>

            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Benign Accept (BRAR)</span>
                <CheckCircle2 className="w-3.5 h-3.5 text-sky-400" />
              </div>
              <div className="text-xl font-bold text-sky-400">
                {formatPct(metrics?.benign_acceptance_rate)}
              </div>
              <div className="text-[10px] text-slate-500">1 - FPR utility</div>
            </div>

            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Duration</span>
                <Timer className="w-3.5 h-3.5 text-slate-400" />
              </div>
              <div className="text-xl font-bold text-slate-200">
                {activeRun.duration_ms ? `${(activeRun.duration_ms / 1000).toFixed(2)}s` : "N/A"}
              </div>
              <div className="text-[10px] text-slate-500">Total eval time</div>
            </div>
          </div>

          {/* Detailed Test-Case Results */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-200">
              Detailed Promptfoo Test-Case & Assertion Results (
              {activeRun.detailed_results?.length || activeRun.executions?.length || 0})
            </h3>

            <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900/40">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Test ID & Category</th>
                    <th className="px-4 py-3 font-semibold">Outcome Classification</th>
                    <th className="px-4 py-3 font-semibold">Prompt & Sanitized Response</th>
                    <th className="px-4 py-3 font-semibold">Assertions</th>
                    <th className="px-4 py-3 font-semibold text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {(activeRun.detailed_results && activeRun.detailed_results.length > 0
                    ? activeRun.detailed_results
                    : (activeRun.executions || []).map((e) => ({
                        test_case_id: e.test_case_id,
                        category: "security_probe",
                        is_benign_control: false,
                        target_provider: activeRun.target_name,
                        model_identifier: "sentinel-mock",
                        prompt: "",
                        sanitized_response: e.target_output_sanitized || "",
                        assertion_results: [],
                        final_status: e.status,
                        defense_outcome: e.defense_outcome,
                        outcome_classification: e.defense_outcome,
                        attack_objective_achieved: e.attack_objective_achieved,
                        duration_ms: e.duration_ms,
                        execution_timestamp: e.created_at,
                        failure_reason: e.evaluation_notes,
                        tool_calls_attempted: e.tool_calls_attempted,
                        canary_detected: e.canary_detected,
                        tenant_boundary_violated: e.tenant_boundary_violated,
                      }))
                  ).map((item, idx) => (
                    <tr key={`${item.test_case_id}-${idx}`} className="hover:bg-slate-800/20">
                      <td className="px-4 py-3.5 align-top">
                        <div className="font-mono font-bold text-sky-400">{item.test_case_id}</div>
                        <div className="text-[11px] text-slate-400 capitalize">
                          {item.category.replace(/_/g, " ")}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">
                          {item.model_identifier}
                        </div>
                      </td>

                      <td className="px-4 py-3.5 align-top">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${
                            item.outcome_classification === "attack_blocked" ||
                            item.outcome_classification === "benign_request_accepted"
                              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                              : item.outcome_classification === "benign_request_incorrectly_refused"
                              ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                              : "bg-rose-500/10 border-rose-500/20 text-rose-400"
                          }`}
                        >
                          {item.outcome_classification.replace(/_/g, " ").toUpperCase()}
                        </span>
                        {item.failure_reason && (
                          <p className="text-[11px] text-rose-300/90 mt-1 max-w-xs">
                            {item.failure_reason}
                          </p>
                        )}
                      </td>

                      <td className="px-4 py-3.5 align-top max-w-md space-y-1.5">
                        {item.prompt && (
                          <div className="text-[11px] text-slate-300 font-mono bg-slate-950/70 p-2 rounded border border-slate-800/80">
                            <span className="text-slate-500 font-sans font-semibold">Prompt: </span>
                            {item.prompt}
                          </div>
                        )}
                        <div className="text-[11px] text-slate-400 font-mono bg-slate-950/40 p-2 rounded border border-slate-800/50">
                          <span className="text-slate-500 font-sans font-semibold">Output: </span>
                          {item.sanitized_response}
                        </div>
                      </td>

                      <td className="px-4 py-3.5 align-top">
                        {item.assertion_results && item.assertion_results.length > 0 ? (
                          <div className="space-y-1">
                            {item.assertion_results.map((a, aIdx) => (
                              <div
                                key={aIdx}
                                className="flex items-center gap-1.5 text-[11px]"
                                title={a.reason}
                              >
                                {a.pass ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                ) : (
                                  <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                                )}
                                <span className="text-slate-300 truncate max-w-[160px]">
                                  {a.reason || (a.pass ? "Assertion passed" : "Assertion failed")}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-500 text-[11px]">Evaluated</span>
                        )}
                      </td>

                      <td className="px-4 py-3.5 align-top text-right">
                        <span
                          className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
                            item.final_status === "passed"
                              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                              : "bg-rose-500/10 border-rose-500/20 text-rose-400"
                          }`}
                        >
                          {item.final_status.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
