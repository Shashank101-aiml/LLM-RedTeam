import { useState } from "react";
import {
  GitCompare,
  AlertTriangle,
  ArrowUpRight,
  ArrowDownRight,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { EvaluationRun, RunComparisonResult } from "../types";
import { compareRuns } from "../api/client";
import { EmptyState } from "../components/EmptyState";
import { LoadingState } from "../components/LoadingState";
import { ErrorBanner } from "../components/ErrorBanner";

interface ComparisonPageProps {
  runs: EvaluationRun[];
}

export function ComparisonPage({ runs }: ComparisonPageProps) {
  const completedRuns = runs.filter(
    (r) => r.status === "passed" || r.status === "failed"
  );

  const [baselineId, setBaselineId] = useState<string>(
    completedRuns.length > 1 ? completedRuns[1].id : completedRuns[0]?.id || ""
  );
  const [candidateId, setCandidateId] = useState<string>(
    completedRuns.length > 0 ? completedRuns[0].id : ""
  );

  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [comparison, setComparison] = useState<RunComparisonResult | null>(null);

  const handleCompare = async () => {
    if (!baselineId || !candidateId) return;
    if (baselineId === candidateId) {
      setError("Please select two distinct runs for comparison.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await compareRuns(baselineId, candidateId);
      setComparison(result);
    } catch (err: any) {
      setError(err.message || "Failed to compare runs");
    } finally {
      setLoading(false);
    }
  };

  if (completedRuns.length < 2) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Run-to-Run Comparison</h2>
          <p className="text-xs text-slate-400">
            Compare candidate models or prompts against baseline benchmarks to detect security regressions.
          </p>
        </div>
        <EmptyState
          title="At Least Two Completed Runs Required"
          description="To run a comparison and detect regressions, execute at least two evaluation runs (e.g. baseline secure vs. candidate target)."
          icon={<GitCompare className="w-8 h-8 text-sky-400" />}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">Run-to-Run Comparison & Regressions</h2>
        <p className="text-xs text-slate-400">
          Measure security deltas, highlight newly introduced vulnerabilities, and detect regressions without fabricated comparisons.
        </p>
      </div>

      {/* Selectors Bar */}
      <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Baseline Run (Reference)</label>
            <select
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
            >
              {completedRuns.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.target_name} ({r.id.slice(0, 8)}) — {new Date(r.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Candidate Run (Under Evaluation)</label>
            <select
              value={candidateId}
              onChange={(e) => setCandidateId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
            >
              {completedRuns.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.target_name} ({r.id.slice(0, 8)}) — {new Date(r.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={handleCompare}
          disabled={loading || baselineId === candidateId}
          className="px-5 py-2 bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-md shadow-sky-500/20"
        >
          {loading ? "Comparing..." : "Execute Differential Comparison"}
        </button>
      </div>

      {error && <ErrorBanner message={error} />}
      {loading && <LoadingState message="Analyzing regressions and calculating delta metrics..." />}

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          {/* Incompatible Suite Warning */}
          {comparison.compatibility_warning && (
            <div className="p-4 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-xl text-xs flex items-center gap-3">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>
                <span className="font-bold">Suite Incompatibility Warning:</span> Over 20% of test cases differ
                between these runs. Regression metrics apply strictly to the intersecting test set.
              </span>
            </div>
          )}

          {/* Delta KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <span className="text-xs text-slate-400 font-medium">&Delta; Attack Success Rate (ASR)</span>
              <div
                className={`text-2xl font-bold flex items-center gap-1.5 ${
                  (comparison.delta_asr || 0) > 0
                    ? "text-rose-400"
                    : (comparison.delta_asr || 0) < 0
                    ? "text-emerald-400"
                    : "text-slate-300"
                }`}
              >
                {(comparison.delta_asr || 0) > 0 ? (
                  <ArrowUpRight className="w-5 h-5" />
                ) : (comparison.delta_asr || 0) < 0 ? (
                  <ArrowDownRight className="w-5 h-5" />
                ) : null}
                {comparison.delta_asr !== null
                  ? `${((comparison.delta_asr || 0) * 100).toFixed(1)}%`
                  : "N/A"}
              </div>
              <p className="text-[11px] text-slate-500">
                {(comparison.delta_asr || 0) > 0
                  ? "Security degraded (+ASR)"
                  : (comparison.delta_asr || 0) < 0
                  ? "Security improved (-ASR)"
                  : "No change"}
              </p>
            </div>

            <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <span className="text-xs text-slate-400 font-medium">Regressions Detected</span>
              <div className="text-2xl font-bold text-rose-400">
                {comparison.regressions_count}
              </div>
              <p className="text-[11px] text-slate-500">
                Tests that passed in baseline but failed in candidate
              </p>
            </div>

            <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
              <span className="text-xs text-slate-400 font-medium">Fixes / Improvements</span>
              <div className="text-2xl font-bold text-emerald-400">
                {comparison.improvements_count}
              </div>
              <p className="text-[11px] text-slate-500">
                Tests that failed in baseline but now pass securely
              </p>
            </div>
          </div>

          {/* Regressions List */}
          {comparison.regression_test_ids.length > 0 && (
            <div className="p-6 bg-slate-900/40 border border-rose-500/30 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-rose-400 flex items-center gap-2">
                <XCircle className="w-4 h-4" />
                Flagged Regressions ({comparison.regression_test_ids.length})
              </h3>
              <p className="text-xs text-slate-400">
                The candidate run yielded to adversarial attacks that were previously successfully blocked by the baseline.
              </p>

              <div className="flex flex-wrap gap-2 pt-2">
                {comparison.regression_test_ids.map((id) => (
                  <span
                    key={id}
                    className="px-2.5 py-1 bg-rose-500/10 border border-rose-500/20 text-rose-300 rounded font-mono text-xs font-semibold"
                  >
                    {id}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Improvements List */}
          {comparison.improvement_test_ids.length > 0 && (
            <div className="p-6 bg-slate-900/40 border border-emerald-500/30 rounded-xl space-y-3">
              <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                Remediated Vulnerabilities ({comparison.improvement_test_ids.length})
              </h3>
              <div className="flex flex-wrap gap-2 pt-2">
                {comparison.improvement_test_ids.map((id) => (
                  <span
                    key={id}
                    className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded font-mono text-xs font-semibold"
                  >
                    {id}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
