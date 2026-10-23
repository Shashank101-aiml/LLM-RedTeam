import { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Play,
  CheckCircle2,
  XCircle,
  Activity,
  Layers,
  Flame,
} from "lucide-react";
import { EvaluationRun } from "../types";
import { EmptyState } from "../components/EmptyState";

interface OverviewPageProps {
  runs: EvaluationRun[];
  onTriggerRun: (targetMode: string) => Promise<void>;
  onNavigateToRuns: () => void;
  onNavigateToFindings: () => void;
}

export function OverviewPage({
  runs,
  onTriggerRun,
  onNavigateToRuns,
  onNavigateToFindings,
}: OverviewPageProps) {
  const [triggering, setTriggering] = useState<boolean>(false);
  const [selectedTarget, setSelectedTarget] = useState<string>("Deterministic Mock Target (Secure)");

  const totalRuns = runs.length;
  const latestRun = runs.length > 0 ? runs[0] : null;

  // Aggregate statistics computed strictly from actual run data
  const totalTestsExecuted = runs.reduce((acc, r) => acc + (r.completed_tests || 0), 0);
  const totalFindings = runs.reduce((acc, r) => acc + (r.findings_count || 0), 0);

  // Latest run metrics
  const latestMetrics = latestRun?.metrics;
  const asrPercent =
    latestMetrics?.attack_success_rate !== null && latestMetrics?.attack_success_rate !== undefined
      ? `${(latestMetrics.attack_success_rate * 100).toFixed(1)}%`
      : "N/A";
  const stprPercent =
    latestMetrics?.security_pass_rate !== null && latestMetrics?.security_pass_rate !== undefined
      ? `${(latestMetrics.security_pass_rate * 100).toFixed(1)}%`
      : "N/A";

  const handleLaunch = async () => {
    setTriggering(true);
    try {
      await onTriggerRun(selectedTarget);
    } finally {
      setTriggering(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Trigger */}
      <div className="p-6 bg-gradient-to-r from-slate-900 via-slate-900/90 to-sky-950/40 border border-slate-800 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-sm">
        <div className="space-y-1">
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Security Benchmarking Overview</h2>
          <p className="text-xs text-slate-400 max-w-xl">
            Automated red-team evaluation analyzing prompt injection, canary leakage, unauthorized tool calls, and cross-tenant boundaries.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-semibold text-slate-200 focus:outline-none focus:border-sky-500"
          >
            <option value="Deterministic Mock Target (Secure)">Mock Target (Secure Mode)</option>
            <option value="Deterministic Mock Target (Vulnerable)">Mock Target (Vulnerable Mode)</option>
          </select>
          <button
            onClick={handleLaunch}
            disabled={triggering}
            className="flex items-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all shadow-md shadow-sky-500/20"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${triggering ? "animate-spin" : ""}`} />
            <span>{triggering ? "Evaluating..." : "Launch Evaluation"}</span>
          </button>
        </div>
      </div>

      {/* First-Run Empty State */}
      {totalRuns === 0 ? (
        <EmptyState
          title="No Evaluation Runs Executed Yet"
          description="Your platform is initialized and ready. Launch your first evaluation run against the deterministic mock target to measure attack success rate, canary leakage, and tool authorization boundaries."
          actionText="Execute First Benchmark Run"
          onAction={() => onTriggerRun("Deterministic Mock Target (Secure)")}
          icon={<ShieldCheck className="w-8 h-8 text-sky-400" />}
        />
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-5 bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                <span>Total Runs</span>
                <Layers className="w-4 h-4 text-sky-400" />
              </div>
              <div className="text-2xl font-bold text-slate-100">{totalRuns}</div>
              <p className="text-[11px] text-slate-500">
                {totalTestsExecuted.toLocaleString()} test executions recorded
              </p>
            </div>

            <div className="p-5 bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                <span>Security Pass Rate</span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold text-emerald-400">{stprPercent}</div>
              <p className="text-[11px] text-slate-500">
                Latest run defense effectiveness
              </p>
            </div>

            <div className="p-5 bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                <span>Attack Success Rate</span>
                <Flame className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-2xl font-bold text-rose-400">{asrPercent}</div>
              <p className="text-[11px] text-slate-500">
                Proportion of attacks that breached boundary
              </p>
            </div>

            <div className="p-5 bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                <span>Identified Findings</span>
                <ShieldAlert className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold text-amber-400">{totalFindings}</div>
              <button
                onClick={onNavigateToFindings}
                className="text-[11px] text-sky-400 hover:underline font-medium block"
              >
                Inspect vulnerability triage &rarr;
              </button>
            </div>
          </div>

          {/* Latest Run Snapshot */}
          {latestRun && (
            <div className="p-6 bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2.5">
                  <Activity className="w-4 h-4 text-sky-400" />
                  <h3 className="text-sm font-semibold text-slate-200">Latest Run Summary</h3>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                      latestRun.status === "passed"
                        ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                        : latestRun.status === "failed"
                        ? "bg-rose-500/10 border-rose-500/20 text-rose-400"
                        : "bg-amber-500/10 border-amber-500/20 text-amber-400"
                    }`}
                  >
                    {latestRun.status.toUpperCase()}
                  </span>
                  <button
                    onClick={onNavigateToRuns}
                    className="text-xs text-sky-400 hover:text-sky-300 font-semibold transition"
                  >
                    View all runs &rarr;
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-slate-500 block mb-0.5">Target</span>
                  <span className="font-semibold text-slate-200">{latestRun.target_name}</span>
                </div>
                <div>
                  <span className="text-slate-500 block mb-0.5">Tests Completed</span>
                  <span className="font-semibold text-slate-200">
                    {latestRun.completed_tests} / {latestRun.total_tests}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block mb-0.5">Defensive Result</span>
                  <div className="flex items-center gap-3 font-semibold mt-0.5">
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      {latestRun.passed_tests} Passed
                    </span>
                    <span className="text-rose-400 flex items-center gap-1">
                      <XCircle className="w-3.5 h-3.5" />
                      {latestRun.failed_tests} Failed
                    </span>
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 block mb-0.5">Timestamp</span>
                  <span className="text-slate-300">
                    {new Date(latestRun.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
