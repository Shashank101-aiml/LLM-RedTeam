import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from "recharts";
import { AlertCircle, TrendingUp, BarChart2, Activity } from "lucide-react";
import { EvaluationRun } from "../types";
import { EmptyState } from "../components/EmptyState";

interface MetricsPageProps {
  runs: EvaluationRun[];
}

export function MetricsPage({ runs }: MetricsPageProps) {
  // Filter runs with metrics and sort chronologically for trends
  const validRuns = runs
    .filter((r) => r.metrics !== null && r.metrics !== undefined)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

  if (validRuns.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Metrics & Trends</h2>
          <p className="text-xs text-slate-400">
            Statistical security indicators, attack success rates, and detector precision/recall.
          </p>
        </div>
        <EmptyState
          title="No Metric Snapshots Recorded Yet"
          description="Execute one or more evaluation runs to generate empirical trend data, precision-recall metrics, and latency distributions."
          icon={<BarChart2 className="w-8 h-8 text-sky-400" />}
        />
      </div>
    );
  }

  // Trend data for ASR, STPR, and FPR over time
  const trendData = validRuns.map((r, idx) => ({
    name: `Run #${idx + 1}`,
    target: r.target_name,
    asr: r.metrics?.attack_success_rate !== null ? (r.metrics!.attack_success_rate! * 100).toFixed(1) : 0,
    stpr: r.metrics?.security_pass_rate !== null ? (r.metrics!.security_pass_rate! * 100).toFixed(1) : 0,
    fpr: r.metrics?.false_positive_rate !== null ? (r.metrics!.false_positive_rate! * 100).toFixed(1) : 0,
    medianLatency: r.metrics?.median_latency_ms || 0,
  }));

  const latestRun = validRuns[validRuns.length - 1];
  const m = latestRun.metrics!;

  // Category breakdown for the latest run
  const categoryChartData = Object.entries(m.category_breakdown || {}).map(([cat, stats]) => ({
    category: cat.replace(/_/g, " "),
    total: stats.total || 0,
    passed: stats.passed || 0,
    vulnerabilities: stats.vulnerabilities || 0,
  }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">Security Metrics & Trends</h2>
        <p className="text-xs text-slate-400">
          Empirical mathematical metrics: ASR, Detection Precision & Recall, Overblocking (FPR), and latency.
        </p>
      </div>

      {/* Small sample warning if latest run has < 30 samples */}
      {m.small_sample_warning && (
        <div className="p-4 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-xl text-xs flex items-center gap-3">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <div>
            <span className="font-bold">Small Sample Advisory (N = {m.total_tests}):</span> For sample sizes under
            30, percentage rates should be interpreted alongside Wilson confidence intervals.
            {m.asr_confidence_interval && (
              <span className="ml-1 text-amber-200">
                (95% CI: [{(m.asr_confidence_interval.lower * 100).toFixed(1)}%,{" "}
                {(m.asr_confidence_interval.upper * 100).toFixed(1)}%])
              </span>
            )}
          </div>
        </div>
      )}

      {/* Precision / Recall / FPR Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[11px] text-slate-400 font-medium">Detection Precision</span>
          <div className="text-xl font-bold text-slate-100">
            {m.detection_precision !== null ? `${(m.detection_precision * 100).toFixed(1)}%` : "N/A"}
          </div>
          <p className="text-[10px] text-slate-500">TP / (TP + FP) — True defense ratio</p>
        </div>

        <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[11px] text-slate-400 font-medium">Detection Recall</span>
          <div className="text-xl font-bold text-sky-400">
            {m.detection_recall !== null ? `${(m.detection_recall * 100).toFixed(1)}%` : "N/A"}
          </div>
          <p className="text-[10px] text-slate-500">TP / (TP + FN) — Attack capture rate</p>
        </div>

        <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[11px] text-slate-400 font-medium">False Positive Rate (Overblocking)</span>
          <div className="text-xl font-bold text-amber-400">
            {m.false_positive_rate !== null ? `${(m.false_positive_rate * 100).toFixed(1)}%` : "N/A"}
          </div>
          <p className="text-[10px] text-slate-500">FP / (FP + TN) — Benign requests blocked</p>
        </div>

        <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[11px] text-slate-400 font-medium">Median / P95 Latency</span>
          <div className="text-xl font-bold text-slate-200">
            {m.median_latency_ms.toFixed(1)} / {m.p95_latency_ms.toFixed(1)} ms
          </div>
          <p className="text-[10px] text-slate-500">Target inference duration</p>
        </div>
      </div>

      {/* Trend Chart: ASR vs Security Pass Rate Over Time */}
      <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-200">Security Performance Trends Over Time</h3>
          </div>
          <div className="flex items-center gap-4 text-xs font-medium">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Security Pass Rate (%)
            </span>
            <span className="flex items-center gap-1.5 text-rose-400">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-400" /> Attack Success Rate (%)
            </span>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
              <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} unit="%" />
              <Tooltip
                contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px" }}
              />
              <Line type="monotone" dataKey="stpr" stroke="#10b981" strokeWidth={2} dot={{ r: 4 }} />
              <Line type="monotone" dataKey="asr" stroke="#f43f5e" strokeWidth={2} dot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Category Breakdown Bar Chart */}
      {categoryChartData.length > 0 && (
        <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-slate-200">
                Latest Run Breakdown by Attack Category
              </h3>
            </div>
            <div className="flex items-center gap-4 text-xs font-medium">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Passed
              </span>
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400" /> Vulnerable
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="category" stroke="#64748b" fontSize={10} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px" }}
                />
                <Bar dataKey="passed" fill="#10b981" radius={[4, 4, 0, 0]} />
                <Bar dataKey="vulnerabilities" fill="#f43f5e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
