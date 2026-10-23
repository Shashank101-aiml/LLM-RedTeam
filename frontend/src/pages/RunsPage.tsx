import { useState } from "react";
import {
  Search,
  Filter,
  Download,
  Eye,
  CheckCircle2,
  XCircle,
  Clock,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  FileSpreadsheet,
  FileCode,
} from "lucide-react";
import { EvaluationRun } from "../types";
import { getExportCsvUrl, getExportJsonUrl } from "../api/client";
import { EmptyState } from "../components/EmptyState";

interface RunsPageProps {
  runs: EvaluationRun[];
  onSelectRun: (runId: string) => void;
  selectedRunDetails: EvaluationRun | null;
  onCloseDetails: () => void;
}

export function RunsPage({
  runs,
  onSelectRun,
  selectedRunDetails,
  onCloseDetails,
}: RunsPageProps) {
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [page, setPage] = useState<number>(0);
  const pageSize = 8;

  const filteredRuns = runs.filter((run) => {
    const matchesSearch =
      run.target_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      run.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === "all" || run.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const totalPages = Math.ceil(filteredRuns.length / pageSize) || 1;
  const paginatedRuns = filteredRuns.slice(page * pageSize, (page + 1) * pageSize);

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Evaluation Runs</h2>
          <p className="text-xs text-slate-400">
            Browse and inspect historical red-team evaluations, test execution traces, and exported reports.
          </p>
        </div>

        {/* Search & Filter */}
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by target or run ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
            >
              <option value="all">All Statuses</option>
              <option value="passed">Passed (Secure)</option>
              <option value="failed">Failed (Vulnerable)</option>
              <option value="running">Running</option>
              <option value="error">Error</option>
            </select>
          </div>
        </div>
      </div>

      {filteredRuns.length === 0 ? (
        <EmptyState
          title="No Matching Runs Found"
          description="No evaluation runs match your current search and filter criteria. Adjust your filters or trigger a new evaluation."
        />
      ) : (
        <>
          {/* Table */}
          <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900/40">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="px-4 py-3 font-semibold">Run ID / Target</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 font-semibold">Progress</th>
                  <th className="px-4 py-3 font-semibold">Results</th>
                  <th className="px-4 py-3 font-semibold">Findings</th>
                  <th className="px-4 py-3 font-semibold">Created</th>
                  <th className="px-4 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium">
                {paginatedRuns.map((run) => (
                  <tr key={run.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="px-4 py-3.5">
                      <div className="font-semibold text-slate-200">{run.target_name}</div>
                      <div className="font-mono text-[10px] text-slate-500">{run.id.slice(0, 8)}...</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
                          run.status === "passed"
                            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                            : run.status === "failed"
                            ? "bg-rose-500/10 border-rose-500/20 text-rose-400"
                            : "bg-amber-500/10 border-amber-500/20 text-amber-400"
                        }`}
                      >
                        {run.status === "passed" && <CheckCircle2 className="w-3 h-3" />}
                        {run.status === "failed" && <XCircle className="w-3 h-3" />}
                        {run.status === "running" && <Clock className="w-3 h-3 animate-spin" />}
                        {run.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 text-slate-300">
                      {run.completed_tests} / {run.total_tests}
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-400 font-semibold">{run.passed_tests} P</span>
                        <span className="text-slate-600">/</span>
                        <span className="text-rose-400 font-semibold">{run.failed_tests} F</span>
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      {run.findings_count > 0 ? (
                        <span className="text-rose-400 font-bold flex items-center gap-1">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          {run.findings_count}
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="px-4 py-3.5 text-slate-400 text-[11px]">
                      {new Date(run.created_at).toLocaleDateString()} {new Date(run.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectRun(run.id)}
                          className="p-1.5 text-slate-400 hover:text-sky-400 hover:bg-slate-800 rounded-lg transition"
                          title="Inspect Executions"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <a
                          href={getExportJsonUrl(run.id)}
                          download
                          className="p-1.5 text-slate-400 hover:text-sky-400 hover:bg-slate-800 rounded-lg transition"
                          title="Export JSON"
                        >
                          <FileCode className="w-4 h-4" />
                        </a>
                        <a
                          href={getExportCsvUrl(run.id)}
                          download
                          className="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded-lg transition"
                          title="Export CSV"
                        >
                          <FileSpreadsheet className="w-4 h-4" />
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between text-xs text-slate-400 px-1">
            <span>
              Showing {page * pageSize + 1} to {Math.min((page + 1) * pageSize, filteredRuns.length)} of{" "}
              {filteredRuns.length} runs
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg disabled:opacity-40 hover:bg-slate-800 transition"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="font-semibold text-slate-200">
                {page + 1} / {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg disabled:opacity-40 hover:bg-slate-800 transition"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </>
      )}

      {/* Run Detail Modal */}
      {selectedRunDetails && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
              <div>
                <h3 className="font-bold text-slate-100 text-sm">
                  Run Trace: {selectedRunDetails.target_name}
                </h3>
                <p className="font-mono text-[10px] text-slate-500">ID: {selectedRunDetails.id}</p>
              </div>
              <div className="flex items-center gap-3">
                <a
                  href={getExportJsonUrl(selectedRunDetails.id)}
                  download
                  className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  JSON
                </a>
                <button
                  onClick={onCloseDetails}
                  className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
                >
                  Close
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Executed Tests ({selectedRunDetails.executions?.length || 0})
              </div>

              <div className="space-y-2">
                {selectedRunDetails.executions?.map((exec) => (
                  <div
                    key={exec.id}
                    className="p-3.5 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold font-mono text-slate-200">{exec.test_case_id}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          exec.status === "passed"
                            ? "bg-emerald-500/10 text-emerald-400"
                            : "bg-rose-500/10 text-rose-400"
                        }`}
                      >
                        {exec.status.toUpperCase()} ({exec.defense_outcome})
                      </span>
                    </div>
                    {exec.target_output_sanitized && (
                      <div className="p-2.5 bg-slate-900 border border-slate-800/50 rounded-lg font-mono text-[11px] text-slate-400">
                        {exec.target_output_sanitized}
                      </div>
                    )}
                    <div className="flex items-center justify-between text-[11px] text-slate-500">
                      <span>Duration: {exec.duration_ms.toFixed(1)} ms</span>
                      <span>Canary Detected: {exec.canary_detected ? "YES" : "NO"}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
