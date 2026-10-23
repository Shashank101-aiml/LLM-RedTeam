import { useState } from "react";
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Lock,
} from "lucide-react";
import { Finding, Severity } from "../types";
import { EmptyState } from "../components/EmptyState";

interface FindingsPageProps {
  findings: Finding[];
}

export function FindingsPage({ findings }: FindingsPageProps) {
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.test_case_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === "all" || f.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const toggleExpand = (id: string) => {
    setExpandedId((curr) => (curr === id ? null : id));
  };

  const severityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case "critical":
        return "bg-rose-500/20 text-rose-300 border-rose-500/30";
      case "high":
        return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "medium":
        return "bg-yellow-500/20 text-yellow-300 border-yellow-500/30";
      default:
        return "bg-slate-700/50 text-slate-300 border-slate-600";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Vulnerability Findings Triage</h2>
          <p className="text-xs text-slate-400">
            Confirmed security findings detected during adversarial evaluation. All secret tokens and canaries are redacted.
          </p>
        </div>

        {/* Search & Severity Filter */}
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings or test ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {filteredFindings.length === 0 ? (
        <EmptyState
          title={findings.length === 0 ? "Zero Vulnerabilities Detected" : "No Matching Findings"}
          description={
            findings.length === 0
              ? "All test cases held securely, or no vulnerable evaluation runs have been executed yet."
              : "No findings match the current severity or text filter."
          }
          icon={<CheckCircle2 className="w-8 h-8 text-emerald-400" />}
        />
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden transition-all"
              >
                {/* Header Row */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-800/30 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-100 text-xs">{finding.title}</span>
                        <span className="font-mono text-[10px] text-slate-500">[{finding.test_case_id}]</span>
                      </div>
                      <p className="text-[11px] text-slate-400 line-clamp-1">{finding.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ${severityBadgeClass(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-[10px] font-semibold text-slate-400 px-2 py-0.5 bg-slate-800 rounded">
                      {finding.category}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 space-y-4 text-xs">
                    {/* Sanitized Evidence */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <span className="font-semibold text-slate-400 flex items-center gap-1.5 text-[11px]">
                          <Lock className="w-3 h-3 text-sky-400" />
                          Redacted Adversarial Input
                        </span>
                        <pre className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-slate-300 font-mono text-[11px] whitespace-pre-wrap break-all">
                          {finding.attack_input_redacted}
                        </pre>
                      </div>

                      <div className="space-y-1.5">
                        <span className="font-semibold text-slate-400 flex items-center gap-1.5 text-[11px]">
                          <ShieldAlert className="w-3 h-3 text-rose-400" />
                          Observed Target Output (Redacted)
                        </span>
                        <pre className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-rose-200/90 font-mono text-[11px] whitespace-pre-wrap break-all">
                          {finding.target_output_redacted}
                        </pre>
                      </div>
                    </div>

                    {/* Boundary Violations Checklist */}
                    <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400 pt-1">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            finding.tool_violation_observed ? "bg-rose-500" : "bg-slate-700"
                          }`}
                        />
                        <span>Tool Boundary Breached: {finding.tool_violation_observed ? "YES" : "NO"}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            finding.canary_leaked ? "bg-rose-500" : "bg-slate-700"
                          }`}
                        />
                        <span>Canary Leaked: {finding.canary_leaked ? "YES" : "NO"}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            finding.tenant_isolation_breached ? "bg-rose-500" : "bg-slate-700"
                          }`}
                        />
                        <span>Tenant Isolation Breached: {finding.tenant_isolation_breached ? "YES" : "NO"}</span>
                      </div>
                    </div>

                    {/* Remediation Guidance */}
                    <div className="p-3 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-200 space-y-1">
                      <div className="font-bold text-[11px] uppercase tracking-wide text-sky-400">
                        Remediation Guidance
                      </div>
                      <p className="text-xs text-sky-100/90 leading-relaxed">{finding.remediation_guidance}</p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
