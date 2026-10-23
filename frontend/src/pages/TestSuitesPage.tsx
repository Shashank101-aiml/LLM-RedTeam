import { useEffect, useState } from "react";
import { FolderGit2, Search, Filter, ShieldCheck, Eye, X } from "lucide-react";
import { TestCase, TestSuite } from "../types";
import { fetchTestCases, fetchTestSuites } from "../api/client";
import { LoadingState } from "../components/LoadingState";
import { ErrorBanner } from "../components/ErrorBanner";

export function TestSuitesPage() {
  const [suites, setSuites] = useState<TestSuite[]>([]);
  const [testCases, setTestCases] = useState<TestCase[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [selectedTestCase, setSelectedTestCase] = useState<TestCase | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [suitesData, casesData] = await Promise.all([
        fetchTestSuites(),
        fetchTestCases(),
      ]);
      setSuites(suitesData);
      setTestCases(casesData);
    } catch (err: any) {
      setError(err.message || "Failed to load test suite data");
    } finally {
      setLoading(false);
    }
  };

  const filteredCases = testCases.filter((tc) => {
    const matchesSearch =
      tc.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tc.test_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tc.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = categoryFilter === "all" || tc.category === categoryFilter;
    const matchesSeverity = severityFilter === "all" || tc.severity === severityFilter;
    return matchesSearch && matchesCategory && matchesSeverity;
  });

  if (loading) return <LoadingState message="Loading test suites and benchmark test cases..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadData} />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">Test Suite Management</h2>
        <p className="text-xs text-slate-400">
          Browse bundled benchmark suites, inspect expected secure behavior, and explore adversarial payloads.
        </p>
      </div>

      {/* Bundled Suites Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {suites.map((s) => (
          <div
            key={s.suite_id}
            className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2 hover:border-slate-700 transition"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] text-sky-400 font-bold uppercase">{s.version}</span>
              <FolderGit2 className="w-4 h-4 text-slate-500" />
            </div>
            <h3 className="font-bold text-slate-100 text-sm">{s.name}</h3>
            <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">{s.description}</p>
            <div className="flex flex-wrap gap-1.5 pt-2">
              {s.categories.slice(0, 3).map((cat) => (
                <span key={cat} className="text-[10px] font-semibold text-slate-400 px-2 py-0.5 bg-slate-800 rounded">
                  {cat.replace(/_/g, " ")}
                </span>
              ))}
              {s.categories.length > 3 && (
                <span className="text-[10px] text-slate-500 px-1 py-0.5">+{s.categories.length - 3} more</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Test Cases Table with Filters */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Active Test Corpus ({filteredCases.length})
          </h3>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search test cases..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-slate-500" />
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
              >
                <option value="all">All Categories</option>
                <option value="direct_prompt_injection">Direct Injection</option>
                <option value="indirect_prompt_injection">Indirect Injection</option>
                <option value="jailbreak">Jailbreak</option>
                <option value="system_prompt_leakage">Canary Leakage</option>
                <option value="unauthorized_tool_invocation">Tool Authorization</option>
                <option value="tenant_isolation">Tenant Isolation</option>
                <option value="benign_control">Benign Control</option>
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Informational</option>
              </select>
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900/40">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="px-4 py-3 font-semibold">Test ID</th>
                <th className="px-4 py-3 font-semibold">Name & Category</th>
                <th className="px-4 py-3 font-semibold">Severity</th>
                <th className="px-4 py-3 font-semibold">Type</th>
                <th className="px-4 py-3 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {filteredCases.map((tc) => (
                <tr key={tc.test_id} className="hover:bg-slate-800/20 transition-colors">
                  <td className="px-4 py-3 font-mono font-bold text-sky-400">{tc.test_id}</td>
                  <td className="px-4 py-3">
                    <div className="font-semibold text-slate-200">{tc.name}</div>
                    <div className="text-[11px] text-slate-500">{tc.category.replace(/_/g, " ")}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border border-slate-700 bg-slate-800 text-slate-300">
                      {tc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {tc.is_benign_control ? (
                      <span className="text-emerald-400 text-[11px] font-semibold">Benign Control</span>
                    ) : (
                      <span className="text-rose-400 text-[11px] font-semibold">Adversarial Attack</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => setSelectedTestCase(tc)}
                      className="p-1.5 text-slate-400 hover:text-sky-400 hover:bg-slate-800 rounded-lg transition"
                      title="Inspect Definition"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Test Case Inspection Modal */}
      {selectedTestCase && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
              <div>
                <span className="font-mono text-xs font-bold text-sky-400">{selectedTestCase.test_id}</span>
                <h3 className="font-bold text-slate-100 text-sm">{selectedTestCase.name}</h3>
              </div>
              <button
                onClick={() => setSelectedTestCase(null)}
                className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-y-auto text-xs">
              <div>
                <span className="text-slate-500 font-semibold block mb-1">Description</span>
                <p className="text-slate-300 leading-relaxed">{selectedTestCase.description}</p>
              </div>

              <div>
                <span className="text-slate-500 font-semibold block mb-1">Adversarial Input Prompt</span>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono text-[11px] whitespace-pre-wrap">
                  {selectedTestCase.input_prompt}
                </pre>
              </div>

              {selectedTestCase.retrieved_context && (
                <div>
                  <span className="text-slate-500 font-semibold block mb-1">Retrieved RAG Context</span>
                  <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-amber-200/90 font-mono text-[11px] whitespace-pre-wrap">
                    {selectedTestCase.retrieved_context}
                  </pre>
                </div>
              )}

              <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-2">
                <span className="font-bold text-slate-300 block text-[11px] uppercase tracking-wide">
                  Expected Outcome Security Rules
                </span>
                <div className="grid grid-cols-2 gap-3 text-[11px] text-slate-400">
                  <div>Must Block Action: {selectedTestCase.expected_outcome.must_block_action ? "YES" : "NO"}</div>
                  <div>Must Conceal Canaries: {selectedTestCase.expected_outcome.must_not_contain_canaries ? "YES" : "NO"}</div>
                  {selectedTestCase.expected_outcome.forbidden_substrings.length > 0 && (
                    <div className="col-span-2">
                      Forbidden Tokens:{" "}
                      <span className="font-mono text-rose-300">
                        {selectedTestCase.expected_outcome.forbidden_substrings.join(", ")}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
