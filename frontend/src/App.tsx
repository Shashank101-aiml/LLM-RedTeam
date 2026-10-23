import { useEffect, useState } from "react";
import { Sidebar, NavTab } from "./components/Sidebar";
import { OverviewPage } from "./pages/OverviewPage";
import { RunsPage } from "./pages/RunsPage";
import { FindingsPage } from "./pages/FindingsPage";
import { MetricsPage } from "./pages/MetricsPage";
import { ComparisonPage } from "./pages/ComparisonPage";
import { TestSuitesPage } from "./pages/TestSuitesPage";
import { ConfigurationPage } from "./pages/ConfigurationPage";
import { EvaluationRun, Finding, HealthStatus } from "./types";
import { createRun, fetchHealth, fetchRun, fetchRuns } from "./api/client";
import { LoadingState } from "./components/LoadingState";
import { ErrorBanner } from "./components/ErrorBanner";

export function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>("overview");
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [runs, setRuns] = useState<EvaluationRun[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedRunDetails, setSelectedRunDetails] = useState<EvaluationRun | null>(null);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [healthData, runsData] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchRuns(0, 50).catch(() => []),
      ]);
      setHealth(healthData);
      setRuns(runsData);
    } catch (err: any) {
      setError(err.message || "Failed to connect to backend engine");
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerRun = async (targetMode: string) => {
    try {
      await createRun({
        target_name: targetMode,
        notes: `Executed via LLM Sentinel Dashboard`,
      });
      // Refresh runs list to include newly created run
      const updatedRuns = await fetchRuns(0, 50);
      setRuns(updatedRuns);
    } catch (err: any) {
      alert(`Error launching run: ${err.message}`);
    }
  };

  const handleSelectRun = async (runId: string) => {
    try {
      const runDetails = await fetchRun(runId);
      setSelectedRunDetails(runDetails);
    } catch (err: any) {
      alert(`Failed to load run details: ${err.message}`);
    }
  };

  // Compile all unique findings across all runs for the Findings Triage tab
  const allFindings: Finding[] = runs.flatMap((r) => r.findings || []);

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans antialiased">
      {/* Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        runsCount={runs.length}
        findingsCount={allFindings.length}
        safeMode={health?.safe_mode ?? true}
      />

      {/* Main Panel */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Bar */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/30 px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-400">
            <span>Sentinel</span>
            <span>/</span>
            <span className="text-slate-200 capitalize">{currentTab.replace(/-/g, " ")}</span>
          </div>

          <div className="flex items-center gap-4 text-xs font-medium">
            {health && (
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-full text-[11px] font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span>Engine Ready</span>
              </div>
            )}
            <span className="text-slate-500 text-[11px]">v0.1.0</span>
          </div>
        </header>

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-8 max-w-7xl w-full mx-auto">
          {error && <ErrorBanner message={error} onRetry={loadInitialData} />}

          {loading ? (
            <LoadingState message="Connecting to Sentinel security engine..." />
          ) : (
            <>
              {currentTab === "overview" && (
                <OverviewPage
                  runs={runs}
                  onTriggerRun={handleTriggerRun}
                  onNavigateToRuns={() => setCurrentTab("runs")}
                  onNavigateToFindings={() => setCurrentTab("findings")}
                />
              )}

              {currentTab === "runs" && (
                <RunsPage
                  runs={runs}
                  onSelectRun={handleSelectRun}
                  selectedRunDetails={selectedRunDetails}
                  onCloseDetails={() => setSelectedRunDetails(null)}
                />
              )}

              {currentTab === "findings" && <FindingsPage findings={allFindings} />}

              {currentTab === "metrics" && <MetricsPage runs={runs} />}

              {currentTab === "comparison" && <ComparisonPage runs={runs} />}

              {currentTab === "test-suites" && <TestSuitesPage />}

              {currentTab === "configuration" && <ConfigurationPage />}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
