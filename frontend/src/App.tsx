import { useEffect, useState } from "react";
import { Shield, CheckCircle2, AlertTriangle, Activity, Lock, Database } from "lucide-react";
import { HealthStatus } from "./types";

export function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/health")
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        setHealth(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100 tracking-tight">LLM Sentinel</h1>
            <p className="text-xs text-slate-400">Red-Team Evaluation & Security Benchmarking</p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs font-medium">
          <div className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-full">
            <Lock className="w-3.5 h-3.5" />
            <span>Safe Mode Active</span>
          </div>
          <span className="text-slate-500">v0.1.0</span>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-400" />
              Engine Status & Platform Readiness
            </h2>
            {loading && <span className="text-xs text-slate-400 animate-pulse">Connecting...</span>}
          </div>

          {error && (
            <div className="p-4 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-lg text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Backend not running or unreachable ({error}). Start backend on port 8000.</span>
            </div>
          )}

          {health && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-4 bg-slate-950/50 border border-slate-800/80 rounded-lg">
                <div className="text-xs text-slate-400 mb-1">Core Health</div>
                <div className="text-lg font-semibold text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  {health.status.toUpperCase()}
                </div>
              </div>
              <div className="p-4 bg-slate-950/50 border border-slate-800/80 rounded-lg">
                <div className="text-xs text-slate-400 mb-1">Safe Mode Status</div>
                <div className="text-lg font-semibold text-sky-400">
                  {health.safe_mode ? "STRICT LOCAL" : "PERMISSIVE"}
                </div>
              </div>
              <div className="p-4 bg-slate-950/50 border border-slate-800/80 rounded-lg">
                <div className="text-xs text-slate-400 mb-1">Database Component</div>
                <div className="text-lg font-semibold text-slate-200 flex items-center gap-2">
                  <Database className="w-4 h-4 text-slate-400" />
                  {health.components.database || "Ready"}
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
