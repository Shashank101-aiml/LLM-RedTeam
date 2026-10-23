import { useEffect, useState } from "react";
import { Lock, Server, ShieldCheck, Check } from "lucide-react";
import { TargetConfiguration } from "../types";
import { fetchTargets } from "../api/client";
import { LoadingState } from "../components/LoadingState";
import { ErrorBanner } from "../components/ErrorBanner";

export function ConfigurationPage() {
  const [data, setData] = useState<{
    safe_mode: boolean;
    allowed_target_hosts: string[];
    available_adapters: TargetConfiguration[];
  } | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    setLoading(true);
    setError(null);
    try {
      const targetsData = await fetchTargets();
      setData(targetsData);
    } catch (err: any) {
      setError(err.message || "Failed to load targets configuration");
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <LoadingState message="Loading platform configuration..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadTargets} />;
  if (!data) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">Platform Configuration & Safety</h2>
        <p className="text-xs text-slate-400">
          Environment security guardrails, Safe-Mode host rules, and configured target adapters.
        </p>
      </div>

      {/* Safe Mode Policy Banner */}
      <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100 text-sm">Safe Mode Guardrails</h3>
              <p className="text-xs text-slate-400">
                Evaluation attacks are strictly prohibited against external endpoints by default.
              </p>
            </div>
          </div>
          <span
            className={`px-3 py-1 rounded-full text-xs font-bold border ${
              data.safe_mode
                ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                : "bg-amber-500/10 border-amber-500/20 text-amber-400"
            }`}
          >
            {data.safe_mode ? "STRICT LOCAL ACTIVE" : "PERMISSIVE MODE"}
          </span>
        </div>

        <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-2 text-xs">
          <span className="font-semibold text-slate-300 block text-[11px] uppercase tracking-wide">
            Allowed Target Hostnames
          </span>
          <div className="flex flex-wrap gap-2">
            {data.allowed_target_hosts.map((host) => (
              <span
                key={host}
                className="px-2.5 py-1 bg-slate-900 border border-slate-800 text-slate-300 rounded font-mono text-[11px]"
              >
                {host}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Target Adapters Grid */}
      <div className="space-y-3">
        <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <Server className="w-4 h-4 text-sky-400" />
          Configured Target Adapters ({data.available_adapters.length})
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {data.available_adapters.map((adapter) => (
            <div
              key={adapter.id}
              className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-500 font-bold uppercase">{adapter.type}</span>
                <span className="p-1 bg-emerald-500/10 text-emerald-400 rounded-full" title="Safe Mode Compatible">
                  <Check className="w-3.5 h-3.5" />
                </span>
              </div>
              <h4 className="font-bold text-slate-100 text-xs">{adapter.name}</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">{adapter.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Zero Secrets Guarantee */}
      <div className="p-5 bg-slate-900/30 border border-slate-800/80 rounded-xl flex items-center gap-3 text-xs text-slate-400">
        <ShieldCheck className="w-4 h-4 text-sky-400 shrink-0" />
        <span>
          <span className="font-bold text-slate-200">Zero Plaintext Secrets Guarantee:</span> Provider API keys and synthetic secrets are never persisted in plain text or rendered on the dashboard.
        </span>
      </div>
    </div>
  );
}
