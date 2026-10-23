import {
  LayoutDashboard,
  PlaySquare,
  ShieldAlert,
  BarChart3,
  GitCompare,
  FolderGit2,
  Settings,
  Shield,
  Lock,
} from "lucide-react";

export type NavTab =
  | "overview"
  | "runs"
  | "findings"
  | "metrics"
  | "comparison"
  | "test-suites"
  | "configuration";

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  runsCount: number;
  findingsCount: number;
  safeMode: boolean;
}

export function Sidebar({
  currentTab,
  onSelectTab,
  runsCount,
  findingsCount,
  safeMode,
}: SidebarProps) {
  const navItems = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "runs", label: "Evaluation Runs", icon: PlaySquare, badge: runsCount > 0 ? runsCount : undefined },
    { id: "findings", label: "Findings Triage", icon: ShieldAlert, badge: findingsCount > 0 ? findingsCount : undefined, badgeColor: "bg-rose-500/20 text-rose-300 border-rose-500/30" },
    { id: "metrics", label: "Metrics & Trends", icon: BarChart3 },
    { id: "comparison", label: "Run Comparison", icon: GitCompare },
    { id: "test-suites", label: "Test Suites", icon: FolderGit2 },
    { id: "configuration", label: "Configuration", icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/40 flex flex-col shrink-0">
      {/* Brand */}
      <div className="p-6 border-b border-slate-800/80 flex items-center gap-3">
        <div className="p-2 bg-gradient-to-br from-sky-500/20 to-blue-600/20 border border-sky-500/30 rounded-xl text-sky-400 shadow-sm">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="font-bold text-slate-100 text-sm tracking-tight flex items-center gap-1.5">
            LLM Sentinel
          </div>
          <p className="text-[11px] text-slate-400 font-medium">Security Benchmarking</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id as NavTab)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                isActive
                  ? "bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? "text-sky-400" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    item.badgeColor || "bg-slate-800 text-slate-300 border-slate-700"
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Safe Mode Footer */}
      <div className="p-4 border-t border-slate-800/80">
        <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 font-medium flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-emerald-400" />
              Safe Mode
            </span>
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                safeMode
                  ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                  : "bg-amber-500/10 border-amber-500/20 text-amber-400"
              }`}
            >
              {safeMode ? "ACTIVE" : "OFF"}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 leading-tight">
            Restricted to local & mock targets. External attacks blocked.
          </p>
        </div>
      </div>
    </aside>
  );
}
