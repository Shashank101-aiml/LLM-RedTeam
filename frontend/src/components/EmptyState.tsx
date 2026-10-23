import React from "react";
import { Inbox } from "lucide-react";

interface EmptyStateProps {
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export function EmptyState({
  title,
  description,
  actionText,
  onAction,
  icon,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-4">
      <div className="p-3 bg-slate-800/60 rounded-xl text-slate-400">
        {icon || <Inbox className="w-8 h-8" />}
      </div>
      <div className="max-w-md space-y-1">
        <h3 className="text-base font-semibold text-slate-200">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed">{description}</p>
      </div>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-all shadow-md shadow-sky-500/10"
        >
          {actionText}
        </button>
      )}
    </div>
  );
}
