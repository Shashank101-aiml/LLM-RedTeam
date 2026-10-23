import { Loader2 } from "lucide-react";

interface LoadingStateProps {
  message?: string;
}

export function LoadingState({ message = "Loading data from Sentinel Engine..." }: LoadingStateProps) {
  return (
    <div className="flex flex-col items-center justify-center p-12 space-y-3 bg-slate-900/40 border border-slate-800/80 rounded-xl">
      <Loader2 className="w-7 h-7 text-sky-400 animate-spin" />
      <p className="text-sm text-slate-400 animate-pulse font-medium">{message}</p>
    </div>
  );
}
