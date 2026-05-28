import { useEffect } from "react";
import { CheckCircle2, X } from "lucide-react";

type ActionToastProps = {
  message: string | null;
  onDismiss: () => void;
};

export function ActionToast({ message, onDismiss }: ActionToastProps) {
  useEffect(() => {
    if (!message) return;
    const timeout = window.setTimeout(onDismiss, 3000);
    return () => window.clearTimeout(timeout);
  }, [message, onDismiss]);

  if (!message) return null;

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex max-w-sm justify-end" aria-live="polite">
      <div className="pointer-events-auto flex items-start gap-3 rounded-md border border-emerald-200 bg-white px-4 py-3 text-sm text-slate-800 shadow-lg">
        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-700" />
        <span className="font-medium">{message}</span>
        <button
          type="button"
          className="ml-2 rounded p-0.5 text-slate-500 hover:bg-slate-100 hover:text-slate-700"
          onClick={onDismiss}
          aria-label="Dismiss notification"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
