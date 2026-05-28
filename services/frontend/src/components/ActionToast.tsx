import { ReactNode, createContext, useCallback, useContext, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { CheckCircle2, X } from "lucide-react";

type ActionToastContextValue = {
  showSuccess: (message: string) => void;
  clearToast: () => void;
};

const ActionToastContext = createContext<ActionToastContextValue | null>(null);

export function ActionToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<{ id: number; message: string } | null>(null);

  const clearToast = useCallback(() => setToast(null), []);
  const showSuccess = useCallback((message: string) => {
    setToast({ id: Date.now(), message });
  }, []);

  return (
    <ActionToastContext.Provider value={{ showSuccess, clearToast }}>
      {children}
      <ActionToast toast={toast} onDismiss={clearToast} />
    </ActionToastContext.Provider>
  );
}

export function useActionToast() {
  const context = useContext(ActionToastContext);
  if (!context) throw new Error("useActionToast must be used within ActionToastProvider");
  return context;
}

type ActionToastProps = {
  toast: { id: number; message: string } | null;
  onDismiss: () => void;
};

function ActionToast({ toast, onDismiss }: ActionToastProps) {
  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(onDismiss, 3000);
    return () => window.clearTimeout(timeout);
  }, [toast, onDismiss]);

  if (!toast) return null;

  return createPortal(
    <div className="pointer-events-none fixed right-4 top-4 z-[100] flex max-w-sm justify-end" aria-live="polite">
      <div className="pointer-events-auto flex items-start gap-3 rounded-md border border-emerald-200 bg-white px-4 py-3 text-sm text-slate-800 shadow-lg">
        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-700" />
        <span className="font-medium">{toast.message}</span>
        <button
          type="button"
          className="ml-2 rounded p-0.5 text-slate-500 hover:bg-slate-100 hover:text-slate-700"
          onClick={onDismiss}
          aria-label="Dismiss notification"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>,
    document.body
  );
}
