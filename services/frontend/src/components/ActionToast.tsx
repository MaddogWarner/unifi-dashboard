import { ReactNode, useCallback, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { CheckCircle2, CircleAlert, X } from "lucide-react";

type ToastTone = "success" | "error";

type ToastEventDetail = {
  message: string;
  tone: ToastTone;
};

type ToastState = ToastEventDetail & {
  id: number;
};

const TOAST_EVENT = "unifi-dashboard:toast";
const CLEAR_TOAST_EVENT = "unifi-dashboard:clear-toast";

export function showSuccessToast(message: string) {
  dispatchToast({ message, tone: "success" });
}

export function showErrorToast(message: string) {
  dispatchToast({ message, tone: "error" });
}

export function clearActionToast() {
  window.dispatchEvent(new CustomEvent(CLEAR_TOAST_EVENT));
}

function dispatchToast(detail: ToastEventDetail) {
  window.dispatchEvent(new CustomEvent<ToastEventDetail>(TOAST_EVENT, { detail }));
}

export function ActionToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastState | null>(null);
  const clearToast = useCallback(() => setToast(null), []);

  useEffect(() => {
    const show = (event: Event) => {
      const detail = (event as CustomEvent<ToastEventDetail>).detail;
      setToast({ ...detail, id: Date.now() });
    };
    window.addEventListener(TOAST_EVENT, show);
    window.addEventListener(CLEAR_TOAST_EVENT, clearToast);
    return () => {
      window.removeEventListener(TOAST_EVENT, show);
      window.removeEventListener(CLEAR_TOAST_EVENT, clearToast);
    };
  }, [clearToast]);

  return (
    <>
      {children}
      <ActionToast toast={toast} onDismiss={clearToast} />
    </>
  );
}

type ActionToastProps = {
  toast: ToastState | null;
  onDismiss: () => void;
};

function ActionToast({ toast, onDismiss }: ActionToastProps) {
  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(onDismiss, 3000);
    return () => window.clearTimeout(timeout);
  }, [toast, onDismiss]);

  if (!toast) return null;

  const isSuccess = toast.tone === "success";
  const Icon = isSuccess ? CheckCircle2 : CircleAlert;
  const toneClass = isSuccess
    ? "border-emerald-200 text-slate-800 dark:border-emerald-800 dark:text-slate-200"
    : "border-rose-200 text-slate-800 dark:border-rose-800 dark:text-slate-200";
  const iconClass = isSuccess ? "text-emerald-700" : "text-rose-700";

  return createPortal(
    <div
      aria-live="polite"
      className="pointer-events-none fixed right-4 top-4 z-[1000] flex max-w-sm justify-end"
      data-testid="action-toast"
      data-tone={toast.tone}
    >
      <div
        className={`pointer-events-auto flex items-start gap-3 rounded-lg border bg-white px-4 py-3 text-sm shadow-lg dark:bg-slate-900 ${toneClass}`}
      >
        <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${iconClass}`} />
        <span className="font-medium">{toast.message}</span>
        <button
          type="button"
          className="ml-2 rounded p-0.5 text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-300"
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
