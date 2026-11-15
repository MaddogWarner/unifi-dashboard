import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";

type Props = {
  value: string;
  label: string;
};

export function CopyButton({ value, label }: Props) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => setState("idle"), 1500);
    return () => window.clearTimeout(timer);
  }, [state]);

  async function copy(event: React.MouseEvent) {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={copy}
        aria-label={label}
        className="rounded p-1 text-fg-muted hover:bg-hover hover:text-fg focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
      >
        {state === "copied" ? <Check aria-hidden className="h-3.5 w-3.5" /> : <Copy aria-hidden className="h-3.5 w-3.5" />}
      </button>
      <span role="status" className={state === "idle" ? "sr-only" : "text-xs text-fg-muted"}>
        {state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : ""}
      </span>
    </>
  );
}
