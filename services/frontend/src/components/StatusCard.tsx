import type { LucideIcon } from "lucide-react";

type Props = {
  icon: LucideIcon;
  label: string;
  value: string | number;
  tone?: "neutral" | "good" | "warn" | "bad";
  hint?: string;
};

const tones = {
  neutral: "bg-hover text-fg-muted",
  good: "bg-success-bg text-success-fg",
  warn: "bg-warning-bg text-warning-fg",
  bad: "bg-danger-bg text-danger-fg"
};

export function StatusCard({ icon: Icon, label, value, tone = "neutral", hint }: Props) {
  return (
    <div className="min-w-0 rounded-lg border border-line bg-surface p-4 shadow-sm">
      <div className="flex items-center gap-3">
        <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-md ${tones[tone]}`}>
          <Icon aria-hidden className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium text-fg-muted">{label}</p>
          <p title={hint} className="mt-1 break-normal text-lg font-semibold leading-tight sm:text-xl text-fg tabular-nums md:text-2xl">{value}</p>
        </div>
      </div>
    </div>
  );
}
