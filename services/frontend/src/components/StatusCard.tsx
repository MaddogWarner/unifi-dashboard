import type { LucideIcon } from "lucide-react";

type Props = {
  icon: LucideIcon;
  label: string;
  value: string | number;
  tone?: "neutral" | "good" | "warn" | "bad";
};

const tones = {
  neutral: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  good: "bg-emerald-50 text-emerald-600 dark:bg-emerald-950 dark:text-emerald-300",
  warn: "bg-amber-50 text-amber-600 dark:bg-amber-950 dark:text-amber-300",
  bad: "bg-rose-50 text-rose-600 dark:bg-rose-950 dark:text-rose-300"
};

export function StatusCard({ icon: Icon, label, value, tone = "neutral" }: Props) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center gap-3">
        <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-md ${tones[tone]}`}>
          <Icon aria-hidden className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium text-slate-600 dark:text-slate-400">{label}</p>
          <p className="mt-1 break-normal text-xl font-semibold leading-tight text-slate-950 tabular-nums dark:text-slate-50 md:text-2xl">{value}</p>
        </div>
      </div>
    </div>
  );
}
