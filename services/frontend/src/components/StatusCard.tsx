import type { LucideIcon } from "lucide-react";

type Props = {
  icon: LucideIcon;
  label: string;
  value: string | number;
  tone?: "neutral" | "good" | "warn" | "bad";
};

const tones = {
  neutral: "border-slate-200 bg-white text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200",
  good: "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
  warn: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200",
  bad: "border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-200"
};

const valueTones = {
  neutral: "text-slate-950 dark:text-slate-50",
  good: "text-emerald-950 dark:text-emerald-100",
  warn: "text-amber-950 dark:text-amber-100",
  bad: "text-rose-900 dark:text-rose-100"
};

export function StatusCard({ icon: Icon, label, value, tone = "neutral" }: Props) {
  return (
    <div className={`min-w-0 rounded-md border p-4 shadow-sm ${tones[tone]}`}>
      <div className="flex items-center gap-3">
        <Icon aria-hidden className="h-5 w-5 shrink-0" />
        <div className="min-w-0">
          <p className="break-words text-sm font-medium text-slate-600 dark:text-slate-400">{label}</p>
          <p className={`mt-1 break-words text-2xl font-semibold leading-tight ${valueTones[tone]}`}>{value}</p>
        </div>
      </div>
    </div>
  );
}
