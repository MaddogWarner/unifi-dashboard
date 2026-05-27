import type { LucideIcon } from "lucide-react";

type Props = {
  icon: LucideIcon;
  label: string;
  value: string | number;
  tone?: "neutral" | "good" | "warn" | "bad";
};

const tones = {
  neutral: "border-slate-200 bg-white text-slate-800",
  good: "border-emerald-200 bg-emerald-50 text-emerald-900",
  warn: "border-amber-200 bg-amber-50 text-amber-900",
  bad: "border-rose-200 bg-rose-50 text-rose-900"
};

const valueTones = {
  neutral: "text-slate-950",
  good: "text-emerald-950",
  warn: "text-amber-950",
  bad: "text-rose-900"
};

export function StatusCard({ icon: Icon, label, value, tone = "neutral" }: Props) {
  return (
    <div className={`rounded-md border p-4 shadow-sm ${tones[tone]}`}>
      <div className="flex items-center gap-3">
        <Icon aria-hidden className="h-5 w-5 shrink-0" />
        <div className="min-w-0">
          <p className="text-sm font-medium text-slate-600">{label}</p>
          <p className={`mt-1 text-2xl font-semibold ${valueTones[tone]}`}>{value}</p>
        </div>
      </div>
    </div>
  );
}
