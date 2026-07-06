type Props = {
  severity: string | null | undefined;
};

export function SeverityBadge({ severity }: Props) {
  const value = (severity || "info").toLowerCase();
  const cls =
    value === "critical"
      ? "border-rose-200 bg-rose-100 text-rose-800 dark:border-rose-800 dark:bg-rose-900 dark:text-rose-200"
      : value === "high"
        ? "border-orange-200 bg-orange-100 text-orange-800 dark:border-orange-800 dark:bg-orange-900 dark:text-orange-200"
        : value === "medium"
          ? "border-yellow-200 bg-yellow-100 text-yellow-800 dark:border-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
          : value === "low"
            ? "border-sky-200 bg-sky-100 text-sky-800 dark:border-sky-800 dark:bg-sky-900 dark:text-sky-200"
            : "border-slate-200 bg-slate-100 text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300";
  return <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}>{value}</span>;
}
