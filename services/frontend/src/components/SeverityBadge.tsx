type Props = {
  severity: string | null | undefined;
};

export function SeverityBadge({ severity }: Props) {
  const value = (severity || "info").toLowerCase();
  const cls =
    value === "critical"
      ? "bg-rose-100 text-rose-800 dark:bg-rose-900 dark:text-rose-200"
      : value === "high"
        ? "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
        : value === "medium"
          ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
          : value === "low"
            ? "bg-sky-100 text-sky-800 dark:bg-sky-900 dark:text-sky-200"
            : "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300";
  return <span className={`rounded px-2 py-1 text-xs font-semibold ${cls}`}>{value}</span>;
}
