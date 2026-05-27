type Props = {
  severity: string | null | undefined;
};

export function SeverityBadge({ severity }: Props) {
  const value = (severity || "info").toLowerCase();
  const cls =
    value === "critical"
      ? "bg-rose-100 text-rose-800"
      : value === "high"
        ? "bg-orange-100 text-orange-800"
        : value === "medium"
          ? "bg-yellow-100 text-yellow-800"
          : value === "low"
            ? "bg-sky-100 text-sky-800"
            : "bg-slate-100 text-slate-700";
  return <span className={`rounded px-2 py-1 text-xs font-semibold ${cls}`}>{value}</span>;
}
