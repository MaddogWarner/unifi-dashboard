type Props = {
  action: string | null;
};

function actionTone(action: string | null) {
  const normalised = action?.toLowerCase();
  if (normalised === "allow" || normalised === "accept") {
    return "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-200";
  }
  if (normalised === "block" || normalised === "drop" || normalised === "deny") {
    return "border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-200";
  }
  if (normalised === "reject") {
    return "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200";
  }
  return "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300";
}

export function ActionBadge({ action }: Props) {
  return (
    <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold uppercase ${actionTone(action)}`}>
      {action ?? "Unknown"}
    </span>
  );
}
