import type { FirewallPolicy } from "../lib/api";
import { Fragment } from "react";

type Props = {
  policies: FirewallPolicy[];
  selected?: { src: string; dst: string } | null;
  onSelect?: (pair: { src: string; dst: string }) => void;
  emptyMessage?: string;
};

type CellSummary = {
  label: string | null;
  total: number;
  breakdown: string | null;
};

function normaliseAction(action: string) {
  const value = action.toLowerCase();
  if (value === "accept") return "allow";
  if (value === "drop" || value === "deny") return "block";
  return value;
}

function summariseCell(matches: FirewallPolicy[]): CellSummary {
  const enabledCounts = matches
    .filter((policy) => policy.enabled)
    .reduce<Record<string, number>>((counts, policy) => {
      const action = normaliseAction(policy.action);
      counts[action] = (counts[action] ?? 0) + 1;
      return counts;
    }, {});
  const actions = Object.keys(enabledCounts);
  if (actions.length === 0) return { label: null, total: matches.length, breakdown: null };
  if (actions.length === 1) return { label: actions[0].toUpperCase(), total: matches.length, breakdown: null };
  const breakdown = actions
    .sort()
    .map((action) => `${enabledCounts[action]} ${action}`)
    .join(" · ");
  return { label: "MIXED", total: matches.length, breakdown };
}

function cellTone(label: string | null) {
  if (label === "ALLOW") return "bg-emerald-100 text-emerald-900 hover:bg-emerald-200 dark:bg-emerald-900 dark:text-emerald-100";
  if (label === "BLOCK") return "bg-rose-100 text-rose-900 hover:bg-rose-200 dark:bg-rose-900 dark:text-rose-100";
  if (label === "REJECT") return "bg-amber-100 text-amber-900 hover:bg-amber-200 dark:bg-amber-900 dark:text-amber-100";
  if (label === "MIXED") return "bg-violet-100 text-violet-900 hover:bg-violet-200 dark:bg-violet-900 dark:text-violet-100";
  return "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300";
}

export function ZoneMatrix({ policies, selected, onSelect, emptyMessage }: Props) {
  const zones = Array.from(
    new Set(policies.flatMap((policy) => [policy.src_zone, policy.dst_zone]).filter(Boolean) as string[])
  ).sort();

  if (zones.length === 0) {
    return (
      <div className="rounded-md border border-slate-200 bg-white p-6 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
        {emptyMessage ?? "No zone policy data synced yet."}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-md border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900">
      <div className="grid min-w-[680px]" style={{ gridTemplateColumns: `140px repeat(${zones.length}, minmax(92px, 1fr))` }}>
        <div className="border-b border-slate-200 bg-slate-50 p-3 text-xs font-semibold uppercase text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">Source</div>
        {zones.map((zone) => (
          <div key={zone} className="border-b border-l border-slate-200 bg-slate-50 p-3 text-xs font-semibold uppercase text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
            {zone}
          </div>
        ))}
        {zones.map((src) => (
          <Fragment key={src}>
            <div key={`${src}-label`} className="border-b border-slate-200 p-3 text-sm font-semibold text-slate-800 dark:border-slate-800 dark:text-slate-200">
              {src}
            </div>
            {zones.map((dst) => {
              const matches = policies.filter((policy) => policy.src_zone === src && policy.dst_zone === dst);
              const summary = summariseCell(matches);
              const isSelected = selected?.src === src && selected.dst === dst;
              return (
                <button
                  key={`${src}-${dst}`}
                  type="button"
                  className={`min-h-20 border-b border-l border-slate-200 p-2 text-left text-xs dark:border-slate-800 ${cellTone(summary.label)} ${
                    isSelected ? "ring-2 ring-teal-700" : ""
                  }`}
                  onClick={() => onSelect?.({ src, dst })}
                >
                  <div className="font-semibold">{summary.label ?? "None"}</div>
                  <div>{summary.total === 1 ? "1 policy" : `${summary.total} policies`}</div>
                  {summary.breakdown ? <div className="mt-1">{summary.breakdown}</div> : null}
                </button>
              );
            })}
          </Fragment>
        ))}
      </div>
    </div>
  );
}
