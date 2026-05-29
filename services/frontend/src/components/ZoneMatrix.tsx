import type { FirewallPolicy } from "../lib/api";
import { Fragment } from "react";

type Props = {
  policies: FirewallPolicy[];
  selected?: { src: string; dst: string } | null;
  onSelect?: (pair: { src: string; dst: string }) => void;
  emptyMessage?: string;
};

function cellTone(action: string | null) {
  if (action === "ALLOW") return "bg-emerald-100 text-emerald-900 hover:bg-emerald-200";
  if (action === "BLOCK") return "bg-rose-100 text-rose-900 hover:bg-rose-200";
  if (action === "REJECT") return "bg-amber-100 text-amber-900 hover:bg-amber-200";
  return "bg-slate-100 text-slate-600 hover:bg-slate-200";
}

export function ZoneMatrix({ policies, selected, onSelect, emptyMessage }: Props) {
  const zones = Array.from(
    new Set(policies.flatMap((policy) => [policy.src_zone, policy.dst_zone]).filter(Boolean) as string[])
  ).sort();

  if (zones.length === 0) {
    return (
      <div className="rounded-md border border-slate-200 bg-white p-6 text-sm text-slate-600">
        {emptyMessage ?? "No zone policy data synced yet."}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-md border border-slate-200 bg-white">
      <div className="grid min-w-[680px]" style={{ gridTemplateColumns: `140px repeat(${zones.length}, minmax(92px, 1fr))` }}>
        <div className="border-b border-slate-200 bg-slate-50 p-3 text-xs font-semibold uppercase text-slate-500">Source</div>
        {zones.map((zone) => (
          <div key={zone} className="border-b border-l border-slate-200 bg-slate-50 p-3 text-xs font-semibold uppercase text-slate-500">
            {zone}
          </div>
        ))}
        {zones.map((src) => (
          <Fragment key={src}>
            <div key={`${src}-label`} className="border-b border-slate-200 p-3 text-sm font-semibold text-slate-800">
              {src}
            </div>
            {zones.map((dst) => {
              const matches = policies.filter((policy) => policy.src_zone === src && policy.dst_zone === dst);
              const action = matches[0]?.action ?? null;
              const isSelected = selected?.src === src && selected.dst === dst;
              return (
                <button
                  key={`${src}-${dst}`}
                  type="button"
                  className={`h-16 border-b border-l border-slate-200 p-2 text-left text-xs ${cellTone(action)} ${
                    isSelected ? "ring-2 ring-teal-700" : ""
                  }`}
                  onClick={() => onSelect?.({ src, dst })}
                >
                  <div className="font-semibold">{action ?? "None"}</div>
                  <div>{matches.length} policies</div>
                </button>
              );
            })}
          </Fragment>
        ))}
      </div>
    </div>
  );
}
