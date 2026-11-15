import { X } from "lucide-react";

import type { LogFilters } from "./logFilters";

const labels: Record<string, string> = {
  src_ip: "Source",
  dst_ip: "Destination",
  rule_name: "Rule",
  action: "Action",
  range: "Range"
};

type Props = {
  active: Array<{ key: keyof LogFilters; value: string }>;
  onRemove: (key: keyof LogFilters) => void;
  onClear: () => void;
};

export function FilterChips({ active, onRemove, onClear }: Props) {
  if (active.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2" aria-label="Active filters">
      {active.map(({ key, value }) => (
        <span key={key} className="inline-flex items-center gap-1 rounded-full bg-brand-soft px-2.5 py-1 text-xs text-brand-ink">
          {labels[key]}: <span className="font-mono">{value}</span>
          <button
            type="button"
            onClick={() => onRemove(key)}
            aria-label={`Remove filter ${key} ${value}`}
            className="rounded-full p-0.5 hover:bg-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
          >
            <X aria-hidden className="h-3 w-3" />
          </button>
        </span>
      ))}
      <button
        type="button"
        onClick={onClear}
        className="text-xs text-fg-muted underline hover:text-fg focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
      >
        Clear all
      </button>
    </div>
  );
}
