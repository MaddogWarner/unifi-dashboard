import { useQuery } from "@tanstack/react-query";

import { Skeleton } from "../../components/Skeleton";
import type { FirewallLogSummary } from "../../lib/api";
import { getFirewallLogSummary } from "../../lib/api";
import type { LogFilters } from "./logFilters";
import { fromTimestamp } from "./logFilters";

type Props = {
  filters: LogFilters;
  onFilter: (patch: Partial<LogFilters>) => void;
};

function ListBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <h3 className="text-xs font-medium uppercase tracking-wide text-fg-muted">{title}</h3>
      <ul className="mt-2 space-y-1 text-sm">{children}</ul>
    </div>
  );
}

function Row({ label, count, onClick }: { label: string; count: number; onClick?: () => void }) {
  return (
    <li className="flex items-center justify-between gap-2">
      {onClick ? (
        <button
          type="button"
          onClick={onClick}
          className="min-w-0 truncate rounded text-left font-mono text-xs text-brand-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
        >
          {label}
        </button>
      ) : (
        <span className="min-w-0 truncate font-mono text-xs text-fg">{label}</span>
      )}
      <span className="shrink-0 tabular-nums text-fg-muted">{count}</span>
    </li>
  );
}

export function LogSummaryBody({ summary, onFilter }: { summary: FirewallLogSummary; onFilter: Props["onFilter"] }) {
  const empty = <li className="text-xs text-fg-muted">None</li>;
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
      <div>
        <p className="text-xs font-medium uppercase tracking-wide text-fg-muted">Events</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums text-fg">{summary.total}</p>
        <p className="text-sm text-fg-muted">{summary.blocked} blocked</p>
      </div>
      <ListBlock title="Top blocked sources">
        {summary.top_sources.length === 0
          ? empty
          : summary.top_sources.map((item) => (
              <Row key={item.ip} label={item.ip} count={item.count} onClick={() => onFilter({ src_ip: item.ip })} />
            ))}
      </ListBlock>
      <ListBlock title="Top targeted ports">
        {summary.top_ports.length === 0
          ? empty
          : summary.top_ports.map((item) => (
              <Row
                key={`${item.port}/${item.protocol}`}
                label={`${item.port}/${(item.protocol ?? "?").toLowerCase()}`}
                count={item.count}
              />
            ))}
      </ListBlock>
      <ListBlock title="Top rules">
        {summary.top_rules.length === 0
          ? empty
          : summary.top_rules.map((item) => (
              <Row
                key={item.rule_name}
                label={item.rule_name}
                count={item.count}
                onClick={() => onFilter({ rule_name: item.rule_name })}
              />
            ))}
      </ListBlock>
    </div>
  );
}

export function LogSummary({ filters, onFilter }: Props) {
  const { src_ip, dst_ip, rule_name, action, range } = filters;
  const summary = useQuery({
    queryKey: ["firewall-log-summary", src_ip, dst_ip, rule_name, action, range],
    queryFn: () => getFirewallLogSummary({ src_ip, dst_ip, rule_name, action, from_ts: fromTimestamp(range) }),
    refetchInterval: 60_000
  });

  if (summary.isLoading) {
    return (
      <div role="status" aria-label="Loading summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
      </div>
    );
  }
  if (summary.error || !summary.data) return null;
  return <LogSummaryBody summary={summary.data} onFilter={onFilter} />;
}
