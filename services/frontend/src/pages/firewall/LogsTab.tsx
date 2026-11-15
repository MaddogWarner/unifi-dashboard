import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { ActionBadge } from "../../components/ActionBadge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { CopyButton } from "../../components/CopyButton";
import { Drawer } from "../../components/Drawer";
import { EmptyState } from "../../components/EmptyState";
import type { FirewallLog, FirewallLogParams } from "../../lib/api";
import { getFirewallLogs } from "../../lib/api";
import { formatTimestamp } from "../../lib/format";
import { FilterChips } from "./FilterChips";
import { IpCell } from "./IpCell";
import { LogSummary } from "./LogSummary";
import type { LogFilters } from "./logFilters";
import { activeFilters, fromTimestamp, useLogFilters } from "./logFilters";

const pageSize = 50;
const fieldClass =
  "mt-1 w-full rounded-md border border-line bg-surface px-3 py-2 text-sm text-fg focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500";
const labelClass = "text-xs font-medium uppercase tracking-wide text-fg-muted";

type Draft = Pick<LogFilters, "src_ip" | "dst_ip" | "rule_name" | "action" | "range">;

function toDraft(filters: LogFilters): Draft {
  const { src_ip, dst_ip, rule_name, action, range } = filters;
  return { src_ip, dst_ip, rule_name, action, range };
}

export function LogsTab() {
  const [, setSearchParams] = useSearchParams();
  const { filters, update, clear } = useLogFilters();
  const [draft, setDraft] = useState<Draft>(() => toDraft(filters));
  const [selected, setSelected] = useState<FirewallLog | null>(null);

  useEffect(() => setDraft(toDraft(filters)), [filters]);

  const params = useMemo<FirewallLogParams>(
    () => ({
      src_ip: filters.src_ip,
      dst_ip: filters.dst_ip,
      rule_name: filters.rule_name,
      action: filters.action,
      from_ts: fromTimestamp(filters.range),
      skip: (filters.page - 1) * pageSize,
      limit: pageSize
    }),
    [filters]
  );
  const logs = useQuery({
    queryKey: ["firewall-logs", filters],
    queryFn: () => getFirewallLogs(params),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData
  });
  const rows = logs.data ?? [];
  const active = activeFilters(filters);

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    update(draft);
  }

  function goToPolicySearch(log: FirewallLog) {
    if (log.rule_name) setSearchParams({ tab: "policies", q: log.rule_name });
  }

  const pivots = {
    onSource: (ip: string) => update({ src_ip: ip }),
    onDestination: (ip: string) => update({ dst_ip: ip })
  };

  return (
    <Card title="Firewall Logs">
      <div className="space-y-4">
        <LogSummary filters={filters} onFilter={update} />
        {logs.error && (
          <div className="rounded-md bg-danger-bg p-4 text-sm text-danger-fg">
            Firewall logs view failed: {logs.error.message}
          </div>
        )}
        <form className="grid gap-3 md:grid-cols-6" onSubmit={handleSubmit}>
          <label className={labelClass}>
            Source IP
            <input
              value={draft.src_ip}
              onChange={(event) => setDraft({ ...draft, src_ip: event.target.value })}
              className={fieldClass}
              placeholder="192.168.1.10"
            />
          </label>
          <label className={labelClass}>
            Destination IP
            <input
              value={draft.dst_ip}
              onChange={(event) => setDraft({ ...draft, dst_ip: event.target.value })}
              className={fieldClass}
              placeholder="192.168.1.1"
            />
          </label>
          <label className={labelClass}>
            Rule
            <input
              value={draft.rule_name}
              onChange={(event) => setDraft({ ...draft, rule_name: event.target.value })}
              className={fieldClass}
              placeholder="Rule name"
            />
          </label>
          <label className={labelClass}>
            Action
            <select
              value={draft.action}
              onChange={(event) => setDraft({ ...draft, action: event.target.value as LogFilters["action"] })}
              className={fieldClass}
            >
              <option value="">All</option>
              <option value="drop">Blocked</option>
              <option value="accept">Allowed</option>
              <option value="reject">Rejected</option>
            </select>
          </label>
          <label className={labelClass}>
            Time range
            <select
              value={draft.range}
              onChange={(event) => setDraft({ ...draft, range: event.target.value as LogFilters["range"] })}
              className={fieldClass}
            >
              <option value="1h">Last hour</option>
              <option value="24h">24 h</option>
              <option value="7d">7 days</option>
              <option value="all">All time</option>
            </select>
          </label>
          <div className="flex items-end">
            <Button type="submit" variant="primary" className="w-full">
              Apply
            </Button>
          </div>
        </form>
        <FilterChips active={active} onRemove={(key) => update({ [key]: key === "range" ? "24h" : "" })} onClear={clear} />

        {rows.length === 0 ? (
          active.length > 0 ? (
            <EmptyState title="No events match these filters" detail="Try widening the time range or clearing a filter." />
          ) : (
            <EmptyState
              title="No firewall events yet"
              detail="No firewall syslog events have been parsed yet. Confirm UDP 514 is published and allowed from the UniFi console."
            />
          )
        ) : (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-surface-muted text-xs uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="px-2 py-2">Time</th>
                    <th className="px-2 py-2">Rule</th>
                    <th className="px-2 py-2">Action</th>
                    <th className="px-2 py-2">Source</th>
                    <th className="px-2 py-2">Destination</th>
                    <th className="px-2 py-2">Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((log) => (
                    <tr
                      key={log.id}
                      tabIndex={0}
                      aria-label={`Open details for event at ${formatTimestamp(log.timestamp, true)}`}
                      className="cursor-pointer border-t border-line hover:bg-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-500"
                      onClick={() => setSelected(log)}
                      onKeyDown={(event) => {
                        if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) {
                          event.preventDefault();
                          setSelected(log);
                        }
                      }}
                    >
                      <td className="whitespace-nowrap px-2 py-2">{formatTimestamp(log.timestamp, true)}</td>
                      <td className="px-2 py-2">
                        <RuleCell log={log} onRuleClick={() => goToPolicySearch(log)} />
                      </td>
                      <td className="px-2 py-2">
                        <ActionBadge action={log.action} />
                      </td>
                      <td className="px-2 py-2">
                        <IpCell ip={log.src_ip} port={log.src_port} role="source" onFilter={pivots.onSource} />
                      </td>
                      <td className="px-2 py-2">
                        <IpCell ip={log.dst_ip} port={log.dst_port} role="destination" onFilter={pivots.onDestination} />
                      </td>
                      <td className="px-2 py-2">{log.protocol ?? "Unknown"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ul className="divide-y divide-line md:hidden">
              {rows.map((log) => (
                <li key={log.id} className="space-y-2 py-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-fg-muted">{formatTimestamp(log.timestamp, true)}</span>
                    <ActionBadge action={log.action} />
                  </div>
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <IpCell ip={log.src_ip} port={log.src_port} role="source" onFilter={pivots.onSource} />
                    <span aria-hidden className="text-fg-muted">→</span>
                    <IpCell ip={log.dst_ip} port={log.dst_port} role="destination" onFilter={pivots.onDestination} />
                  </div>
                  <div className="flex items-center justify-between gap-2 text-sm">
                    <RuleCell log={log} onRuleClick={() => goToPolicySearch(log)} />
                    <Button variant="quiet" className="px-2 py-1 text-xs" onClick={() => setSelected(log)}>
                      Details
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}

        <div className="flex items-center gap-3 text-sm">
          <Button
            type="button"
            onClick={() => update({ page: Math.max(1, filters.page - 1) })}
            disabled={filters.page === 1}
            className="min-h-11"
          >
            Prev
          </Button>
          <span className="text-fg-muted">Page {filters.page}</span>
          <Button
            type="button"
            onClick={() => update({ page: filters.page + 1 })}
            disabled={rows.length < pageSize}
            className="min-h-11"
          >
            Next
          </Button>
        </div>
      </div>

      <Drawer open={selected !== null} title="Firewall event" onClose={() => setSelected(null)}>
        {selected ? <LogDetail log={selected} /> : null}
      </Drawer>
    </Card>
  );
}

function RuleCell({ log, onRuleClick }: { log: FirewallLog; onRuleClick: () => void }) {
  if (!log.rule_name) return <span className="text-fg-muted">—</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {log.matched_policy_id ? (
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onRuleClick();
          }}
          className="rounded font-medium text-brand-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
        >
          {log.rule_name}
        </button>
      ) : (
        <span>
          {log.rule_name} <span className="text-fg-muted">· unmatched</span>
        </span>
      )}
      <CopyButton value={log.rule_name} label={`Copy rule name ${log.rule_name}`} />
    </span>
  );
}

function LogDetail({ log }: { log: FirewallLog }) {
  const fields: Array<[string, string]> = [
    ["Time", formatTimestamp(log.timestamp, true) ?? "Unknown"],
    ["Rule", log.rule_name ?? "None"],
    ["Action", log.action],
    ["Source", log.src_ip ? `${log.src_ip}${log.src_port ? `:${log.src_port}` : ""}` : "Unknown"],
    ["Destination", log.dst_ip ? `${log.dst_ip}${log.dst_port ? `:${log.dst_port}` : ""}` : "Unknown"],
    ["Protocol", log.protocol ?? "Unknown"],
    ["Interface", log.interface ?? "Unknown"],
    ["Direction", log.direction ?? "Unknown"],
    ["Matched policy ID", log.matched_policy_id ? String(log.matched_policy_id) : "None"]
  ];
  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
        {fields.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-fg-muted">{label}</dt>
            <dd className="break-all font-mono text-xs text-fg">{value}</dd>
          </div>
        ))}
      </dl>
      <div>
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-medium uppercase tracking-wide text-fg-muted">Raw line</h3>
          <CopyButton value={log.raw_line} label="Copy raw log line" />
        </div>
        <pre className="mt-2 whitespace-pre-wrap break-words rounded border border-line bg-surface-muted p-3 font-mono text-xs text-fg">
          {log.raw_line}
        </pre>
      </div>
    </div>
  );
}
