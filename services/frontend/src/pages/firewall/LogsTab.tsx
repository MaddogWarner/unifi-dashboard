import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { ActionBadge } from "../../components/ActionBadge";
import type { FirewallLog, FirewallLogParams } from "../../lib/api";
import { getFirewallLogs } from "../../lib/api";

const pageSize = 50;

type DraftFilters = {
  src_ip: string;
  dst_ip: string;
  rule_name: string;
  action: string;
  range: string;
};

function formatTimestamp(value: string) {
  return new Date(value).toLocaleString("en-AU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });
}

function fromTimestamp(range: string) {
  const now = Date.now();
  if (range === "1h") return new Date(now - 60 * 60 * 1000).toISOString();
  if (range === "24h") return new Date(now - 24 * 60 * 60 * 1000).toISOString();
  if (range === "7d") return new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
  return undefined;
}

function endpoint(log: FirewallLog, field: "src" | "dst") {
  const ip = field === "src" ? log.src_ip : log.dst_ip;
  const port = field === "src" ? log.src_port : log.dst_port;
  if (!ip) return "Unknown";
  return port ? `${ip}:${port}` : ip;
}

export function LogsTab() {
  const [, setSearchParams] = useSearchParams();
  const [draft, setDraft] = useState<DraftFilters>({
    src_ip: "",
    dst_ip: "",
    rule_name: "",
    action: "",
    range: "24h"
  });
  const [filters, setFilters] = useState<DraftFilters>(draft);
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const params = useMemo<FirewallLogParams>(() => {
    const from_ts = fromTimestamp(filters.range);
    return {
      src_ip: filters.src_ip,
      dst_ip: filters.dst_ip,
      rule_name: filters.rule_name,
      action: filters.action,
      from_ts,
      skip: page * pageSize,
      limit: pageSize
    };
  }, [filters, page]);
  const logs = useQuery({
    queryKey: ["firewall-logs", filters, page],
    queryFn: () => getFirewallLogs(params),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData
  });
  const rows = logs.data ?? [];

  function updateDraft(key: keyof DraftFilters, value: string) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function applyFilters() {
    setFilters(draft);
    setPage(0);
    setExpanded(null);
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    applyFilters();
  }

  function goToPolicySearch(log: FirewallLog) {
    if (log.rule_name) setSearchParams({ tab: "policies", q: log.rule_name });
  }

  return (
    <section className="rounded-md border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
      <h2 className="text-lg font-semibold text-slate-950 dark:text-slate-50">Firewall Logs</h2>
      {logs.error && (
        <div className="mt-4 rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-300">
          Firewall logs view failed: {logs.error.message}
        </div>
      )}
      <form className="mt-4 grid gap-3 md:grid-cols-6" onSubmit={handleSubmit}>
        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Source IP
          <input
            value={draft.src_ip}
            onChange={(event) => updateDraft("src_ip", event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
            placeholder="192.168.1.10"
          />
        </label>
        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Destination IP
          <input
            value={draft.dst_ip}
            onChange={(event) => updateDraft("dst_ip", event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
            placeholder="192.168.1.1"
          />
        </label>
        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Rule
          <input
            value={draft.rule_name}
            onChange={(event) => updateDraft("rule_name", event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
            placeholder="Rule name"
          />
        </label>
        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Action
          <select
            value={draft.action}
            onChange={(event) => updateDraft("action", event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
          >
            <option value="">All</option>
            <option value="drop">Blocked</option>
            <option value="accept">Allowed</option>
            <option value="reject">Rejected</option>
          </select>
        </label>
        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Time range
          <select
            value={draft.range}
            onChange={(event) => updateDraft("range", event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
          >
            <option value="1h">Last hour</option>
            <option value="24h">24 h</option>
            <option value="7d">7 days</option>
            <option value="all">All time</option>
          </select>
        </label>
        <div className="flex items-end">
          <button
            type="submit"
            className="w-full rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-700 dark:hover:bg-slate-600"
          >
            Apply
          </button>
        </div>
      </form>
      <div className="mt-4 overflow-x-auto">
        {rows.length > 0 ? (
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
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
                <LogRow
                  key={log.id}
                  log={log}
                  expanded={expanded === log.id}
                  onToggle={() => setExpanded((current) => (current === log.id ? null : log.id))}
                  onRuleClick={() => goToPolicySearch(log)}
                />
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-slate-600 dark:text-slate-400">
            No firewall syslog events have been parsed yet. Confirm UDP 514 is published and allowed from the UniFi console.
          </p>
        )}
      </div>
      <div className="mt-4 flex items-center gap-3 text-sm">
        <button
          type="button"
          onClick={() => setPage((current) => Math.max(0, current - 1))}
          disabled={page === 0}
          className="rounded border border-slate-300 px-3 py-2 font-medium disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-700"
        >
          Prev
        </button>
        <span className="text-slate-600 dark:text-slate-400">Page {page + 1}</span>
        <button
          type="button"
          onClick={() => setPage((current) => current + 1)}
          disabled={rows.length < pageSize}
          className="rounded border border-slate-300 px-3 py-2 font-medium disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-700"
        >
          Next
        </button>
      </div>
    </section>
  );
}

function LogRow({
  log,
  expanded,
  onToggle,
  onRuleClick
}: {
  log: FirewallLog;
  expanded: boolean;
  onToggle: () => void;
  onRuleClick: () => void;
}) {
  return (
    <>
      <tr
        className="cursor-pointer border-t border-slate-100 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800"
        onClick={onToggle}
      >
        <td className="whitespace-nowrap px-2 py-2">{formatTimestamp(log.timestamp)}</td>
        <td className="px-2 py-2">
          {log.matched_policy_id && log.rule_name ? (
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onRuleClick();
              }}
              className="font-medium text-teal-700 hover:underline dark:text-teal-300"
            >
              {log.rule_name}
            </button>
          ) : log.rule_name ? (
            <span>
              {log.rule_name} <span className="text-slate-500">· unmatched</span>
            </span>
          ) : (
            <span className="text-slate-500">—</span>
          )}
        </td>
        <td className="px-2 py-2"><ActionBadge action={log.action} /></td>
        <td className="px-2 py-2 font-mono text-xs">{endpoint(log, "src")}</td>
        <td className="px-2 py-2 font-mono text-xs">{endpoint(log, "dst")}</td>
        <td className="px-2 py-2">{log.protocol ?? "Unknown"}</td>
      </tr>
      {expanded ? (
        <tr className="border-t border-slate-100 bg-slate-50 dark:border-slate-800 dark:bg-slate-950">
          <td colSpan={6} className="p-3">
            <div className="grid gap-2 text-xs text-slate-600 dark:text-slate-400 md:grid-cols-3">
              <span>Interface: {log.interface ?? "Unknown"}</span>
              <span>Direction: {log.direction ?? "Unknown"}</span>
              <span>Matched policy ID: {log.matched_policy_id ?? "None"}</span>
            </div>
            <pre className="mt-2 whitespace-pre-wrap break-words rounded border border-slate-200 bg-white p-3 font-mono text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200">
              {log.raw_line}
            </pre>
          </td>
        </tr>
      ) : null}
    </>
  );
}
