import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { ActionBadge } from "../../components/ActionBadge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import type { FirewallPolicy, FirewallRule } from "../../lib/api";
import { getFirewallPolicies, getFirewallRules } from "../../lib/api";

type HitsSort = "asc" | "desc" | null;

const fieldClass =
  "mt-1 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";
const labelClass = "text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400";
const tableHeadClass = "bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400";

function normaliseAction(action: string) {
  const value = action.toLowerCase();
  if (value === "accept") return "allow";
  if (value === "drop" || value === "deny") return "block";
  return value;
}

function matchesAction(action: string, filter: string) {
  return filter === "" || normaliseAction(action) === filter;
}

function zoneLabel(zone: string | null) {
  return zone ?? "Any";
}

export function PoliciesTab() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") ?? "");
  const [action, setAction] = useState("");
  const [enabled, setEnabled] = useState("");
  const [hitsSort, setHitsSort] = useState<HitsSort>(null);
  const policies = useQuery({ queryKey: ["policies"], queryFn: getFirewallPolicies });
  const rules = useQuery({ queryKey: ["firewall-rules"], queryFn: getFirewallRules });
  const policyRows = policies.data ?? [];
  const ruleRows = rules.data ?? [];
  const src = searchParams.get("src") ?? "";
  const dst = searchParams.get("dst") ?? "";
  const hasPolicies = policyRows.length > 0;
  const hasRules = ruleRows.length > 0;

  useEffect(() => {
    setQuery(searchParams.get("q") ?? "");
  }, [searchParams]);

  function updateUrl(updates: Record<string, string>) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", "policies");
    Object.entries(updates).forEach(([key, value]) => {
      if (value) next.set(key, value);
      else next.delete(key);
    });
    setSearchParams(next, { replace: true });
  }

  function handleQueryChange(value: string) {
    setQuery(value);
    updateUrl({ q: value });
  }

  function clearFilters() {
    setQuery("");
    setAction("");
    setEnabled("");
    setHitsSort(null);
    setSearchParams({ tab: "policies" }, { replace: true });
  }

  const sourceZones = useMemo(
    () => Array.from(new Set(policyRows.map((policy) => policy.src_zone).filter(Boolean) as string[])).sort(),
    [policyRows]
  );
  const destinationZones = useMemo(
    () => Array.from(new Set(policyRows.map((policy) => policy.dst_zone).filter(Boolean) as string[])).sort(),
    [policyRows]
  );
  const filteredPolicies = useMemo(() => {
    const loweredQuery = query.trim().toLowerCase();
    const rows = policyRows.filter((policy) => {
      const matchesQuery = loweredQuery === "" || policy.name.toLowerCase().includes(loweredQuery);
      const matchesSrc = src === "" || policy.src_zone === src;
      const matchesDst = dst === "" || policy.dst_zone === dst;
      const matchesEnabled =
        enabled === "" || (enabled === "enabled" && policy.enabled) || (enabled === "disabled" && !policy.enabled);
      return matchesQuery && matchesAction(policy.action, action) && matchesSrc && matchesDst && matchesEnabled;
    });
    if (!hitsSort) return rows;
    return [...rows].sort((a, b) => (hitsSort === "desc" ? b.hit_count - a.hit_count : a.hit_count - b.hit_count));
  }, [action, dst, enabled, hitsSort, policyRows, query, src]);
  const filteredRules = useMemo(() => {
    const loweredQuery = query.trim().toLowerCase();
    return ruleRows.filter((rule) => {
      const matchesQuery = loweredQuery === "" || rule.name.toLowerCase().includes(loweredQuery);
      return matchesQuery && matchesAction(rule.action, action);
    });
  }, [action, query, ruleRows]);

  function toggleHitsSort() {
    setHitsSort((current) => (current === null ? "desc" : current === "desc" ? "asc" : null));
  }

  return (
    <Card title={hasPolicies ? "Zone Policies" : "Legacy Firewall Rules"}>
      {(policies.error || rules.error) && (
        <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-300">
          {policies.error ? `Policy sync view failed: ${policies.error.message}` : null}
          {rules.error ? ` Legacy rules view failed: ${rules.error.message}` : null}
        </div>
      )}
      {!hasPolicies && hasRules && (
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
          UniFi has not returned v2 zone policies, so this table is showing legacy firewall rules.
        </p>
      )}
      <div className="mt-4 grid gap-3 md:grid-cols-5">
        <label className={labelClass}>
          Search
          <input
            value={query}
            onChange={(event) => handleQueryChange(event.target.value)}
            className={fieldClass}
            placeholder="Policy name"
          />
        </label>
        <label className={labelClass}>
          Action
          <select
            value={action}
            onChange={(event) => setAction(event.target.value)}
            className={fieldClass}
          >
            <option value="">All</option>
            <option value="allow">Allow</option>
            <option value="block">Block</option>
            <option value="reject">Reject</option>
          </select>
        </label>
        {hasPolicies ? (
          <>
            <label className={labelClass}>
              Source zone
              <select
                value={src}
                onChange={(event) => updateUrl({ src: event.target.value })}
                className={fieldClass}
              >
                <option value="">All</option>
                {sourceZones.map((zone) => (
                  <option key={zone} value={zone}>{zone}</option>
                ))}
              </select>
            </label>
            <label className={labelClass}>
              Destination zone
              <select
                value={dst}
                onChange={(event) => updateUrl({ dst: event.target.value })}
                className={fieldClass}
              >
                <option value="">All</option>
                {destinationZones.map((zone) => (
                  <option key={zone} value={zone}>{zone}</option>
                ))}
              </select>
            </label>
          </>
        ) : null}
        {hasPolicies ? (
          <label className={labelClass}>
            Enabled
            <select
              value={enabled}
              onChange={(event) => setEnabled(event.target.value)}
              className={fieldClass}
            >
              <option value="">All</option>
              <option value="enabled">Enabled only</option>
              <option value="disabled">Disabled only</option>
            </select>
          </label>
        ) : null}
      </div>
      <Button
        type="button"
        onClick={clearFilters}
        className="mt-3"
      >
        × Clear filters
      </Button>
      <div className="mt-4 overflow-x-auto">
        {hasPolicies ? (
          <PolicyTable rows={filteredPolicies} total={policyRows.length} hitsSort={hitsSort} onToggleHits={toggleHitsSort} />
        ) : hasRules ? (
          <LegacyRuleTable rows={filteredRules} total={ruleRows.length} />
        ) : (
          <p className="text-sm text-slate-600 dark:text-slate-400">
            No firewall policies or legacy rules have been synced yet. Check API startup, UniFi API access, and poller logs.
          </p>
        )}
      </div>
    </Card>
  );
}

function PolicyTable({
  rows,
  total,
  hitsSort,
  onToggleHits
}: {
  rows: FirewallPolicy[];
  total: number;
  hitsSort: HitsSort;
  onToggleHits: () => void;
}) {
  return (
    <>
      <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
        Showing {rows.length} of {total} policies
      </p>
      <table className="min-w-full text-left text-sm">
        <thead className={tableHeadClass}>
          <tr>
            <th className="px-2 py-2">Name</th>
            <th className="px-2 py-2">Action</th>
            <th className="px-2 py-2">Source → Destination</th>
            <th className="px-2 py-2">Protocol</th>
            <th className="px-2 py-2">Schedule</th>
            <th className="px-2 py-2 text-right">
              <Button type="button" variant="quiet" onClick={onToggleHits} className="-my-1 px-1 py-1 font-semibold">
                Hits{hitsSort ? ` ${hitsSort === "desc" ? "↓" : "↑"}` : ""}
              </Button>
            </th>
            <th className="px-2 py-2">Enabled</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((policy) => (
            <tr
              key={policy.id}
              className={`border-t border-slate-100 dark:border-slate-800 ${policy.enabled ? "" : "opacity-60"}`}
            >
              <td className="px-2 py-2 font-medium">{policy.name}</td>
              <td className="px-2 py-2"><ActionBadge action={policy.action} /></td>
              <td className="px-2 py-2">{zoneLabel(policy.src_zone)} → {zoneLabel(policy.dst_zone)}</td>
              <td className="px-2 py-2">{policy.protocol ?? "Any"}</td>
              <td className="px-2 py-2">{policy.schedule ?? "Always"}</td>
              <td className="px-2 py-2 text-right">{policy.hit_count}</td>
              <td className={`px-2 py-2 ${policy.enabled ? "" : "text-slate-500"}`}>{policy.enabled ? "Yes" : "No"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function LegacyRuleTable({ rows, total }: { rows: FirewallRule[]; total: number }) {
  return (
    <>
      <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
        Showing {rows.length} of {total} rules
      </p>
      <table className="min-w-full text-left text-sm">
        <thead className={tableHeadClass}>
          <tr>
            <th className="px-2 py-2">Ruleset</th>
            <th className="px-2 py-2">Index</th>
            <th className="px-2 py-2">Name</th>
            <th className="px-2 py-2">Action</th>
            <th className="px-2 py-2">Source</th>
            <th className="px-2 py-2">Destination</th>
            <th className="px-2 py-2">Protocol</th>
            <th className="px-2 py-2">Port</th>
            <th className="px-2 py-2">Enabled</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((rule) => (
            <tr key={rule.id} className="border-t border-slate-100 dark:border-slate-800">
              <td className="px-2 py-2 font-mono text-xs">{rule.ruleset ?? "Unknown"}</td>
              <td className="px-2 py-2">{rule.rule_index ?? "-"}</td>
              <td className="px-2 py-2 font-medium">{rule.name}</td>
              <td className="px-2 py-2"><ActionBadge action={rule.action} /></td>
              <td className="px-2 py-2">{rule.src_address ?? "Any"}</td>
              <td className="px-2 py-2">{rule.dst_address ?? "Any"}</td>
              <td className="px-2 py-2">{rule.protocol ?? "Any"}</td>
              <td className="px-2 py-2">{rule.dst_port ?? "Any"}</td>
              <td className={`px-2 py-2 ${rule.enabled ? "" : "text-slate-500"}`}>{rule.enabled ? "Yes" : "No"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
