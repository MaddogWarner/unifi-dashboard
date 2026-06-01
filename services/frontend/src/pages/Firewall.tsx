import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ZoneMatrix } from "../components/ZoneMatrix";
import { getFirewallLogs, getFirewallPolicies, getFirewallRules } from "../lib/api";

export function Firewall() {
  const [selected, setSelected] = useState<{ src: string; dst: string } | null>(null);
  const policies = useQuery({ queryKey: ["policies"], queryFn: getFirewallPolicies });
  const rules = useQuery({ queryKey: ["firewall-rules"], queryFn: getFirewallRules });
  const logs = useQuery({ queryKey: ["firewall-logs"], queryFn: () => getFirewallLogs("?limit=50") });
  const policyRows = policies.data ?? [];
  const ruleRows = rules.data ?? [];
  const logRows = logs.data ?? [];
  const hasPolicies = policyRows.length > 0;
  const hasRules = ruleRows.length > 0;
  const filtered = useMemo(
    () =>
      selected
        ? policyRows.filter((policy) => policy.src_zone === selected.src && policy.dst_zone === selected.dst)
        : policyRows,
    [policyRows, selected]
  );
  const matrixEmptyMessage = hasRules
    ? "No v2 zone policy data synced yet. Legacy firewall rules are available below."
    : "No firewall policy or legacy rule data synced yet.";

  return (
    <div className="space-y-6">
      <ZoneMatrix
        policies={policyRows}
        selected={selected}
        onSelect={setSelected}
        emptyMessage={matrixEmptyMessage}
      />
      {(policies.error || rules.error || logs.error) && (
        <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-300">
          {policies.error ? `Policy sync view failed: ${policies.error.message}` : null}
          {rules.error ? ` Legacy rules view failed: ${rules.error.message}` : null}
          {logs.error ? ` Firewall logs view failed: ${logs.error.message}` : null}
        </div>
      )}
      <section className="rounded-md border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
        <h2 className="text-lg font-semibold text-slate-950 dark:text-slate-50">
          {hasPolicies ? "Zone Policies" : "Legacy Firewall Rules"}
        </h2>
        {!hasPolicies && hasRules && (
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
            UniFi has not returned v2 zone policies, so this table is showing legacy firewall rules.
          </p>
        )}
        <div className="mt-4 overflow-x-auto">
          {hasPolicies ? (
            <table className="min-w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                <tr><th className="p-2">Name</th><th>Action</th><th>Source</th><th>Destination</th><th>Hits</th><th>Enabled</th></tr>
              </thead>
              <tbody>
                {filtered.map((policy) => (
                  <tr key={policy.id} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="p-2 font-medium">{policy.name}</td><td>{policy.action}</td><td>{policy.src_zone ?? "Any"}</td><td>{policy.dst_zone ?? "Any"}</td><td>{policy.hit_count}</td><td>{policy.enabled ? "Yes" : "No"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : hasRules ? (
            <table className="min-w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500 dark:text-slate-400">
                <tr><th className="p-2">Ruleset</th><th>Index</th><th>Name</th><th>Action</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Enabled</th></tr>
              </thead>
              <tbody>
                {ruleRows.map((rule) => (
                  <tr key={rule.id} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="p-2 font-mono text-xs">{rule.ruleset ?? "Unknown"}</td><td>{rule.rule_index ?? "-"}</td><td className="font-medium">{rule.name}</td><td>{rule.action}</td><td>{rule.src_address ?? "Any"}</td><td>{rule.dst_address ?? "Any"}</td><td>{rule.protocol ?? "Any"}</td><td>{rule.dst_port ?? "Any"}</td><td>{rule.enabled ? "Yes" : "No"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-slate-600 dark:text-slate-400">
              No firewall policies or legacy rules have been synced yet. Check API startup, UniFi API access, and poller logs.
            </p>
          )}
        </div>
      </section>
      <section className="rounded-md border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
        <h2 className="text-lg font-semibold text-slate-950 dark:text-slate-50">Recent Firewall Logs</h2>
        <div className="mt-4 grid gap-2">
          {logRows.length > 0 ? (
            <>
              <div className="grid gap-2 px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 md:grid-cols-5">
                <span>Time</span><span>Rule</span><span>Action</span><span>Source</span><span>Destination</span>
              </div>
              {logRows.map((log) => (
                <div key={log.id} className="grid gap-2 rounded border border-slate-100 p-3 text-sm dark:border-slate-800 md:grid-cols-5">
                  <span>{new Date(log.timestamp).toLocaleString()}</span><span>{log.rule_name ?? "Unknown rule"}</span><span>{log.action}</span><span>{log.src_ip}</span><span>{log.dst_ip}:{log.dst_port ?? ""}</span>
                </div>
              ))}
            </>
          ) : (
            <p className="text-sm text-slate-600 dark:text-slate-400">
              No firewall syslog events have been parsed yet. Confirm UDP 514 is published and allowed from the UniFi console.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
