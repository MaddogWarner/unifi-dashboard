import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ZoneMatrix } from "../components/ZoneMatrix";
import { getFirewallLogs, getFirewallPolicies } from "../lib/api";

export function Firewall() {
  const [selected, setSelected] = useState<{ src: string; dst: string } | null>(null);
  const policies = useQuery({ queryKey: ["policies"], queryFn: getFirewallPolicies });
  const logs = useQuery({ queryKey: ["firewall-logs"], queryFn: () => getFirewallLogs("?limit=50") });
  const filtered = useMemo(
    () =>
      selected
        ? policies.data?.filter((policy) => policy.src_zone === selected.src && policy.dst_zone === selected.dst)
        : policies.data,
    [policies.data, selected]
  );

  return (
    <div className="space-y-6">
      <ZoneMatrix policies={policies.data ?? []} selected={selected} onSelect={setSelected} />
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Policies</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr><th className="p-2">Name</th><th>Action</th><th>Source</th><th>Destination</th><th>Hits</th><th>Enabled</th></tr>
            </thead>
            <tbody>
              {(filtered ?? []).map((policy) => (
                <tr key={policy.id} className="border-t border-slate-100">
                  <td className="p-2 font-medium">{policy.name}</td><td>{policy.action}</td><td>{policy.src_zone ?? "Any"}</td><td>{policy.dst_zone ?? "Any"}</td><td>{policy.hit_count}</td><td>{policy.enabled ? "Yes" : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Recent Firewall Logs</h2>
        <div className="mt-4 grid gap-2">
          {(logs.data ?? []).map((log) => (
            <div key={log.id} className="grid gap-2 rounded border border-slate-100 p-3 text-sm md:grid-cols-5">
              <span>{new Date(log.timestamp).toLocaleString()}</span><span>{log.rule_name ?? "Unknown rule"}</span><span>{log.action}</span><span>{log.src_ip}</span><span>{log.dst_ip}:{log.dst_port ?? ""}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
