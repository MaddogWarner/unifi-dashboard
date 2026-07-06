import { useQuery } from "@tanstack/react-query";
import { Card } from "../components/Card";
import { SeverityBadge } from "../components/SeverityBadge";
import { getIdsStatus, getThreats } from "../lib/api";

export function Threats() {
  const threats = useQuery({ queryKey: ["threats"], queryFn: getThreats });
  const ids = useQuery({ queryKey: ["ids-status"], queryFn: getIdsStatus });
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">Threats</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          IDS/IPS posture and recent threat events.
        </p>
      </header>
      <Card title="IDS/IPS Status">
        <div className="grid gap-3 text-sm md:grid-cols-3">
          <div>Enabled: <strong>{ids.data?.enabled ? "Yes" : "No"}</strong></div>
          <div>Mode: <strong>{ids.data?.mode ?? "Unknown"}</strong></div>
          <div>Sensitivity: <strong>{ids.data?.sensitivity ?? "Unknown"}</strong></div>
        </div>
      </Card>
      <Card title="Threat Events">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400"><tr><th className="p-2">Time</th><th>Severity</th><th>Signature</th><th>Source</th><th>Destination</th><th>Action</th></tr></thead>
            <tbody>
              {(threats.data ?? []).map((event) => (
                <tr key={event.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="p-2">{new Date(event.timestamp).toLocaleString()}</td><td><SeverityBadge severity={event.severity} /></td><td>{event.signature_name ?? event.category ?? "Unknown"}</td><td>{event.src_ip}</td><td>{event.dst_ip}</td><td>{event.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
