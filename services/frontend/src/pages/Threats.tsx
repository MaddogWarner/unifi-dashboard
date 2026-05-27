import { useQuery } from "@tanstack/react-query";
import { SeverityBadge } from "../components/SeverityBadge";
import { getIdsStatus, getThreats } from "../lib/api";

export function Threats() {
  const threats = useQuery({ queryKey: ["threats"], queryFn: getThreats });
  const ids = useQuery({ queryKey: ["ids-status"], queryFn: getIdsStatus });
  return (
    <div className="space-y-6">
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">IDS/IPS Status</h2>
        <div className="mt-3 grid gap-3 text-sm md:grid-cols-3">
          <div>Enabled: <strong>{ids.data?.enabled ? "Yes" : "No"}</strong></div>
          <div>Mode: <strong>{ids.data?.mode ?? "Unknown"}</strong></div>
          <div>Sensitivity: <strong>{ids.data?.sensitivity ?? "Unknown"}</strong></div>
        </div>
      </section>
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Threat Events</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500"><tr><th className="p-2">Time</th><th>Severity</th><th>Signature</th><th>Source</th><th>Destination</th><th>Action</th></tr></thead>
            <tbody>
              {(threats.data ?? []).map((event) => (
                <tr key={event.id} className="border-t border-slate-100">
                  <td className="p-2">{new Date(event.timestamp).toLocaleString()}</td><td><SeverityBadge severity={event.severity} /></td><td>{event.signature_name ?? event.category ?? "Unknown"}</td><td>{event.src_ip}</td><td>{event.dst_ip}</td><td>{event.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
