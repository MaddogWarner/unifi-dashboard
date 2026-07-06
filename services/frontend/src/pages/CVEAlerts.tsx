import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusCard } from "../components/StatusCard";
import { acknowledgeCVE, getCVEAlerts, getCVEDevices } from "../lib/api";

const fieldClass =
  "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";
const tableHeadClass = "bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400";

export function CVEAlerts() {
  const queryClient = useQueryClient();
  const [severity, setSeverity] = useState("");
  const [hideAcknowledged, setHideAcknowledged] = useState(true);
  const devices = useQuery({ queryKey: ["cve-devices"], queryFn: getCVEDevices });
  const alerts = useQuery({
    queryKey: ["cve-alerts", severity, hideAcknowledged],
    queryFn: () =>
      getCVEAlerts({ severity: severity || undefined, acknowledged: hideAcknowledged ? false : undefined, limit: 100 })
  });
  const acknowledge = useMutation({
    mutationFn: acknowledgeCVE,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cve-alerts"] });
      queryClient.invalidateQueries({ queryKey: ["cve-devices"] });
    }
  });
  const counts = useMemo(
    () => ({
      critical: alerts.data?.items.filter((item) => item.severity === "CRITICAL").length ?? 0,
      high: alerts.data?.items.filter((item) => item.severity === "HIGH").length ?? 0
    }),
    [alerts.data]
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">CVE Alerts</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Firmware exposure view for managed UniFi devices.</p>
      </header>
      <section className="grid gap-4 md:grid-cols-2">
        <StatusCard icon={ShieldAlert} label="Critical CVEs" value={counts.critical} tone={counts.critical ? "bad" : "good"} />
        <StatusCard icon={AlertTriangle} label="High CVEs" value={counts.high} tone={counts.high ? "warn" : "good"} />
      </section>

      <Card title="Device Inventory">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className={tableHeadClass}>
              <tr>
                <th className="p-2">Device</th>
                <th>Model</th>
                <th>Firmware</th>
                <th>IP</th>
                <th>Open CVEs</th>
              </tr>
            </thead>
            <tbody>
              {(devices.data ?? []).map((device) => (
                <tr key={device.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="p-2 font-medium">{device.name || device.model || "Unnamed"}</td>
                  <td>{device.model ?? "-"}</td>
                  <td className="font-mono text-xs">{device.firmware_version ?? "-"}</td>
                  <td className="font-mono text-xs">{device.ip_address ?? "-"}</td>
                  <td>
                    {device.active_cves.length ? (
                      <span className="font-semibold text-rose-700">{device.active_cves.length}</span>
                    ) : (
                      <span className="text-emerald-700">Clean</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card
        title="Alerts"
        action={
          <div className="flex flex-wrap items-center gap-3">
            <select
              className={fieldClass}
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
            </select>
            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={hideAcknowledged}
                onChange={(event) => setHideAcknowledged(event.target.checked)}
              />
              Hide acknowledged
            </label>
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className={tableHeadClass}>
              <tr>
                <th className="p-2">CVE</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>Title</th>
                <th>Published</th>
                <th>Affected Devices</th>
                <th>Source</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(alerts.data?.items ?? []).map((alert) => (
                <tr key={alert.id} className="border-t border-slate-100 align-top dark:border-slate-800">
                  <td className="p-2 font-mono text-xs">
                    <a
                      className="text-brand-700 hover:underline dark:text-brand-300"
                      href={`https://nvd.nist.gov/vuln/detail/${alert.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {alert.cve_id}
                    </a>
                  </td>
                  <td><SeverityBadge severity={alert.severity} /></td>
                  <td>{alert.cvss_score?.toFixed(1) ?? "-"}</td>
                  <td className="max-w-xl">{alert.title ?? "-"}</td>
                  <td>{alert.published_at ? new Date(alert.published_at).toLocaleDateString() : "-"}</td>
                  <td>{alert.affected_devices.join(", ") || "-"}</td>
                  <td>{alert.source === "ubiquiti" ? "Ubiquiti" : "NVD"}</td>
                  <td>
                    {alert.acknowledged_at ? (
                      <span className="text-slate-400">Acknowledged</span>
                    ) : (
                      <Button
                        className="py-1.5"
                        onClick={() => acknowledge.mutate(alert.id)}
                      >
                        Acknowledge
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
