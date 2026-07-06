import { useQuery } from "@tanstack/react-query";
import { Card } from "../../components/Card";
import { getNetworks } from "../../lib/api";

export function NetworksTab() {
  const networks = useQuery({ queryKey: ["networks"], queryFn: getNetworks });
  return (
    <div className="space-y-6">
      <Card title="Networks and VLANs">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400"><tr><th className="p-2">Name</th><th>VLAN</th><th>Zone</th><th>Subnet</th><th>Purpose</th><th>Enabled</th></tr></thead>
            <tbody>
              {(networks.data ?? []).map((network) => (
                <tr key={network.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="p-2 font-medium">{network.name}</td><td>{network.vlan_id ?? "Untagged"}</td><td>{network.zone ?? "Unassigned"}</td><td>{network.subnet ?? "-"}</td><td>{network.purpose ?? "-"}</td><td>{network.enabled ? "Yes" : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
