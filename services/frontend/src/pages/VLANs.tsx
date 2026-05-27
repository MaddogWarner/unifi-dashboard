import { useQuery } from "@tanstack/react-query";
import { getNetworks } from "../lib/api";

export function VLANs() {
  const networks = useQuery({ queryKey: ["networks"], queryFn: getNetworks });
  return (
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-lg font-semibold text-slate-950">Networks and VLANs</h2>
      <div className="mt-4 overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-xs uppercase text-slate-500"><tr><th className="p-2">Name</th><th>VLAN</th><th>Zone</th><th>Subnet</th><th>Purpose</th><th>Enabled</th></tr></thead>
          <tbody>
            {(networks.data ?? []).map((network) => (
              <tr key={network.id} className="border-t border-slate-100">
                <td className="p-2 font-medium">{network.name}</td><td>{network.vlan_id ?? "Untagged"}</td><td>{network.zone ?? "Unassigned"}</td><td>{network.subnet ?? "-"}</td><td>{network.purpose ?? "-"}</td><td>{network.enabled ? "Yes" : "No"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
