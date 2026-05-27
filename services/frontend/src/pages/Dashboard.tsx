import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Network, ShieldCheck } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { StatusCard } from "../components/StatusCard";
import { getAssessment, getFirewallPolicies, getNetworks, getThreats } from "../lib/api";

export function Dashboard() {
  const policies = useQuery({ queryKey: ["policies"], queryFn: getFirewallPolicies });
  const threats = useQuery({ queryKey: ["threats"], queryFn: getThreats });
  const networks = useQuery({ queryKey: ["networks"], queryFn: getNetworks });
  const assessment = useQuery({ queryKey: ["assessment"], queryFn: getAssessment });
  const actionData = ["ALLOW", "BLOCK", "REJECT"].map((action) => ({
    action,
    count: policies.data?.filter((policy) => policy.action === action).length ?? 0
  }));

  return (
    <div className="space-y-6">
      <section className="grid gap-4 md:grid-cols-4">
        <StatusCard icon={ShieldCheck} label="Assessment score" value={assessment.data?.score ?? "-"} tone={assessment.data?.fail_count ? "bad" : "good"} />
        <StatusCard icon={AlertTriangle} label="Open findings" value={(assessment.data?.warn_count ?? 0) + (assessment.data?.fail_count ?? 0)} tone="warn" />
        <StatusCard icon={Network} label="Networks" value={networks.data?.length ?? "-"} />
        <StatusCard icon={Activity} label="Threat events" value={threats.data?.length ?? "-"} />
      </section>
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Policy Actions</h2>
        <div className="mt-4 h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={actionData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="action" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#0f766e" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  );
}
