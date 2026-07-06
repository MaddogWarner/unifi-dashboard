import { Ban, Clock, Layers3, ShieldCheck } from "lucide-react";
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { StatusCard } from "../../components/StatusCard";
import { ZoneMatrix } from "../../components/ZoneMatrix";
import { getFirewallPolicies, getFirewallRules } from "../../lib/api";

type Props = {
  onMatrixSelect: (pair: { src: string; dst: string }) => void;
};

function formatTimestamp(value: string | null) {
  if (!value) return "Never";
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

function LegendChip({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-3 w-3 rounded-sm ${className}`} />
      {label}
    </span>
  );
}

export function OverviewTab({ onMatrixSelect }: Props) {
  const [searchParams] = useSearchParams();
  const policies = useQuery({ queryKey: ["policies"], queryFn: getFirewallPolicies });
  const rules = useQuery({ queryKey: ["firewall-rules"], queryFn: getFirewallRules });
  const policyRows = policies.data ?? [];
  const ruleRows = rules.data ?? [];
  const hasPolicies = policyRows.length > 0;
  const hasRules = ruleRows.length > 0;
  const selected =
    searchParams.get("src") && searchParams.get("dst")
      ? { src: searchParams.get("src") ?? "", dst: searchParams.get("dst") ?? "" }
      : null;
  const matrixEmptyMessage = hasRules
    ? "No v2 zone policy data synced yet. Legacy firewall rules are available below."
    : "No firewall policy or legacy rule data synced yet.";
  const zones = useMemo(
    () =>
      new Set(policyRows.flatMap((policy) => [policy.src_zone, policy.dst_zone]).filter(Boolean)).size,
    [policyRows]
  );
  const lastSync = useMemo(() => {
    const values = (hasPolicies ? policyRows : ruleRows).map((item) => item.synced_at);
    const sorted = values.sort();
    return sorted.length > 0 ? sorted[sorted.length - 1] : null;
  }, [hasPolicies, policyRows, ruleRows]);

  return (
    <div className="space-y-6">
      {(policies.error || rules.error) && (
        <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-300">
          {policies.error ? `Policy sync view failed: ${policies.error.message}` : null}
          {rules.error ? ` Legacy rules view failed: ${rules.error.message}` : null}
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-4">
        {hasPolicies ? (
          <>
            <StatusCard icon={ShieldCheck} label="Policies" value={policyRows.length} />
            <StatusCard icon={Layers3} label="Zones" value={zones} />
            <StatusCard
              icon={Ban}
              label="Disabled policies"
              value={policyRows.filter((policy) => !policy.enabled).length}
              tone={policyRows.some((policy) => !policy.enabled) ? "warn" : "neutral"}
            />
            <StatusCard icon={Clock} label="Last sync" value={formatTimestamp(lastSync)} />
          </>
        ) : (
          <>
            <StatusCard icon={ShieldCheck} label="Legacy rules" value={ruleRows.length} />
            <StatusCard icon={Layers3} label="Enabled rules" value={ruleRows.filter((rule) => rule.enabled).length} />
            <StatusCard
              icon={Ban}
              label="Disabled rules"
              value={ruleRows.filter((rule) => !rule.enabled).length}
              tone={ruleRows.some((rule) => !rule.enabled) ? "warn" : "neutral"}
            />
            <StatusCard icon={Clock} label="Last sync" value={formatTimestamp(lastSync)} />
          </>
        )}
      </div>
      {!hasPolicies && hasRules && (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          UniFi has not returned v2 zone policies, so this table is showing legacy firewall rules.
        </p>
      )}
      <div className="space-y-3">
        <ZoneMatrix
          policies={policyRows}
          selected={selected}
          onSelect={onMatrixSelect}
          emptyMessage={matrixEmptyMessage}
        />
        <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-slate-600 dark:text-slate-400">
          <LegendChip className="bg-emerald-300" label="Allow" />
          <LegendChip className="bg-rose-300" label="Block" />
          <LegendChip className="bg-amber-300" label="Reject" />
          <LegendChip className="bg-violet-300" label="Mixed" />
          <LegendChip className="bg-slate-300" label="None" />
        </div>
      </div>
    </div>
  );
}
