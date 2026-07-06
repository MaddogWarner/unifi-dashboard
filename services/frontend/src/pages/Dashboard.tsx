import { useQuery } from "@tanstack/react-query";
import { Activity, RefreshCw, ScrollText, ShieldCheck, Wifi } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";

import { Card } from "../components/Card";
import { StatusCard } from "../components/StatusCard";
import type { AttentionItem, DashboardStatus } from "../lib/api";
import { getDashboardAttention } from "../lib/api";

type Tone = "neutral" | "good" | "warn" | "bad";

const severityClasses = {
  critical: "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-300",
  warning: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300",
  info: "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-300"
};

function formatTimestamp(value: string | null) {
  if (!value) return null;
  return new Date(value).toLocaleString("en-AU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
}

function olderThan24h(value: string | null) {
  if (!value) return false;
  return Date.now() - new Date(value).getTime() > 24 * 60 * 60 * 1000;
}

function scoreTone(score: number | null): Tone {
  if (score === null) return "neutral";
  if (score >= 80) return "good";
  if (score >= 50) return "warn";
  return "bad";
}

function statusCards(status: DashboardStatus | undefined) {
  return [
    {
      icon: ShieldCheck,
      label: "Assessment score",
      value: status?.assessment_score ?? "–",
      tone: scoreTone(status?.assessment_score ?? null)
    },
    {
      icon: Wifi,
      label: "UniFi console",
      value: status ? (status.unifi_reachable ? "Connected" : "Unreachable") : "–",
      tone: status ? (status.unifi_reachable ? "good" : "bad") : "neutral"
    },
    {
      icon: RefreshCw,
      label: "Last sync",
      value: status ? (formatTimestamp(status.last_policy_sync) ?? "Never") : "–",
      tone: status ? (status.last_policy_sync ? "neutral" : "warn") : "neutral"
    },
    {
      icon: ScrollText,
      label: "Syslog",
      value: status ? (formatTimestamp(status.last_syslog_event) ?? "No events") : "–",
      tone: status && (!status.last_syslog_event || olderThan24h(status.last_syslog_event)) ? "warn" : "neutral"
    },
    {
      icon: Activity,
      label: "Threats (24 h)",
      value: status ? status.threat_events_24h : "–",
      tone: status?.threat_events_24h ? "warn" : "neutral"
    }
  ] satisfies Array<{
    icon: LucideIcon;
    label: string;
    value: string | number;
    tone: Tone;
  }>;
}

function capitalise(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function SeverityChip({ severity }: { severity: AttentionItem["severity"] }) {
  return (
    <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${severityClasses[severity]}`}>
      {capitalise(severity)}
    </span>
  );
}

function itemCountLabel(count: number) {
  return `${count} item${count === 1 ? "" : "s"}`;
}

export function Dashboard() {
  const attention = useQuery({
    queryKey: ["dashboard-attention"],
    queryFn: getDashboardAttention,
    refetchInterval: 60_000
  });
  const items = attention.data?.items ?? [];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          What needs your attention across the network.
        </p>
      </header>

      <section className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        {statusCards(attention.data?.status).map((card) => (
          <StatusCard
            key={card.label}
            icon={card.icon}
            label={card.label}
            value={card.value}
            tone={card.tone}
          />
        ))}
      </section>

      <Card
        title="Needs attention"
        action={attention.data ? <span className="text-sm text-slate-500 dark:text-slate-400">{itemCountLabel(items.length)}</span> : null}
      >
        {attention.isLoading ? (
          <p className="text-sm text-slate-600 dark:text-slate-400">Loading…</p>
        ) : attention.error ? (
          <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-300">
            Dashboard attention feed failed: {attention.error.message}
          </div>
        ) : items.length === 0 ? (
          <div className="rounded-md border border-emerald-200 bg-emerald-50 p-4 text-sm font-medium text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-200">
            All clear — nothing needs attention.
          </div>
        ) : (
          <div className="-mx-4 -mb-4 divide-y divide-slate-100 dark:divide-slate-800">
            {items.map((item, index) => (
              <Link
                key={`${item.category}-${item.title}-${index}`}
                to={item.link}
                className="flex flex-col gap-3 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800 sm:flex-row sm:items-start sm:justify-between"
              >
                <div className="flex min-w-0 gap-3">
                  <div className="shrink-0 pt-0.5">
                    <SeverityChip severity={item.severity} />
                  </div>
                  <div className="min-w-0">
                    <p className="font-medium text-brand-700 dark:text-brand-300">{item.title}</p>
                    <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{item.detail}</p>
                  </div>
                </div>
                {item.timestamp && (
                  <span className="shrink-0 text-left text-xs text-slate-500 dark:text-slate-400 sm:text-right">
                    {formatTimestamp(item.timestamp)}
                  </span>
                )}
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
