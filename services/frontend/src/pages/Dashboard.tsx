import { useQuery } from "@tanstack/react-query";
import { Activity, RefreshCw, ScrollText, ShieldCheck, Wifi } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";

import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { PageHeader } from "../components/PageHeader";
import { Skeleton } from "../components/Skeleton";
import { StatusCard } from "../components/StatusCard";
import type { AttentionItem, DashboardStatus } from "../lib/api";
import { getDashboardAttention } from "../lib/api";
import { formatTimestamp, relativeTime } from "../lib/format";

type Tone = "neutral" | "good" | "warn" | "bad";
type Severity = AttentionItem["severity"];

const severityOrder: Severity[] = ["critical", "warning", "info"];
const severityBadge = { critical: "danger", warning: "warning", info: "neutral" } as const;
const severityLabel = { critical: "Critical", warning: "Warning", info: "Info" };

export function olderThan24h(value: string | null) {
  if (!value) return false;
  return Date.now() - new Date(value).getTime() > 24 * 60 * 60 * 1000;
}

export function scoreTone(score: number | null): Tone {
  if (score === null) return "neutral";
  if (score >= 80) return "good";
  if (score >= 50) return "warn";
  return "bad";
}

export function groupBySeverity(items: AttentionItem[]) {
  return severityOrder
    .map((severity) => ({ severity, items: items.filter((item) => item.severity === severity) }))
    .filter((group) => group.items.length > 0);
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
      value: status ? (relativeTime(status.last_policy_sync) ?? "Never") : "–",
      hint: formatTimestamp(status?.last_policy_sync ?? null) ?? undefined,
      tone: status ? (status.last_policy_sync ? "neutral" : "warn") : "neutral"
    },
    {
      icon: ScrollText,
      label: "Syslog",
      value: status ? (relativeTime(status.last_syslog_event) ?? "No events") : "–",
      hint: formatTimestamp(status?.last_syslog_event ?? null) ?? undefined,
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
    hint?: string;
    tone: Tone;
  }>;
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
  const groups = groupBySeverity(items);
  const updated = relativeTime(attention.data?.generated_at ?? null);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="What needs your attention across the network."
        actions={
          <div className="flex items-center gap-3">
            {updated ? (
              <span className="text-xs text-fg-muted" title={formatTimestamp(attention.data?.generated_at ?? null) ?? undefined}>
                Updated {updated}
              </span>
            ) : null}
            <Button
              className="inline-flex items-center gap-2"
              disabled={attention.isFetching}
              onClick={() => void attention.refetch()}
            >
              <RefreshCw aria-hidden className={`h-4 w-4 ${attention.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
        }
      />

      <section className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        {statusCards(attention.data?.status).map((card) => (
          <StatusCard
            key={card.label}
            icon={card.icon}
            label={card.label}
            value={card.value}
            hint={card.hint}
            tone={card.tone}
          />
        ))}
      </section>

      <Card
        title="Needs attention"
        action={attention.data ? <span className="text-sm text-fg-muted">{itemCountLabel(items.length)}</span> : null}
      >
        {attention.isLoading ? (
          <div className="space-y-3" role="status" aria-label="Loading">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : attention.error ? (
          <div className="rounded-md bg-danger-bg p-4 text-sm text-danger-fg">
            Dashboard attention feed failed: {attention.error.message}
          </div>
        ) : items.length === 0 ? (
          <div className="rounded-md bg-success-bg p-4 text-sm font-medium text-success-fg">
            All clear — nothing needs attention.
          </div>
        ) : (
          <div className="space-y-4">
            {groups.map((group) => (
              <section key={group.severity} aria-label={`${severityLabel[group.severity]} items`}>
                <div className="mb-1 flex items-center gap-2">
                  <Badge tone={severityBadge[group.severity]}>{severityLabel[group.severity]}</Badge>
                  <span className="text-xs text-fg-muted">{itemCountLabel(group.items.length)}</span>
                </div>
                <div className="-mx-4 divide-y divide-line">
                  {group.items.map((item, index) => (
                    <Link
                      key={`${item.category}-${item.title}-${index}`}
                      to={item.link}
                      className="flex flex-col gap-1 px-4 py-3 hover:bg-hover sm:flex-row sm:items-start sm:justify-between sm:gap-3"
                    >
                      <div className="min-w-0">
                        <p className="font-medium text-brand-ink">{item.title}</p>
                        <p className="mt-1 text-sm text-fg-muted">{item.detail}</p>
                      </div>
                      {item.timestamp && (
                        <span
                          className="shrink-0 text-left text-xs text-fg-muted sm:text-right"
                          title={formatTimestamp(item.timestamp) ?? undefined}
                        >
                          {relativeTime(item.timestamp)}
                        </span>
                      )}
                    </Link>
                  ))}
                </div>
              </section>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
