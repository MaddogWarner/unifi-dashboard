import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CheckCircle2, CircleAlert, CircleX } from "lucide-react";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { ScoreRing } from "../components/ScoreRing";
import type { AssessmentReport } from "../lib/api";
import { getAssessment, getAssessmentHistory } from "../lib/api";

type Check = AssessmentReport["checks"][number];

const statusOrder = { fail: 0, warn: 1, pass: 2 };
const statusIcon = { pass: CheckCircle2, warn: CircleAlert, fail: CircleX };
const statusColour = { pass: "text-success-fg", warn: "text-warning-fg", fail: "text-danger-fg" };
const axisTick = { fill: "var(--fg-muted)", fontSize: 12 };

function evidenceLabel(type: string) {
  return type
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function CheckCard({ check }: { check: Check }) {
  const Icon = statusIcon[check.status];
  return (
    <Card>
      <div className="flex items-start gap-3">
        <Icon aria-hidden className={`mt-1 h-5 w-5 shrink-0 ${statusColour[check.status]}`} />
        <div className="min-w-0">
          <h3 className="font-semibold text-fg">{check.label}</h3>
          <p className="mt-1 text-sm text-fg">{check.detail}</p>
          <p className="mt-2 text-sm text-fg-muted">{check.recommendation}</p>
          {(check.evidence?.length ?? 0) > 0 ? (
            <div className="mt-4 overflow-x-auto">
              <table className="min-w-full text-left text-xs">
                <thead className="bg-surface-muted uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="p-2">Evidence</th>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Source</th>
                    <th>Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {check.evidence?.map((item, index) => (
                    <tr key={`${check.check_id}-${index}`} className="border-t border-line">
                      <td className="p-2 font-medium text-fg">{evidenceLabel(item.type)}</td>
                      <td className="font-mono">{item.target_ip ?? "-"}</td>
                      <td>{item.port ? `${item.port}/${item.protocol ?? "tcp"}` : "-"}</td>
                      <td>{item.service ?? item.reason ?? "-"}</td>
                      <td>{item.matched_name ?? item.source ?? "-"}</td>
                      <td>{item.observed_at ? new Date(item.observed_at).toLocaleString() : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      </div>
    </Card>
  );
}

export function Assessment() {
  const assessment = useQuery({ queryKey: ["assessment"], queryFn: getAssessment });
  const [historyDays, setHistoryDays] = useState(30);
  const history = useQuery({
    queryKey: ["assessment-history", historyDays],
    queryFn: () => getAssessmentHistory(historyDays)
  });

  const checks = [...(assessment.data?.checks ?? [])].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);
  const open = checks.filter((check) => check.status !== "pass");
  const passing = checks.filter((check) => check.status === "pass");

  return (
    <div className="space-y-6">
      <PageHeader title="Security Assessment" description="Scored checks, evidence, and remediation guidance." />
      <Card title="Current score">
        <div className="flex flex-wrap items-center gap-6">
          <ScoreRing score={assessment.data?.score ?? null} />
          <div className="flex flex-wrap gap-2">
            <Badge tone="success">{assessment.data?.pass_count ?? 0} pass</Badge>
            <Badge tone="warning">{assessment.data?.warn_count ?? 0} warn</Badge>
            <Badge tone="danger">{assessment.data?.fail_count ?? 0} fail</Badge>
          </div>
        </div>
      </Card>
      <Card
        title="Score history"
        action={
          <select
            aria-label="History range"
            className="rounded-md border border-line bg-surface px-3 py-2 text-sm text-fg"
            value={historyDays}
            onChange={(event) => setHistoryDays(Number(event.target.value))}
          >
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </select>
        }
      >
        {(history.data?.length ?? 0) >= 2 ? (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history.data}>
                <CartesianGrid stroke="var(--line)" strokeDasharray="3 3" />
                <XAxis
                  dataKey="created_at"
                  tick={axisTick}
                  stroke="var(--line)"
                  tickFormatter={(value: string) => new Date(value).toLocaleDateString()}
                />
                <YAxis domain={[0, 100]} tick={axisTick} stroke="var(--line)" />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    borderRadius: 8,
                    color: "var(--fg)"
                  }}
                  labelFormatter={(value) => new Date(String(value)).toLocaleString()}
                  formatter={(value, name, item) =>
                    name === "score"
                      ? [
                          `${value}% (pass ${item.payload.pass_count}, warn ${item.payload.warn_count}, fail ${item.payload.fail_count})`,
                          "Score"
                        ]
                      : [value, name]
                  }
                />
                <Area dataKey="score" stroke="var(--brand-ink)" fill="var(--brand-ink)" fillOpacity={0.15} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyState title="No history yet" detail="History builds up as the assessment runs — check back tomorrow." />
        )}
      </Card>
      {open.map((check) => (
        <CheckCard key={check.check_id} check={check} />
      ))}
      {passing.length > 0 ? (
        <details className="group rounded-lg border border-line bg-surface shadow-sm">
          <summary className="cursor-pointer rounded-lg px-4 py-3 text-sm font-medium text-fg focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500">
            {passing.length} passing {passing.length === 1 ? "check" : "checks"}
          </summary>
          <div className="space-y-4 p-4 pt-0">
            {passing.map((check) => (
              <CheckCard key={check.check_id} check={check} />
            ))}
          </div>
        </details>
      ) : null}
    </div>
  );
}
