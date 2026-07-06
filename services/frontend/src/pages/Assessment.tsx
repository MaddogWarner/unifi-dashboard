import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, CircleX } from "lucide-react";
import { Card } from "../components/Card";
import { getAssessment } from "../lib/api";

export function Assessment() {
  const assessment = useQuery({ queryKey: ["assessment"], queryFn: getAssessment });
  const icon = { pass: CheckCircle2, warn: CircleAlert, fail: CircleX };
  const evidenceLabel = (type: string) =>
    type
      .split("_")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">Security Assessment</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Scored checks, evidence, and remediation guidance.
        </p>
      </header>
      <Card title="Current score">
        <p className="text-4xl font-semibold text-brand-700 dark:text-brand-300">{assessment.data?.score ?? "-"}%</p>
      </Card>
      {(assessment.data?.checks ?? []).map((check) => {
        const Icon = icon[check.status];
        return (
          <Card key={check.check_id}>
            <div className="flex items-start gap-3">
              <Icon className={`mt-1 h-5 w-5 ${check.status === "fail" ? "text-rose-700" : check.status === "warn" ? "text-amber-700" : "text-emerald-700"}`} />
              <div>
                <h3 className="font-semibold text-slate-950 dark:text-slate-50">{check.label}</h3>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">{check.detail}</p>
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{check.recommendation}</p>
                {(check.evidence?.length ?? 0) > 0 ? (
                  <div className="mt-4 overflow-x-auto">
                    <table className="min-w-full text-left text-xs">
                      <thead className="bg-slate-50 uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400">
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
                          <tr key={`${check.check_id}-${index}`} className="border-t border-slate-100 dark:border-slate-800">
                            <td className="p-2 font-medium text-slate-800 dark:text-slate-200">{evidenceLabel(item.type)}</td>
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
      })}
    </div>
  );
}
