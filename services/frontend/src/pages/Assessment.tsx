import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, CircleX } from "lucide-react";
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
    <div className="space-y-4">
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Security Assessment</h2>
        <p className="mt-2 text-4xl font-semibold text-teal-800">{assessment.data?.score ?? "-"}%</p>
      </section>
      {(assessment.data?.checks ?? []).map((check) => {
        const Icon = icon[check.status];
        return (
          <section key={check.check_id} className="rounded-md border border-slate-200 bg-white p-4">
            <div className="flex items-start gap-3">
              <Icon className={`mt-1 h-5 w-5 ${check.status === "fail" ? "text-rose-700" : check.status === "warn" ? "text-amber-700" : "text-emerald-700"}`} />
              <div>
                <h3 className="font-semibold text-slate-950">{check.label}</h3>
                <p className="mt-1 text-sm text-slate-700">{check.detail}</p>
                <p className="mt-2 text-sm text-slate-600">{check.recommendation}</p>
                {(check.evidence?.length ?? 0) > 0 ? (
                  <div className="mt-4 overflow-x-auto">
                    <table className="min-w-full text-left text-xs">
                      <thead className="uppercase text-slate-500">
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
                          <tr key={`${check.check_id}-${index}`} className="border-t border-slate-100">
                            <td className="p-2 font-medium text-slate-800">{evidenceLabel(item.type)}</td>
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
          </section>
        );
      })}
    </div>
  );
}
