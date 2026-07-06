import { FormEvent, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { getScanResult, triggerScan } from "../lib/api";

const fieldClass =
  "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";

export function Scanner() {
  const [target, setTarget] = useState("192.168.1.1");
  const [ports, setPorts] = useState("22,80,443");
  const [scanType, setScanType] = useState<"connect" | "syn" | "udp">("connect");
  const [scanId, setScanId] = useState<number | null>(null);
  const trigger = useMutation({
    mutationFn: triggerScan,
    onSuccess: (data) => setScanId(data.scan_id)
  });
  const result = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScanResult(scanId as number),
    enabled: scanId !== null,
    refetchInterval: (query) => (query.state.data?.status === "done" || query.state.data?.status === "error" ? false : 3000)
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    trigger.mutate({ target, ports, scan_type: scanType });
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">Scanner</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          RFC1918-only validation scans for firewall rule checks.
        </p>
      </header>
      <Card>
        <form onSubmit={submit} className="grid gap-4 md:grid-cols-[1fr_1fr_160px_auto]">
          <input className={fieldClass} value={target} onChange={(event) => setTarget(event.target.value)} aria-label="Target IP" />
          <input className={fieldClass} value={ports} onChange={(event) => setPorts(event.target.value)} aria-label="Ports" />
          <select className={fieldClass} value={scanType} onChange={(event) => setScanType(event.target.value as "connect" | "syn" | "udp")}>
            <option value="connect">Connect</option><option value="syn">SYN</option><option value="udp">UDP</option>
          </select>
          <Button className="flex items-center justify-center gap-2" variant="primary" type="submit">
            <Play className="h-4 w-4" /> Run
          </Button>
        </form>
      </Card>
      <Card title="Scan Result">
        <pre className="overflow-x-auto rounded bg-slate-950 p-4 text-sm text-slate-50">{JSON.stringify(result.data ?? trigger.error ?? { status: "No scan submitted" }, null, 2)}</pre>
      </Card>
    </div>
  );
}
