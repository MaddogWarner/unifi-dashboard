import { FormEvent, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { getScanResult, triggerScan } from "../lib/api";

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
      <form onSubmit={submit} className="grid gap-4 rounded-md border border-slate-200 bg-white p-4 md:grid-cols-[1fr_1fr_160px_auto]">
        <input className="rounded border border-slate-300 px-3 py-2" value={target} onChange={(event) => setTarget(event.target.value)} aria-label="Target IP" />
        <input className="rounded border border-slate-300 px-3 py-2" value={ports} onChange={(event) => setPorts(event.target.value)} aria-label="Ports" />
        <select className="rounded border border-slate-300 px-3 py-2" value={scanType} onChange={(event) => setScanType(event.target.value as "connect" | "syn" | "udp")}>
          <option value="connect">Connect</option><option value="syn">SYN</option><option value="udp">UDP</option>
        </select>
        <button className="flex items-center justify-center gap-2 rounded bg-teal-700 px-4 py-2 font-semibold text-white" type="submit">
          <Play className="h-4 w-4" /> Run
        </button>
      </form>
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Scan Result</h2>
        <pre className="mt-4 overflow-x-auto rounded bg-slate-950 p-4 text-sm text-slate-50">{JSON.stringify(result.data ?? trigger.error ?? { status: "No scan submitted" }, null, 2)}</pre>
      </section>
    </div>
  );
}
