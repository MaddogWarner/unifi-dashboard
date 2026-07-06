import { FormEvent, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { getScanResult, triggerScan } from "../lib/api";
import type { ScanResult } from "../lib/api";

const fieldClass =
  "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";
const tableHeadClass = "bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400";

type ScanPort = {
  port: number;
  protocol: string;
  state: string;
  service: string;
  reason: string;
};

type ParsedScanResult = { host: string; ports: ScanPort[] } | { error: string };

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
        <ScanResultView
          scan={result.data}
          triggerError={trigger.error}
          requestedScanId={scanId}
        />
      </Card>
    </div>
  );
}

function ScanResultView({
  scan,
  triggerError,
  requestedScanId
}: {
  scan: ScanResult | undefined;
  triggerError: Error | null;
  requestedScanId: number | null;
}) {
  if (triggerError) {
    return <ErrorBanner message={triggerError.message} />;
  }

  if (!scan) {
    return <RawResult payload={{ status: "No scan submitted" }} />;
  }

  if (scan.status !== "done" && scan.status !== "error") {
    return (
      <p className="text-sm text-slate-600 dark:text-slate-400">
        Scanning scan #{requestedScanId ?? scan.id} for target {scan.target_ip}...
      </p>
    );
  }

  const parsed = parseScanResult(scan.result_json);
  if (scan.status === "error") {
    const message = parsed && "error" in parsed ? parsed.error : "Scan failed";
    return (
      <div className="space-y-4">
        <ErrorBanner message={message} />
        <RawResult payload={scan} collapsed />
      </div>
    );
  }

  if (!parsed) {
    return <RawResult payload={scan} />;
  }

  if ("error" in parsed) {
    return (
      <div className="space-y-4">
        <ErrorBanner message={parsed.error} />
        <RawResult payload={scan} collapsed />
      </div>
    );
  }

  const openCount = parsed.ports.filter((port) => port.state.toLowerCase() === "open").length;

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-700 dark:text-slate-300">
        Host <span className="font-mono">{parsed.host}</span> -{" "}
        <span className="tabular-nums">{parsed.ports.length}</span> ports scanned,{" "}
        <span className="tabular-nums">{openCount}</span> open
      </p>
      {parsed.ports.length ? (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className={tableHeadClass}>
              <tr>
                <th className="p-2">Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {parsed.ports.map((port) => (
                <tr
                  key={`${port.protocol}-${port.port}`}
                  className="border-t border-slate-100 dark:border-slate-800"
                >
                  <td className="p-2 font-mono tabular-nums">{port.port}</td>
                  <td className="font-mono text-xs">{port.protocol}</td>
                  <td><StateChip state={port.state} /></td>
                  <td>{port.service || "-"}</td>
                  <td>{port.reason || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-slate-600 dark:text-slate-400">
          No ports responded in the scanned range.
        </p>
      )}
      <RawResult payload={scan} collapsed />
    </div>
  );
}

function parseScanResult(value: string | null): ParsedScanResult | null {
  if (!value) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;
  if (typeof parsed.error === "string") return { error: parsed.error };
  if (typeof parsed.host !== "string" || !Array.isArray(parsed.ports)) return null;

  const ports: ScanPort[] = [];
  for (const item of parsed.ports) {
    if (!isRecord(item)) return null;
    if (
      typeof item.port !== "number" ||
      typeof item.protocol !== "string" ||
      typeof item.state !== "string" ||
      typeof item.service !== "string" ||
      typeof item.reason !== "string"
    ) {
      return null;
    }
    ports.push({
      port: item.port,
      protocol: item.protocol,
      state: item.state,
      service: item.service,
      reason: item.reason
    });
  }
  return { host: parsed.host, ports };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function StateChip({ state }: { state: string }) {
  const open = state.toLowerCase() === "open";
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
        open
          ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200"
          : "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300"
      }`}
    >
      {state}
    </span>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <p className="rounded bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">
      {message}
    </p>
  );
}

function RawResult({ payload, collapsed = false }: { payload: unknown; collapsed?: boolean }) {
  const pre = (
    <pre className="overflow-x-auto rounded bg-slate-950 p-4 text-sm text-slate-50">
      {JSON.stringify(payload, null, 2)}
    </pre>
  );
  if (!collapsed) return pre;
  return (
    <details>
      <summary className="cursor-pointer text-sm font-medium text-slate-700 dark:text-slate-300">
        Raw result
      </summary>
      <div className="mt-3">{pre}</div>
    </details>
  );
}
