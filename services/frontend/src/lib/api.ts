const BASE = "/api/v1";

export type FirewallPolicy = {
  id: number;
  unifi_id: string;
  name: string;
  action: string;
  src_zone: string | null;
  dst_zone: string | null;
  enabled: boolean;
  protocol: string | null;
  schedule: string | null;
  synced_at: string;
  hit_count: number;
};

export type FirewallLog = {
  id: number;
  timestamp: string;
  rule_name: string | null;
  action: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
};

export type ThreatEvent = {
  id: number;
  timestamp: string;
  signature_name: string | null;
  category: string | null;
  severity: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  action: string | null;
};

export type IdsStatus = {
  enabled: boolean;
  mode: string | null;
  categories: string[];
  sensitivity: string | null;
  synced_at: string | null;
  gaps: string[];
};

export type Network = {
  id: number;
  name: string;
  vlan_id: number | null;
  zone: string | null;
  subnet: string | null;
  purpose: string | null;
  enabled: boolean;
};

export type AssessmentReport = {
  score: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  checks: Array<{
    check_id: string;
    label: string;
    status: "pass" | "warn" | "fail";
    detail: string;
    recommendation: string;
  }>;
};

export type Snapshot = {
  id: number;
  snapshot_type: string;
  snapshot_hash: string;
  created_at: string;
};

export type DriftDiff = {
  from_snapshot: number;
  to_snapshot: number;
  added: unknown[];
  removed: unknown[];
  changed: unknown[];
};

export type ScanRequest = {
  target: string;
  ports: string;
  scan_type: "connect" | "syn" | "udp";
};

export type ScanResult = {
  id: number;
  target_ip: string;
  scan_type: string;
  ports_requested: string;
  status: string;
  result_json: string | null;
  nmap_output: string | null;
  created_at: string;
  completed_at: string | null;
};

export async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${BASE}${path}`);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<T>;
}

export const getFirewallPolicies = () => get<FirewallPolicy[]>("/firewall/policies");
export const getFirewallLogs = (params = "") => get<FirewallLog[]>(`/firewall/logs${params}`);
export const getThreats = () => get<ThreatEvent[]>("/threats/events");
export const getIdsStatus = () => get<IdsStatus>("/threats/ids-status");
export const getNetworks = () => get<Network[]>("/networks/");
export const getAssessment = () => get<AssessmentReport>("/assessment/");
export const getDriftSnapshots = () => get<Snapshot[]>("/drift/snapshots");
export const getDriftDiff = (a: number, b: number) => get<DriftDiff>(`/drift/diff/${a}/${b}`);
export const triggerScan = async (body: ScanRequest): Promise<{ scan_id: number }> => {
  const response = await fetch(`${BASE}/scan/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<{ scan_id: number }>;
};
export const getScanResult = (id: number) => get<ScanResult>(`/scan/${id}`);
