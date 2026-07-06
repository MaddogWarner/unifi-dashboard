const BASE = "/api/v1";

function getToken(): string | null {
  return localStorage.getItem("auth_token");
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (response.status === 401) {
    localStorage.removeItem("auth_token");
    window.location.href = "/login";
    throw new Error("Session expired");
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(errorDetail(payload) ?? `${response.status} ${response.statusText}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function errorDetail(payload: unknown): string | null {
  if (typeof payload === "string") return payload;
  if (!payload || typeof payload !== "object" || !("detail" in payload)) return null;
  const detail = (payload as { detail: unknown }).detail;
  return typeof detail === "string" ? detail : null;
}

export async function apiLogin(email: string, password: string): Promise<string> {
  const body = new URLSearchParams({ username: email, password });
  const response = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString()
  });
  if (!response.ok) throw new Error("Invalid credentials");
  const data = (await response.json()) as { access_token?: string };
  if (!data.access_token) throw new Error("Login response did not include a token");
  return data.access_token;
}

export async function getSetupStatus(): Promise<{ configured: boolean }> {
  const response = await fetch(`${BASE}/auth/setup-status`);
  return handleResponse<{ configured: boolean }>(response);
}

export async function apiRegister(email: string, password: string): Promise<void> {
  const response = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(errorDetail(payload) ?? "Registration failed");
  }
}

export interface UserInfo {
  id: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  theme: string;
}

export async function getCurrentUser(): Promise<UserInfo> {
  return get<UserInfo>("/auth/me");
}

export async function updateMe(theme: string): Promise<UserInfo> {
  return patch<UserInfo>("/auth/me", { theme });
}

export async function changePassword(
  currentPassword: string,
  newPassword: string
): Promise<void> {
  await post<void>("/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword
  });
}

export async function listUsers(): Promise<UserInfo[]> {
  return get<UserInfo[]>("/auth/users");
}

export async function createUser(email: string, password: string): Promise<UserInfo> {
  return post<UserInfo>("/auth/users", { email, password });
}

export async function deleteUser(id: string): Promise<void> {
  await del<void>(`/auth/users/${id}`);
}

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
  interface: string | null;
  direction: string | null;
  matched_policy_id: number | null;
  raw_line: string;
};

export type FirewallLogParams = {
  skip?: number;
  limit?: number;
  src_ip?: string;
  dst_ip?: string;
  rule_name?: string;
  action?: string;
  from_ts?: string;
};

export type FirewallRule = {
  id: number;
  unifi_id: string;
  name: string;
  action: string;
  ruleset: string | null;
  rule_index: number | null;
  enabled: boolean;
  src_address: string | null;
  dst_address: string | null;
  protocol: string | null;
  dst_port: string | null;
  synced_at: string;
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
    evidence?: Array<{
      type: string;
      target_ip: string | null;
      port: number | null;
      protocol: string | null;
      service: string | null;
      reason: string | null;
      source: string | null;
      matched_name: string | null;
      scan_id: number | null;
      observed_at: string | null;
    }> | null;
  }>;
};

export type AttentionItem = {
  severity: "critical" | "warning" | "info";
  category: "connectivity" | "assessment" | "conflict" | "cve" | "syslog" | "threat";
  title: string;
  detail: string;
  link: string;
  timestamp: string | null;
};

export type DashboardStatus = {
  unifi_reachable: boolean;
  assessment_score: number | null;
  last_policy_sync: string | null;
  last_syslog_event: string | null;
  threat_events_24h: number;
};

export type DashboardAttention = {
  generated_at: string;
  status: DashboardStatus;
  items: AttentionItem[];
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

export type CVEAlert = {
  id: number;
  cve_id: string;
  title: string | null;
  description: string | null;
  severity: string;
  cvss_score: number | null;
  published_at: string | null;
  source: string;
  ubiquiti_bulletin_url: string | null;
  acknowledged_at: string | null;
  affected_devices: string[];
  created_at: string;
};

export type CVEListResponse = {
  total: number;
  items: CVEAlert[];
};

export type DeviceInventory = {
  id: number;
  name: string | null;
  model: string | null;
  firmware_version: string | null;
  ip_address: string | null;
  synced_at: string | null;
  active_cves: string[];
};

export type ThreatFeedSource = {
  id: number;
  name: string;
  url: string;
  source_type: string;
  enabled: boolean;
  misp_verify_ssl?: boolean;
  last_polled_at: string | null;
  last_entry_count: number;
  last_error: string | null;
  created_at: string;
};

export type ThreatFeedCreatePayload = {
  name: string;
  url: string;
  source_type?: string;
  api_key?: string;
  misp_verify_ssl?: boolean;
};

export type ThreatFeedUpdatePayload = {
  name?: string;
  url?: string;
  enabled?: boolean;
  api_key?: string;
  misp_verify_ssl?: boolean;
};

export type ThreatFeedStatus = {
  enabled: boolean;
  apply_mode: string;
  direction_mode: string;
  last_updated: string | null;
  total_entries: number;
  pending_count: number;
  zone_rules: Array<{ ruleset: string; direction: string; group_count: number; rule_count: number }>;
};

export type ThreatFeedEntry = {
  id: number;
  cidr: string;
  feed_source_name: string;
  added_at: string;
};

export type ThreatFeedPendingRule = {
  id: number;
  ruleset: string;
  chunk_index: number;
  direction: string;
  action: string;
  group_name: string;
  rule_name: string;
  entry_count: number;
  status: string;
  error: string | null;
  created_at: string;
  decided_at: string | null;
  applied_at: string | null;
};

export async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: authHeaders()
  });
  return handleResponse<T>(response);
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...authHeaders(),
      ...(body === undefined ? {} : { "Content-Type": "application/json" })
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return handleResponse<T>(response);
}

export const post = <T>(path: string, body?: unknown) => send<T>("POST", path, body);
export const put = <T>(path: string, body?: unknown) => send<T>("PUT", path, body);
export const patch = <T>(path: string, body?: unknown) => send<T>("PATCH", path, body);
export const del = <T>(path: string) => send<T>("DELETE", path);

export const getFirewallPolicies = () => get<FirewallPolicy[]>("/firewall/policies");
export const getFirewallRules = () => get<FirewallRule[]>("/firewall/rules");
export const getFirewallLogs = (params: FirewallLogParams = {}) => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") search.set(key, String(value));
  });
  const query = search.toString();
  return get<FirewallLog[]>(`/firewall/logs${query ? `?${query}` : ""}`);
};
export const getThreats = () => get<ThreatEvent[]>("/threats/events");
export const getIdsStatus = () => get<IdsStatus>("/threats/ids-status");
export type UnifiZone = { id: string | null; name: string };
export const getNetworks = () => get<Network[]>("/networks/");
export const getZones = () => get<UnifiZone[]>("/networks/zones");
export const getAssessment = () => get<AssessmentReport>("/assessment/");
export const getDashboardAttention = () => get<DashboardAttention>("/dashboard/attention");
export const getDriftSnapshots = () => get<Snapshot[]>("/drift/snapshots");
export const getDriftDiff = (a: number, b: number) => get<DriftDiff>(`/drift/diff/${a}/${b}`);
export const triggerScan = async (body: ScanRequest): Promise<{ scan_id: number }> => {
  const response = await fetch(`${BASE}/scan/`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return handleResponse<{ scan_id: number }>(response);
};
export const getScanResult = (id: number) => get<ScanResult>(`/scan/${id}`);
export const getSettings = () => get<Record<string, string>>("/settings/");
export const updateSettings = (settings: Record<string, string>) =>
  put<Record<string, string>>("/settings/", { settings });
export const getCVEAlerts = (params?: { severity?: string; acknowledged?: boolean; limit?: number }) => {
  const query = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value !== undefined) query.set(key, String(value));
  });
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return get<CVEListResponse>(`/cve/alerts${suffix}`);
};
export const acknowledgeCVE = (id: number) => post<{ ok: boolean }>(`/cve/alerts/${id}/acknowledge`, {});
export const getCVEDevices = () => get<DeviceInventory[]>("/cve/devices");
export const refreshCVE = () => post<{ ok: boolean; message: string }>("/cve/refresh", {});
export const getThreatFeedSources = () => get<ThreatFeedSource[]>("/threatfeed/feeds");
export const addThreatFeedSource = (payload: ThreatFeedCreatePayload) =>
  post<ThreatFeedSource>("/threatfeed/feeds", payload);
export const updateThreatFeedSource = (id: number, data: ThreatFeedUpdatePayload) =>
  put<ThreatFeedSource>(`/threatfeed/feeds/${id}`, data);
export const deleteThreatFeedSource = (id: number) => del<void>(`/threatfeed/feeds/${id}`);
export const getThreatFeedStatus = () => get<ThreatFeedStatus>("/threatfeed/status");
export const getThreatFeedEntries = (params?: { skip?: number; limit?: number; cidr?: string }) => {
  const query = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value !== undefined && value !== "") query.set(key, String(value));
  });
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return get<{ total: number; items: ThreatFeedEntry[] }>(`/threatfeed/entries${suffix}`);
};
export const getThreatFeedPendingRules = () => get<ThreatFeedPendingRule[]>("/threatfeed/pending-rules");
export const approveThreatFeedRule = (id: number) =>
  post<ThreatFeedPendingRule>(`/threatfeed/pending-rules/${id}/approve`, {});
export const rejectThreatFeedRule = (id: number) =>
  post<ThreatFeedPendingRule>(`/threatfeed/pending-rules/${id}/reject`, {});
export const refreshThreatFeed = () => post<{ ok: boolean; message: string }>("/threatfeed/refresh", {});
