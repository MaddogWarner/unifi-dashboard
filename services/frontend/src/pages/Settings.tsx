import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, Eye, EyeOff, Save, ShieldCheck } from "lucide-react";
import { clearActionToast, showErrorToast, showSuccessToast } from "../components/ActionToast";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { useTheme } from "../contexts/ThemeContext";
import {
  changePassword,
  createUser,
  deleteUser,
  getCurrentUser,
  getSettings,
  getZones,
  listUsers,
  refreshCVE,
  refreshThreatFeed,
  testNotifications,
  updateMe,
  updateSettings
} from "../lib/api";

const fieldClass =
  "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";
const compactFieldClass =
  "w-full max-w-sm rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";
const labelClass = "text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400";
const tableHeadClass = "bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400";

const RULESET_TO_DEST_ZONE: Record<string, string[]> = {
  WAN_IN: ["Internal", "LAN"],
  WAN_LOCAL: ["Gateway"],
  LAN_IN: ["Internal", "LAN"],
  LAN_OUT: ["Internal", "LAN"],
  LAN_LOCAL: ["Gateway", "Internal", "LAN"],
  GUEST_IN: ["Hotspot", "Guest"],
};

function normalizeZoneNames(zones: string[], available: Set<string>): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const z of zones) {
    const candidates = RULESET_TO_DEST_ZONE[z] ?? [z];
    const mapped = candidates.find((c) => available.has(c)) ?? (available.has(z) ? z : null);
    if (mapped && !seen.has(mapped)) {
      seen.add(mapped);
      result.push(mapped);
    }
  }
  return result;
}

const defaults: Record<string, string> = {
  "unifi.host": "",
  "unifi.api_key": "",
  "unifi.site": "default",
  "unifi.verify_ssl": "false",
  "cve_monitoring.enabled": "false",
  "cve_monitoring.poll_interval_hours": "24",
  "threat_feed.enabled": "false",
  "threat_feed.poll_interval_hours": "24",
  "threat_feed.zones": '["WAN_IN","WAN_LOCAL"]',
  "threat_feed.apply_mode": "preview",
  "threat_feed.direction_mode": "inbound",
  "http_proxy.enabled": "false",
  "http_proxy.url": "",
  "retention.firewall_logs_days": "30",
  "retention.threat_events_days": "90",
  "retention.scan_results_days": "90",
  "retention.assessment_runs_days": "365",
  "notifications.enabled": "false",
  "notifications.severity_threshold": "critical",
  "notifications.ntfy_url": "",
  "notifications.ntfy_token": "",
  "notifications.webhook_url": ""
};

export function Settings() {
  const queryClient = useQueryClient();
  const { theme, setTheme } = useTheme();
  const settings = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  const zonesQuery = useQuery({ queryKey: ["networks-zones"], queryFn: getZones, staleTime: 60_000 });
  const meQuery = useQuery({ queryKey: ["me"], queryFn: getCurrentUser });
  const isSuperuser = meQuery.data?.is_superuser ?? false;
  const [draft, setDraft] = useState(defaults);
  const [showKey, setShowKey] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [notificationError, setNotificationError] = useState<string | null>(null);
  const [cpCurrent, setCpCurrent] = useState("");
  const [cpNew, setCpNew] = useState("");
  const [cpConfirm, setCpConfirm] = useState("");
  const [cpError, setCpError] = useState<string | null>(null);
  const [nuEmail, setNuEmail] = useState("");
  const [nuPassword, setNuPassword] = useState("");
  const [nuError, setNuError] = useState<string | null>(null);
  const usersQuery = useQuery({
    queryKey: ["users"],
    queryFn: listUsers,
    enabled: isSuperuser
  });
  const save = useMutation({
    mutationFn: updateSettings,
    onMutate: clearActionToast,
    onSuccess: (data) => {
      setDraft({ ...defaults, ...data });
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      queryClient.invalidateQueries({ queryKey: ["threatfeed-status"] });
      showSuccessToast("Save successful");
    },
    onError: (err) => showErrorToast(errorMessage(err))
  });
  const themeMutation = useMutation({
    mutationFn: (nextTheme: "light" | "dark") => updateMe(nextTheme),
    onMutate: clearActionToast,
    onSuccess: (data) => {
      setTheme(data.theme === "dark" ? "dark" : "light");
      queryClient.invalidateQueries({ queryKey: ["me"] });
      showSuccessToast("Theme preference saved");
    },
    onError: () => showErrorToast("Failed to save theme preference")
  });
  const cveRefresh = useMutation({
    mutationFn: refreshCVE,
    onMutate: clearActionToast,
    onSuccess: () => {
      setRefreshError(null);
      showSuccessToast("Refresh successful");
    },
    onError: (err) => {
      const message = errorMessage(err);
      setRefreshError(message);
      showErrorToast(message);
    }
  });
  const changePw = useMutation({
    mutationFn: () => changePassword(cpCurrent, cpNew),
    onMutate: clearActionToast,
    onSuccess: () => {
      setCpCurrent("");
      setCpNew("");
      setCpConfirm("");
      setCpError(null);
      showSuccessToast("Password changed");
    },
    onError: (err) => showErrorToast(errorMessage(err))
  });
  const createUserMut = useMutation({
    mutationFn: () => createUser(nuEmail, nuPassword),
    onMutate: clearActionToast,
    onSuccess: () => {
      setNuEmail("");
      setNuPassword("");
      setNuError(null);
      queryClient.invalidateQueries({ queryKey: ["users"] });
      showSuccessToast("User created");
    },
    onError: (err) => {
      const message = errorMessage(err);
      setNuError(message);
      showErrorToast(message);
    }
  });
  const deleteUserMut = useMutation({
    mutationFn: deleteUser,
    onMutate: clearActionToast,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      showSuccessToast("User deleted");
    },
    onError: (err) => showErrorToast(errorMessage(err))
  });
  const feedRefresh = useMutation({
    mutationFn: refreshThreatFeed,
    onMutate: clearActionToast,
    onSuccess: () => {
      setRefreshError(null);
      showSuccessToast("Refresh successful");
      queryClient.invalidateQueries({ queryKey: ["threatfeed-status"] });
    },
    onError: (err) => {
      const message = errorMessage(err);
      setRefreshError(message);
      showErrorToast(message);
    }
  });
  const notificationTest = useMutation({
    mutationFn: testNotifications,
    onMutate: () => {
      clearActionToast();
      setNotificationError(null);
    },
    onSuccess: (results) => {
      const failures = results.filter((result) => !result.ok);
      if (failures.length) {
        const message = failures
          .map((result) => `${result.channel}: ${result.error ?? "Delivery failed"}`)
          .join("; ");
        setNotificationError(message);
        showErrorToast("Notification test failed");
        return;
      }
      showSuccessToast("Test notification sent");
    },
    onError: (err) => {
      const message = errorMessage(err);
      setNotificationError(message);
      showErrorToast(message);
    }
  });

  useEffect(() => {
    if (settings.data) setDraft({ ...defaults, ...settings.data });
  }, [settings.data]);

  const availableZoneNames = new Set((zonesQuery.data ?? []).map((z) => z.name));
  const rawZones = parseZones(draft["threat_feed.zones"]);
  const zones = zonesQuery.isSuccess ? normalizeZoneNames(rawZones, availableZoneNames) : rawZones;
  const setValue = (key: string, value: string) => setDraft((current) => ({ ...current, [key]: value }));
  const toggleZone = (zone: string) => {
    const next = zones.includes(zone) ? zones.filter((item) => item !== zone) : [...zones, zone];
    setValue("threat_feed.zones", JSON.stringify(next));
  };
  const handleChangePw = (event: React.FormEvent) => {
    event.preventDefault();
    setCpError(null);
    if (cpNew !== cpConfirm) {
      setCpError("Passwords do not match");
      return;
    }
    if (cpNew.length < 12) {
      setCpError("Password must be at least 12 characters");
      return;
    }
    changePw.mutate();
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">Settings</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">UniFi connection, monitoring, and enforcement controls.</p>
        </div>
        <Button
          className="inline-flex items-center gap-2"
          variant="primary"
          onClick={() => save.mutate(draft)}
        >
          <Save className="h-4 w-4" />
          Save Settings
        </Button>
      </header>

      <Card title="UniFi Connection">
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            Host URL
            <input
              className={`${fieldClass} font-mono`}
              placeholder="https://192.168.1.1"
              value={draft["unifi.host"]}
              onChange={(event) => setValue("unifi.host", event.target.value)}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            API Key
            <div className="flex gap-2">
              <input
                className={`min-w-0 flex-1 ${fieldClass} font-mono`}
                type={showKey ? "text" : "password"}
                placeholder="••••••••••••••••"
                value={draft["unifi.api_key"]}
                onChange={(event) => setValue("unifi.api_key", event.target.value)}
              />
              <Button
                type="button"
                className="px-2 text-slate-500"
                onClick={() => setShowKey((prev) => !prev)}
                title={showKey ? "Hide key" : "Show key"}
              >
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
            </div>
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            Site
            <input
              className={`${fieldClass} font-mono`}
              placeholder="default"
              value={draft["unifi.site"]}
              onChange={(event) => setValue("unifi.site", event.target.value)}
            />
          </label>
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700 dark:text-slate-300 md:pt-6">
            <input
              type="checkbox"
              checked={draft["unifi.verify_ssl"] === "true"}
              onChange={(event) => setValue("unifi.verify_ssl", String(event.target.checked))}
            />
            Verify SSL certificate
          </label>
        </div>
        <p className="mt-3 text-xs text-slate-400">
          API key is stored in the application database. Changes take effect on the next poll cycle.
        </p>
      </Card>

      <Card title="Data Retention">
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          {[
            ["retention.firewall_logs_days", "Firewall logs"],
            ["retention.threat_events_days", "Threat events"],
            ["retention.scan_results_days", "Scan results"],
            ["retention.assessment_runs_days", "Assessment runs"]
          ].map(([key, label]) => (
            <label key={key} className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
              {label} (days)
              <input
                className={fieldClass}
                type="number"
                min="0"
                max="3650"
                step="1"
                value={draft[key]}
                onChange={(event) => setValue(key, event.target.value)}
              />
              <span className="text-xs font-normal text-slate-400">0 keeps records forever</span>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Proxy">
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={draft["http_proxy.enabled"] === "true"}
              onChange={(event) => setValue("http_proxy.enabled", String(event.target.checked))}
            />
            Enable HTTP proxy
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            Proxy URL
            <input
              className={`${fieldClass} font-mono`}
              value={draft["http_proxy.url"]}
              onChange={(event) => setValue("http_proxy.url", event.target.value)}
              placeholder="http://proxy.example.local:8080"
            />
          </label>
        </div>
      </Card>

      <Card
        title="CVE Monitoring"
        action={
          <Button
            className="inline-flex items-center gap-2"
            onClick={() => cveRefresh.mutate()}
          >
            <ShieldCheck className="h-4 w-4" />
            Run Now
          </Button>
        }
      >
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={draft["cve_monitoring.enabled"] === "true"}
              onChange={(event) => setValue("cve_monitoring.enabled", String(event.target.checked))}
            />
            Enable CVE monitoring
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            Poll interval
            <select
              className={fieldClass}
              value={draft["cve_monitoring.poll_interval_hours"]}
              onChange={(event) => setValue("cve_monitoring.poll_interval_hours", event.target.value)}
            >
              <option value="6">Every 6 hours</option>
              <option value="12">Every 12 hours</option>
              <option value="24">Every 24 hours</option>
            </select>
          </label>
        </div>
      </Card>

      <Card
        title="Threat Feed"
        action={
          <Button
            className="inline-flex items-center gap-2"
            onClick={() => feedRefresh.mutate()}
          >
            <ShieldCheck className="h-4 w-4" />
            Run Now
          </Button>
        }
      >
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={draft["threat_feed.enabled"] === "true"}
              onChange={(event) => setValue("threat_feed.enabled", String(event.target.checked))}
            />
            Enable threat feed
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            Poll interval
            <select
              className={fieldClass}
              value={draft["threat_feed.poll_interval_hours"]}
              onChange={(event) => setValue("threat_feed.poll_interval_hours", event.target.value)}
            >
              <option value="1">Every hour</option>
              <option value="4">Every 4 hours</option>
              <option value="8">Every 8 hours</option>
              <option value="24">Every 24 hours</option>
            </select>
          </label>
        </div>
        <div className="mt-4">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Apply mode</span>
          <div className="mt-2 inline-flex rounded-md border border-slate-300 p-1 dark:border-slate-700">
            {[
              ["preview", "Manual"],
              ["auto", "Auto Push"]
            ].map(([value, label]) => (
              <Button
                key={value}
                variant="quiet"
                className={`px-3 py-1.5 ${
                  draft["threat_feed.apply_mode"] === value ? "bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300" : "text-slate-700 dark:text-slate-300"
                }`}
                onClick={() => setValue("threat_feed.apply_mode", value)}
              >
                {label}
              </Button>
            ))}
          </div>
        </div>
        <div className="mt-4">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Direction</span>
          <div className="mt-2 inline-flex rounded-md border border-slate-300 p-1 dark:border-slate-700">
            {[
              ["inbound", "Inbound"],
              ["bidirectional", "Bidirectional"]
            ].map(([value, label]) => (
              <Button
                key={value}
                variant="quiet"
                className={`px-3 py-1.5 ${
                  draft["threat_feed.direction_mode"] === value ? "bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300" : "text-slate-700 dark:text-slate-300"
                }`}
                onClick={() => setValue("threat_feed.direction_mode", value)}
              >
                {label}
              </Button>
            ))}
          </div>
        </div>
        <fieldset className="mt-4">
          <legend className="text-sm font-medium text-slate-700 dark:text-slate-300">
            Target zones
            {zonesQuery.isSuccess && zonesQuery.data.length > 0 && (
              <span className="ml-2 text-xs font-normal text-slate-400">(from UniFi)</span>
            )}
          </legend>
          {zonesQuery.isLoading ? (
            <p className="mt-2 text-xs text-slate-400">Loading zones…</p>
          ) : zonesQuery.isSuccess && zonesQuery.data.length > 0 ? (
            <div className="mt-2 grid gap-2 md:grid-cols-3">
              {zonesQuery.data.map((zone) => (
                <label key={zone.name} className="flex items-center gap-3 rounded border border-slate-200 p-3 text-sm dark:border-slate-700">
                  <input type="checkbox" checked={zones.includes(zone.name)} onChange={() => toggleZone(zone.name)} />
                  <span>{zone.name}</span>
                </label>
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs text-slate-400">
              Zone list unavailable — check UniFi connection settings and ensure the device is reachable.
            </p>
          )}
        </fieldset>
      </Card>
      <Card
        title="Notifications"
        action={
          <Button
            className="inline-flex items-center gap-2"
            disabled={notificationTest.isPending}
            onClick={() => notificationTest.mutate()}
          >
            <Bell className="h-4 w-4" />
            {notificationTest.isPending ? "Sending…" : "Send test notification"}
          </Button>
        }
      >
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={draft["notifications.enabled"] === "true"}
              onChange={(event) => setValue("notifications.enabled", String(event.target.checked))}
            />
            Enable notifications
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            Severity threshold
            <select
              className={fieldClass}
              value={draft["notifications.severity_threshold"]}
              onChange={(event) => setValue("notifications.severity_threshold", event.target.value)}
            >
              <option value="critical">Critical only</option>
              <option value="warning">Critical + warning</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            ntfy topic URL
            <input
              className={`${fieldClass} font-mono`}
              value={draft["notifications.ntfy_url"]}
              onChange={(event) => setValue("notifications.ntfy_url", event.target.value)}
              placeholder="https://ntfy.sh/my-topic"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            ntfy access token
            <input
              className={`${fieldClass} font-mono`}
              type="password"
              value={draft["notifications.ntfy_token"]}
              onChange={(event) => setValue("notifications.ntfy_token", event.target.value)}
              placeholder="Optional access token"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700 dark:text-slate-300 md:col-span-2">
            Webhook URL
            <input
              className={`${fieldClass} font-mono`}
              value={draft["notifications.webhook_url"]}
              onChange={(event) => setValue("notifications.webhook_url", event.target.value)}
              placeholder="https://automation.example.com/hooks/unifi"
            />
          </label>
        </div>
        {notificationError ? (
          <p className="mt-3 text-xs text-rose-600 dark:text-rose-400">{notificationError}</p>
        ) : null}
      </Card>
      <Card title="Appearance">
        <div className="flex gap-2">
          {(["light", "dark"] as const).map((nextTheme) => (
            <Button
              key={nextTheme}
              type="button"
              onClick={() => themeMutation.mutate(nextTheme)}
              disabled={theme === nextTheme || themeMutation.isPending}
              variant="quiet"
              className={`px-4 py-2 ${
                theme === nextTheme
                  ? "bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300"
                  : "border border-slate-300 text-slate-700 hover:bg-slate-100 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-800"
              }`}
            >
              {nextTheme === "light" ? "Light" : "Dark"}
            </Button>
          ))}
        </div>
      </Card>
      <Card title="Change Password">
        <form onSubmit={handleChangePw} className="mt-4 space-y-3">
          <div>
            <label className={`mb-1 block ${labelClass}`}>Current password</label>
            <input
              type="password"
              value={cpCurrent}
              onChange={(event) => setCpCurrent(event.target.value)}
              required
              className={compactFieldClass}
            />
          </div>
          <div>
            <label className={`mb-1 block ${labelClass}`}>
              New password <span className="text-slate-400">(min 12 characters)</span>
            </label>
            <input
              type="password"
              value={cpNew}
              onChange={(event) => setCpNew(event.target.value)}
              required
              className={compactFieldClass}
            />
          </div>
          <div>
            <label className={`mb-1 block ${labelClass}`}>Confirm new password</label>
            <input
              type="password"
              value={cpConfirm}
              onChange={(event) => setCpConfirm(event.target.value)}
              required
              className={compactFieldClass}
            />
          </div>
          {cpError ? <p className="text-xs text-rose-600 dark:text-rose-400">{cpError}</p> : null}
          <Button
            type="submit"
            disabled={changePw.isPending}
            variant="primary"
            className="px-4 py-1.5"
          >
            {changePw.isPending ? "Saving..." : "Change password"}
          </Button>
        </form>
      </Card>
      {isSuperuser ? (
        <Card title="User Management">
          <div className="mt-4 mb-6 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className={tableHeadClass}>
                <tr className="text-left">
                  <th className="p-2 pr-4">Email</th>
                  <th className="p-2 pr-4">Role</th>
                  <th className="p-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(usersQuery.data ?? []).map((user) => (
                  <tr key={user.id} className="border-b border-slate-100 dark:border-slate-800">
                    <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{user.email}</td>
                    <td className="py-2 pr-4 text-slate-500 dark:text-slate-400">
                      {user.is_superuser ? "Admin" : "User"}
                    </td>
                    <td className="py-2">
                      <Button
                        type="button"
                        disabled={user.id === meQuery.data?.id || deleteUserMut.isPending}
                        onClick={() => {
                          if (window.confirm(`Delete ${user.email}?`)) {
                            deleteUserMut.mutate(user.id);
                          }
                        }}
                        className="border-rose-300 px-2 py-1 text-xs text-rose-600 hover:bg-rose-50 disabled:opacity-40 dark:border-rose-800 dark:text-rose-400 dark:hover:bg-rose-950"
                      >
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {usersQuery.isLoading ? <p className="mt-2 text-xs text-slate-400">Loading...</p> : null}
          </div>

          <h3 className="mb-3 text-xs font-semibold text-slate-600 dark:text-slate-400">Add user</h3>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              setNuError(null);
              createUserMut.mutate();
            }}
            className="space-y-3"
          >
            <div>
              <label className={`mb-1 block ${labelClass}`}>Email</label>
              <input
                type="email"
                value={nuEmail}
                onChange={(event) => setNuEmail(event.target.value)}
                required
                className={compactFieldClass}
              />
            </div>
            <div>
              <label className={`mb-1 block ${labelClass}`}>
                Password <span className="text-slate-400">(min 12 characters)</span>
              </label>
              <input
                type="password"
                value={nuPassword}
                onChange={(event) => setNuPassword(event.target.value)}
                required
                className={compactFieldClass}
              />
            </div>
            {nuError ? <p className="text-xs text-rose-600 dark:text-rose-400">{nuError}</p> : null}
            <Button
              type="submit"
              disabled={createUserMut.isPending}
              variant="primary"
              className="px-4 py-1.5"
            >
              {createUserMut.isPending ? "Creating..." : "Create user"}
            </Button>
          </form>
        </Card>
      ) : null}
      {save.error ? <p className="text-sm text-rose-700 dark:text-rose-400">{String(save.error)}</p> : null}
      {refreshError ? <p className="text-sm text-rose-700 dark:text-rose-400">{refreshError}</p> : null}
    </div>
  );
}

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

function parseZones(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}
