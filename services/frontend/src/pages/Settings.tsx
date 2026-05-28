import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, Save, ShieldCheck } from "lucide-react";
import { getSettings, refreshCVE, refreshThreatFeed, updateSettings } from "../lib/api";

const ruleSets = [
  ["WAN_IN", "WAN Inbound"],
  ["WAN_LOCAL", "WAN Local"],
  ["LAN_IN", "LAN Inbound"],
  ["LAN_OUT", "LAN Outbound"],
  ["LAN_LOCAL", "LAN Local"],
  ["GUEST_IN", "Guest Inbound"]
];

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
  "http_proxy.enabled": "false",
  "http_proxy.url": ""
};

export function Settings() {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  const [draft, setDraft] = useState(defaults);
  const [showKey, setShowKey] = useState(false);
  const save = useMutation({
    mutationFn: updateSettings,
    onSuccess: (data) => {
      setDraft({ ...defaults, ...data });
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      queryClient.invalidateQueries({ queryKey: ["threatfeed-status"] });
    }
  });
  const cveRefresh = useMutation({ mutationFn: refreshCVE });
  const feedRefresh = useMutation({ mutationFn: refreshThreatFeed });

  useEffect(() => {
    if (settings.data) setDraft({ ...defaults, ...settings.data });
  }, [settings.data]);

  const zones = parseZones(draft["threat_feed.zones"]);
  const setValue = (key: string, value: string) => setDraft((current) => ({ ...current, [key]: value }));
  const toggleZone = (zone: string) => {
    const next = zones.includes(zone) ? zones.filter((item) => item !== zone) : [...zones, zone];
    setValue("threat_feed.zones", JSON.stringify(next));
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-950">Settings</h1>
          <p className="mt-1 text-sm text-slate-500">UniFi connection, monitoring, and enforcement controls.</p>
        </div>
        <button
          className="inline-flex items-center gap-2 rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
          onClick={() => save.mutate(draft)}
        >
          <Save className="h-4 w-4" />
          Save Settings
        </button>
      </header>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">UniFi Connection</h2>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="grid gap-1 text-sm font-medium text-slate-700">
            Host URL
            <input
              className="rounded border border-slate-300 px-3 py-2 font-mono text-sm"
              placeholder="https://192.168.1.1"
              value={draft["unifi.host"]}
              onChange={(event) => setValue("unifi.host", event.target.value)}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700">
            API Key
            <div className="flex gap-2">
              <input
                className="min-w-0 flex-1 rounded border border-slate-300 px-3 py-2 font-mono text-sm"
                type={showKey ? "text" : "password"}
                placeholder="••••••••••••••••"
                value={draft["unifi.api_key"]}
                onChange={(event) => setValue("unifi.api_key", event.target.value)}
              />
              <button
                type="button"
                className="rounded border border-slate-300 px-2 text-slate-500 hover:bg-slate-50"
                onClick={() => setShowKey((prev) => !prev)}
                title={showKey ? "Hide key" : "Show key"}
              >
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700">
            Site
            <input
              className="rounded border border-slate-300 px-3 py-2 font-mono text-sm"
              placeholder="default"
              value={draft["unifi.site"]}
              onChange={(event) => setValue("unifi.site", event.target.value)}
            />
          </label>
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700 md:pt-6">
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
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Proxy</h2>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700">
            <input
              type="checkbox"
              checked={draft["http_proxy.enabled"] === "true"}
              onChange={(event) => setValue("http_proxy.enabled", String(event.target.checked))}
            />
            Enable HTTP proxy
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700">
            Proxy URL
            <input
              className="rounded border border-slate-300 px-3 py-2 font-mono text-sm"
              value={draft["http_proxy.url"]}
              onChange={(event) => setValue("http_proxy.url", event.target.value)}
              placeholder="http://proxy.example.local:8080"
            />
          </label>
        </div>
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-slate-950">CVE Monitoring</h2>
          <button
            className="inline-flex items-center gap-2 rounded border border-slate-300 px-3 py-2 text-sm font-medium hover:bg-slate-50"
            onClick={() => cveRefresh.mutate()}
          >
            <ShieldCheck className="h-4 w-4" />
            Run Now
          </button>
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700">
            <input
              type="checkbox"
              checked={draft["cve_monitoring.enabled"] === "true"}
              onChange={(event) => setValue("cve_monitoring.enabled", String(event.target.checked))}
            />
            Enable CVE monitoring
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700">
            Poll interval
            <select
              className="rounded border border-slate-300 px-3 py-2"
              value={draft["cve_monitoring.poll_interval_hours"]}
              onChange={(event) => setValue("cve_monitoring.poll_interval_hours", event.target.value)}
            >
              <option value="6">Every 6 hours</option>
              <option value="12">Every 12 hours</option>
              <option value="24">Every 24 hours</option>
            </select>
          </label>
        </div>
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-slate-950">Threat Feed</h2>
          <button
            className="inline-flex items-center gap-2 rounded border border-slate-300 px-3 py-2 text-sm font-medium hover:bg-slate-50"
            onClick={() => feedRefresh.mutate()}
          >
            <ShieldCheck className="h-4 w-4" />
            Run Now
          </button>
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm font-medium text-slate-700">
            <input
              type="checkbox"
              checked={draft["threat_feed.enabled"] === "true"}
              onChange={(event) => setValue("threat_feed.enabled", String(event.target.checked))}
            />
            Enable threat feed
          </label>
          <label className="grid gap-1 text-sm font-medium text-slate-700">
            Poll interval
            <select
              className="rounded border border-slate-300 px-3 py-2"
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
          <span className="text-sm font-medium text-slate-700">Apply mode</span>
          <div className="mt-2 inline-flex rounded border border-slate-300 p-1">
            {[
              ["preview", "Preview"],
              ["auto", "Auto Push"]
            ].map(([value, label]) => (
              <button
                key={value}
                className={`rounded px-3 py-1.5 text-sm font-medium ${
                  draft["threat_feed.apply_mode"] === value ? "bg-slate-900 text-white" : "text-slate-700"
                }`}
                onClick={() => setValue("threat_feed.apply_mode", value)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <fieldset className="mt-4">
          <legend className="text-sm font-medium text-slate-700">Target rulesets</legend>
          <div className="mt-2 grid gap-2 md:grid-cols-3">
            {ruleSets.map(([zone, label]) => (
              <label key={zone} className="flex items-center gap-3 rounded border border-slate-200 p-3 text-sm">
                <input type="checkbox" checked={zones.includes(zone)} onChange={() => toggleZone(zone)} />
                <span>
                  {label}
                  <span className="ml-2 font-mono text-xs text-slate-500">{zone}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      </section>
      {save.error ? <p className="text-sm text-rose-700">{String(save.error)}</p> : null}
    </div>
  );
}

function parseZones(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}
