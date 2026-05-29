import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Plus, ShieldBan, Trash2, X } from "lucide-react";
import { clearActionToast, showErrorToast, showSuccessToast } from "../components/ActionToast";
import {
  addThreatFeedSource,
  approveThreatFeedRule,
  deleteThreatFeedSource,
  getThreatFeedEntries,
  getThreatFeedPendingRules,
  getThreatFeedSources,
  getThreatFeedStatus,
  refreshThreatFeed,
  rejectThreatFeedRule,
  updateThreatFeedSource
} from "../lib/api";

export function ThreatFeeds() {
  const queryClient = useQueryClient();
  const [cidrSearch, setCidrSearch] = useState("");
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const status = useQuery({
    queryKey: ["threatfeed-status"],
    queryFn: getThreatFeedStatus,
    refetchInterval: 30000
  });
  const feeds = useQuery({ queryKey: ["threatfeed-feeds"], queryFn: getThreatFeedSources });
  const entries = useQuery({
    queryKey: ["threatfeed-entries", cidrSearch],
    queryFn: () => getThreatFeedEntries({ cidr: cidrSearch, limit: 100 })
  });
  const pending = useQuery({ queryKey: ["threatfeed-pending"], queryFn: getThreatFeedPendingRules });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["threatfeed-status"] });
    queryClient.invalidateQueries({ queryKey: ["threatfeed-feeds"] });
    queryClient.invalidateQueries({ queryKey: ["threatfeed-entries"] });
    queryClient.invalidateQueries({ queryKey: ["threatfeed-pending"] });
  };
  const addFeed = useMutation({
    mutationFn: () => addThreatFeedSource(newName, newUrl),
    onSuccess: () => {
      setNewName("");
      setNewUrl("");
      invalidate();
    }
  });
  const updateFeed = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => updateThreatFeedSource(id, { enabled }),
    onSuccess: invalidate
  });
  const removeFeed = useMutation({ mutationFn: deleteThreatFeedSource, onSuccess: invalidate });
  const onActionError = (err: unknown) => {
    const message = errorMessage(err);
    setActionError(message);
    showErrorToast(message);
  };
  const onActionSuccess = () => { setActionError(null); invalidate(); };

  const refresh = useMutation({
    mutationFn: refreshThreatFeed,
    onMutate: clearActionToast,
    onSuccess: () => {
      onActionSuccess();
      showSuccessToast("Refresh successful");
    },
    onError: onActionError
  });
  const onRuleActionSuccess = (data: { status: string; error: string | null }, successMessage: string) => {
    invalidate();
    if (data.status === "failed") {
      const message = data.error ?? "Rule failed to apply to UniFi";
      setActionError(message);
      showErrorToast(message);
    } else {
      setActionError(null);
      showSuccessToast(successMessage);
    }
  };

  const approve = useMutation({
    mutationFn: approveThreatFeedRule,
    onMutate: clearActionToast,
    onSuccess: (data) => onRuleActionSuccess(data, "Rule applied successfully"),
    onError: onActionError
  });
  const reject = useMutation({
    mutationFn: rejectThreatFeedRule,
    onMutate: clearActionToast,
    onSuccess: (data) => onRuleActionSuccess(data, "Rule rejected successfully"),
    onError: onActionError
  });

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-950">Threat Feeds</h1>
          <p className="mt-1 text-sm text-slate-500">External blocklist ingestion and UniFi enforcement state.</p>
        </div>
        <button
          className="inline-flex items-center gap-2 rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
          onClick={() => refresh.mutate()}
        >
          <ShieldBan className="h-4 w-4" />
          Refresh
        </button>
      </header>

      <section className="grid gap-3 rounded-md border border-slate-200 bg-white p-4 text-sm md:grid-cols-6">
        <span className={status.data?.enabled ? "font-semibold text-emerald-700" : "font-semibold text-slate-500"}>
          {status.data?.enabled ? "Active" : "Disabled"}
        </span>
        <span>Mode: {status.data?.apply_mode === "auto" ? "Auto Push" : "Preview"}</span>
        <span>Direction: {status.data?.direction_mode === "bidirectional" ? "Bidirectional" : "Inbound"}</span>
        <span>Last updated: {formatDate(status.data?.last_updated)}</span>
        <span>{(status.data?.total_entries ?? 0).toLocaleString()} IPs</span>
        <span>{status.data?.pending_count ?? 0} pending approvals</span>
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Pending Rule Changes</h2>
        {actionError ? (
          <p className="mt-3 rounded bg-rose-50 px-3 py-2 text-sm text-rose-700">{actionError}</p>
        ) : null}
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr>
                <th className="p-2">Action</th>
                <th>Ruleset</th>
                <th>Direction</th>
                <th>Rule</th>
                <th>Entries</th>
                <th>Created</th>
                <th>Status</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {(pending.data ?? []).map((rule) => (
                <tr key={rule.id} className="border-t border-slate-100 align-top">
                  <td className="p-2 uppercase">{rule.action}</td>
                  <td className="p-2 font-mono text-xs">{rule.ruleset}</td>
                  <td className="p-2 capitalize">{rule.direction}</td>
                  <td className="p-2">{rule.rule_name}</td>
                  <td className="p-2">{rule.entry_count.toLocaleString()}</td>
                  <td className="p-2">{formatDate(rule.created_at)}</td>
                  <td className="p-2">
                    <span className={statusClass(rule.status)}>{rule.status}</span>
                    {rule.status === "failed" && rule.error ? (
                      <p className="mt-1 max-w-xs text-xs text-rose-700">{rule.error}</p>
                    ) : null}
                  </td>
                  <td className="flex gap-2 py-2">
                    {rule.status === "pending" ? (
                      <>
                        <button
                          className="inline-flex items-center gap-1 rounded border border-emerald-300 px-2 py-1 text-sm text-emerald-700 hover:bg-emerald-50 disabled:opacity-50"
                          disabled={approve.isPending || reject.isPending}
                          onClick={() => approve.mutate(rule.id)}
                        >
                          <Check className="h-4 w-4" />
                          {approve.isPending ? "Approving…" : "Approve"}
                        </button>
                        <button
                          className="inline-flex items-center gap-1 rounded border border-rose-300 px-2 py-1 text-sm text-rose-700 hover:bg-rose-50 disabled:opacity-50"
                          disabled={approve.isPending || reject.isPending}
                          onClick={() => reject.mutate(rule.id)}
                        >
                          <X className="h-4 w-4" />
                          {reject.isPending ? "Rejecting…" : "Reject"}
                        </button>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
              {!pending.data?.length ? (
                <tr className="border-t border-slate-100">
                  <td className="p-2 text-slate-500" colSpan={8}>No pending rule changes</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-lg font-semibold text-slate-950">Feed Sources</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr>
                <th className="p-2">Name</th>
                <th>URL</th>
                <th>Enabled</th>
                <th>Last Polled</th>
                <th>Entries</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(feeds.data ?? []).map((feed) => (
                <tr key={feed.id} className="border-t border-slate-100 align-top">
                  <td className="p-2 font-medium">{feed.name}</td>
                  <td className="max-w-sm truncate font-mono text-xs">{feed.url}</td>
                  <td>
                    <input
                      type="checkbox"
                      checked={feed.enabled}
                      onChange={() => updateFeed.mutate({ id: feed.id, enabled: !feed.enabled })}
                    />
                  </td>
                  <td>{formatDate(feed.last_polled_at)}</td>
                  <td>{feed.last_entry_count.toLocaleString()}</td>
                  <td>{feed.last_error ? <span className="text-rose-700">{feed.last_error}</span> : "OK"}</td>
                  <td>
                    <button
                      className="rounded p-1 text-slate-600 hover:bg-slate-100"
                      title="Remove feed"
                      onClick={() => removeFeed.mutate(feed.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 grid gap-2 md:grid-cols-[1fr_2fr_auto_auto_auto]">
          <input
            className="rounded border border-slate-300 px-3 py-2 text-sm"
            placeholder="Name"
            value={newName}
            onChange={(event) => setNewName(event.target.value)}
          />
          <input
            className="rounded border border-slate-300 px-3 py-2 font-mono text-sm"
            placeholder="https://example.com/feed.netset"
            value={newUrl}
            onChange={(event) => setNewUrl(event.target.value)}
          />
          <button
            className="rounded border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50"
            onClick={() => {
              setNewName("FireHOL Level 1");
              setNewUrl("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset");
            }}
          >
            FireHOL
          </button>
          <button
            className="rounded border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50"
            onClick={() => {
              setNewName("Spamhaus DROP");
              setNewUrl("https://www.spamhaus.org/drop/drop_v4.json");
            }}
          >
            Spamhaus
          </button>
          <button
            className="inline-flex items-center justify-center gap-2 rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
            onClick={() => addFeed.mutate()}
          >
            <Plus className="h-4 w-4" />
            Add
          </button>
        </div>
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-slate-950">Blocked Entries</h2>
          <input
            className="rounded border border-slate-300 px-3 py-2 font-mono text-sm"
            placeholder="Search CIDR"
            value={cidrSearch}
            onChange={(event) => setCidrSearch(event.target.value)}
          />
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr>
                <th className="p-2">CIDR</th>
                <th>Feed Source</th>
                <th>Added</th>
              </tr>
            </thead>
            <tbody>
              {(entries.data?.items ?? []).map((entry) => (
                <tr key={entry.id} className="border-t border-slate-100">
                  <td className="p-2 font-mono text-xs">{entry.cidr}</td>
                  <td>{entry.feed_source_name}</td>
                  <td>{formatDate(entry.added_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function formatDate(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "-";
}

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

function statusClass(status: string) {
  if (status === "applied") return "text-xs font-medium text-emerald-700";
  if (status === "failed") return "text-xs font-medium text-rose-700";
  if (status === "rejected") return "text-xs font-medium text-slate-400";
  return "text-xs font-medium text-slate-600";
}
