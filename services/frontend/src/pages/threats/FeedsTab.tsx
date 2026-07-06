import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Plus, ShieldBan, Trash2, X } from "lucide-react";
import { clearActionToast, showErrorToast, showSuccessToast } from "../../components/ActionToast";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
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
} from "../../lib/api";
import type { ThreatFeedSource, ThreatFeedUpdatePayload } from "../../lib/api";

const fieldClass =
  "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100";
const tableHeadClass = "bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900/50 dark:text-slate-400";

export function FeedsTab() {
  const queryClient = useQueryClient();
  const [cidrSearch, setCidrSearch] = useState("");
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newSourceType, setNewSourceType] = useState<"url" | "misp">("url");
  const [newApiKey, setNewApiKey] = useState("");
  const [newMispVerifySsl, setNewMispVerifySsl] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [editingFeedId, setEditingFeedId] = useState<number | null>(null);
  const [editApiKey, setEditApiKey] = useState("");
  const [editVerifySsl, setEditVerifySsl] = useState(false);
  const [credentialError, setCredentialError] = useState<string | null>(null);
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
  const pending = useQuery({
    queryKey: ["threatfeed-pending"],
    queryFn: getThreatFeedPendingRules,
    refetchInterval: 30000
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["threatfeed-status"] });
    queryClient.invalidateQueries({ queryKey: ["threatfeed-feeds"] });
    queryClient.invalidateQueries({ queryKey: ["threatfeed-entries"] });
    queryClient.invalidateQueries({ queryKey: ["threatfeed-pending"] });
  };
  const addFeed = useMutation({
    mutationFn: () =>
      addThreatFeedSource({
        name: newName,
        url: newUrl,
        source_type: newSourceType,
        api_key: newSourceType === "misp" ? newApiKey : undefined,
        misp_verify_ssl: newSourceType === "misp" ? newMispVerifySsl : undefined
      }),
    onSuccess: () => {
      setNewName("");
      setNewUrl("");
      setNewApiKey("");
      setNewMispVerifySsl(false);
      setNewSourceType("url");
      invalidate();
    }
  });
  const updateFeed = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => updateThreatFeedSource(id, { enabled }),
    onSuccess: invalidate
  });
  const updateCredentials = useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: ThreatFeedUpdatePayload }) =>
      updateThreatFeedSource(id, payload),
    onSuccess: () => {
      setEditingFeedId(null);
      setEditApiKey("");
      setCredentialError(null);
      invalidate();
    },
    onError: (err) => setCredentialError(errorMessage(err))
  });
  const removeFeed = useMutation({ mutationFn: deleteThreatFeedSource, onSuccess: invalidate });
  const onActionError = (err: unknown) => {
    const message = errorMessage(err);
    setActionError(message);
    showErrorToast(message);
    // Refetch so the list reflects true server state: a request cut by a timeout
    // may still have applied server-side, and a failed approve stays retryable.
    invalidate();
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

  function openCredentialEdit(feed: ThreatFeedSource) {
    setEditingFeedId(feed.id);
    setEditApiKey("");
    setEditVerifySsl(Boolean(feed.misp_verify_ssl));
    setCredentialError(null);
  }

  function closeCredentialEdit() {
    setEditingFeedId(null);
    setEditApiKey("");
    setCredentialError(null);
  }

  function saveCredentials(feed: ThreatFeedSource) {
    const payload: ThreatFeedUpdatePayload = {};
    const trimmedKey = editApiKey.trim();
    if (trimmedKey) payload.api_key = trimmedKey;
    if (editVerifySsl !== Boolean(feed.misp_verify_ssl)) {
      payload.misp_verify_ssl = editVerifySsl;
    }
    if (Object.keys(payload).length === 0) {
      closeCredentialEdit();
      return;
    }
    updateCredentials.mutate({ id: feed.id, payload });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-end gap-3">
        <Button
          className="inline-flex items-center gap-2"
          variant="primary"
          onClick={() => refresh.mutate()}
        >
          <ShieldBan className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      <Card>
        <div className="grid gap-3 text-sm md:grid-cols-6">
          <span className={status.data?.enabled ? "font-semibold text-emerald-700" : "font-semibold text-slate-500"}>
            {status.data?.enabled ? "Active" : "Disabled"}
          </span>
          <span>Mode: {status.data?.apply_mode === "auto" ? "Auto Push" : "Manual"}</span>
          <span>Direction: {status.data?.direction_mode === "bidirectional" ? "Bidirectional" : "Inbound"}</span>
          <span>Last updated: {formatDate(status.data?.last_updated)}</span>
          <span>{(status.data?.total_entries ?? 0).toLocaleString()} IPs</span>
          <span>{status.data?.pending_count ?? 0} pending approvals</span>
        </div>
      </Card>

      <Card title="Pending Rule Changes">
        {actionError ? (
          <p className="mt-3 rounded bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">{actionError}</p>
        ) : null}
        {pending.error ? (
          <p className="mt-3 rounded bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">
            {errorMessage(pending.error)}
          </p>
        ) : null}
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className={tableHeadClass}>
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
                <tr key={rule.id} className="border-t border-slate-100 align-top dark:border-slate-800">
                  <td className="p-2 uppercase">{rule.action}</td>
                  <td className="p-2 font-mono text-xs">{rule.ruleset}</td>
                  <td className="p-2 capitalize">{rule.direction}</td>
                  <td className="p-2">{rule.rule_name}</td>
                  <td className="p-2">{rule.entry_count.toLocaleString()}</td>
                  <td className="p-2">{formatDate(rule.created_at)}</td>
                  <td className="p-2">
                    <span className={statusClass(rule.status)}>{rule.status}</span>
                    {rule.status === "failed" && rule.error ? (
                      <p className="mt-1 max-w-xs text-xs text-rose-700 dark:text-rose-400">{rule.error}</p>
                    ) : null}
                  </td>
                  <td className="flex gap-2 py-2">
                    {rule.status === "pending" ? (
                      <>
                        <Button
                          className="inline-flex items-center gap-1 border-emerald-300 px-2 py-1 text-emerald-700 hover:bg-emerald-50 dark:border-emerald-800 dark:text-emerald-300 dark:hover:bg-emerald-950"
                          disabled={approve.isPending || reject.isPending}
                          onClick={() => approve.mutate(rule.id)}
                        >
                          <Check className="h-4 w-4" />
                          {approve.isPending ? "Approving…" : "Approve"}
                        </Button>
                        <Button
                          className="inline-flex items-center gap-1 border-rose-300 px-2 py-1 text-rose-700 hover:bg-rose-50 dark:border-rose-800 dark:text-rose-300 dark:hover:bg-rose-950"
                          disabled={approve.isPending || reject.isPending}
                          onClick={() => reject.mutate(rule.id)}
                        >
                          <X className="h-4 w-4" />
                          {reject.isPending ? "Rejecting…" : "Reject"}
                        </Button>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
              {!pending.data?.length ? (
                <tr className="border-t border-slate-100 dark:border-slate-800">
                  <td className="p-2 text-slate-500" colSpan={8}>No pending rule changes</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Feed Sources">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className={tableHeadClass}>
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
                <Fragment key={feed.id}>
                  <tr className="border-t border-slate-100 align-top dark:border-slate-800">
                    <td className="p-2 font-medium">
                      {feed.name}
                      {feed.source_type === "misp" ? (
                        <span className="ml-2 rounded bg-violet-100 px-1.5 py-0.5 text-xs font-medium text-violet-800 dark:bg-violet-900 dark:text-violet-200">
                          MISP
                        </span>
                      ) : null}
                    </td>
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
                      <div className="flex flex-wrap items-center gap-2">
                        {feed.source_type === "misp" ? (
                          <Button
                            variant="quiet"
                            className="px-2 py-1 text-xs text-slate-600 dark:text-slate-400"
                            onClick={() => openCredentialEdit(feed)}
                          >
                            Edit credentials
                          </Button>
                        ) : null}
                        <Button
                          variant="quiet"
                          className="p-1 text-slate-600 dark:text-slate-400"
                          title="Remove feed"
                          onClick={() => removeFeed.mutate(feed.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                  {editingFeedId === feed.id ? (
                    <tr className="border-t border-slate-100 bg-slate-50/60 dark:border-slate-800 dark:bg-slate-900/40">
                      <td className="p-3" colSpan={7}>
                        <div className="grid gap-3 md:grid-cols-[minmax(0,2fr)_auto_auto_auto]">
                          <input
                            className={`${fieldClass} font-mono`}
                            placeholder="Leave blank to keep current key"
                            type="password"
                            value={editApiKey}
                            onChange={(event) => setEditApiKey(event.target.value)}
                          />
                          <label className="flex items-center justify-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:text-slate-300">
                            <input
                              type="checkbox"
                              checked={editVerifySsl}
                              onChange={(event) => setEditVerifySsl(event.target.checked)}
                            />
                            Verify SSL
                          </label>
                          <Button
                            variant="primary"
                            disabled={updateCredentials.isPending}
                            onClick={() => saveCredentials(feed)}
                          >
                            {updateCredentials.isPending ? "Saving..." : "Save"}
                          </Button>
                          <Button variant="quiet" onClick={closeCredentialEdit}>
                            Cancel
                          </Button>
                        </div>
                        {credentialError ? (
                          <p className="mt-3 rounded bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-950 dark:text-rose-300">
                            {credentialError}
                          </p>
                        ) : null}
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 space-y-3">
          <div className="inline-flex rounded-md border border-slate-300 p-1 dark:border-slate-700">
            {(["url", "misp"] as const).map((sourceType) => (
              <Button
                key={sourceType}
                variant="quiet"
                className={`px-3 py-1.5 ${
                  newSourceType === sourceType
                    ? "bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300"
                    : "text-slate-700 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800"
                }`}
                onClick={() => setNewSourceType(sourceType)}
              >
                {sourceType === "url" ? "URL Feed" : "MISP Server"}
              </Button>
            ))}
          </div>

          {newSourceType === "url" ? (
            <div className="grid gap-2 md:grid-cols-[1fr_2fr_auto_auto_auto]">
              <input
                className={fieldClass}
                placeholder="Name"
                value={newName}
                onChange={(event) => setNewName(event.target.value)}
              />
              <input
                className={`${fieldClass} font-mono`}
                placeholder="https://example.com/feed.netset"
                value={newUrl}
                onChange={(event) => setNewUrl(event.target.value)}
              />
              <Button
                onClick={() => {
                  setNewName("FireHOL Level 1");
                  setNewUrl("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset");
                }}
              >
                FireHOL
              </Button>
              <Button
                onClick={() => {
                  setNewName("Spamhaus DROP");
                  setNewUrl("https://www.spamhaus.org/drop/drop_v4.json");
                }}
              >
                Spamhaus
              </Button>
              <Button
                className="inline-flex items-center justify-center gap-2"
                variant="primary"
                onClick={() => addFeed.mutate()}
              >
                <Plus className="h-4 w-4" />
                Add
              </Button>
            </div>
          ) : (
            <div className="grid gap-2 md:grid-cols-[1fr_2fr_2fr_auto_auto]">
              <input
                className={fieldClass}
                placeholder="Name"
                value={newName}
                onChange={(event) => setNewName(event.target.value)}
              />
              <input
                className={`${fieldClass} font-mono`}
                placeholder="https://misp.example.com"
                value={newUrl}
                onChange={(event) => setNewUrl(event.target.value)}
              />
              <input
                className={`${fieldClass} font-mono`}
                placeholder="API key"
                type="password"
                value={newApiKey}
                onChange={(event) => setNewApiKey(event.target.value)}
              />
              <label className="flex items-center justify-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:text-slate-300">
                <input
                  type="checkbox"
                  checked={newMispVerifySsl}
                  onChange={(event) => setNewMispVerifySsl(event.target.checked)}
                />
                Verify SSL
              </label>
              <Button
                className="inline-flex items-center justify-center gap-2"
                variant="primary"
                onClick={() => addFeed.mutate()}
              >
                <Plus className="h-4 w-4" />
                Add
              </Button>
            </div>
          )}
        </div>
      </Card>

      <Card
        title="Blocked Entries"
        action={
          <input
            className={`${fieldClass} font-mono`}
            placeholder="Search CIDR"
            value={cidrSearch}
            onChange={(event) => setCidrSearch(event.target.value)}
          />
        }
      >
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className={tableHeadClass}>
              <tr>
                <th className="p-2">CIDR</th>
                <th>Feed Source</th>
                <th>Added</th>
              </tr>
            </thead>
            <tbody>
              {(entries.data?.items ?? []).map((entry) => (
                <tr key={entry.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="p-2 font-mono text-xs">{entry.cidr}</td>
                  <td>{entry.feed_source_name}</td>
                  <td>{formatDate(entry.added_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
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
