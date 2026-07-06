import { useSearchParams } from "react-router-dom";

import { PageTabs } from "../components/PageTabs";
import { LogsTab } from "./firewall/LogsTab";
import { NetworksTab } from "./firewall/NetworksTab";
import { OverviewTab } from "./firewall/OverviewTab";
import { PoliciesTab } from "./firewall/PoliciesTab";

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "policies", label: "Policies" },
  { id: "logs", label: "Logs" },
  { id: "networks", label: "Networks" }
];

const validTabs = new Set(tabs.map((tab) => tab.id));

export function Firewall() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get("tab") ?? "overview";
  const activeTab = validTabs.has(requestedTab) ? requestedTab : "overview";

  function handleTabChange(tab: string) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    setSearchParams(next);
  }

  function handleMatrixSelect(pair: { src: string; dst: string }) {
    setSearchParams({ tab: "policies", src: pair.src, dst: pair.dst });
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-950 dark:text-slate-50">Firewall</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Zone policies, legacy rules, and syslog-matched firewall events.
        </p>
      </header>
      <PageTabs tabs={tabs} active={activeTab} onChange={handleTabChange} />
      {activeTab === "overview" ? <OverviewTab onMatrixSelect={handleMatrixSelect} /> : null}
      {activeTab === "policies" ? <PoliciesTab /> : null}
      {activeTab === "logs" ? <LogsTab /> : null}
      {activeTab === "networks" ? <NetworksTab /> : null}
    </div>
  );
}
