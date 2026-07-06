import { useSearchParams } from "react-router-dom";

import { PageTabs } from "../components/PageTabs";
import { LogsTab } from "./firewall/LogsTab";
import { OverviewTab } from "./firewall/OverviewTab";
import { PoliciesTab } from "./firewall/PoliciesTab";

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "policies", label: "Policies" },
  { id: "logs", label: "Logs" }
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
      <PageTabs tabs={tabs} active={activeTab} onChange={handleTabChange} />
      {activeTab === "overview" ? <OverviewTab onMatrixSelect={handleMatrixSelect} /> : null}
      {activeTab === "policies" ? <PoliciesTab /> : null}
      {activeTab === "logs" ? <LogsTab /> : null}
    </div>
  );
}
