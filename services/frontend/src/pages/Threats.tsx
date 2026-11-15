import { useSearchParams } from "react-router-dom";

import { PageTabs } from "../components/PageTabs";
import { CveTab } from "./threats/CveTab";
import { EventsTab } from "./threats/EventsTab";
import { FeedsTab } from "./threats/FeedsTab";
import { PageHeader } from "../components/PageHeader";

const tabs = [
  { id: "events", label: "Events" },
  { id: "cve", label: "CVE Alerts" },
  { id: "feeds", label: "Threat Feeds" }
];

const validTabs = new Set(tabs.map((tab) => tab.id));

export function Threats() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get("tab") ?? "events";
  const activeTab = validTabs.has(requestedTab) ? requestedTab : "events";

  function handleTabChange(tab: string) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    setSearchParams(next);
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Threats" description="IDS/IPS posture, vulnerability alerts, and external blocklist enforcement." />
      <PageTabs tabs={tabs} active={activeTab} onChange={handleTabChange} />
      {activeTab === "events" ? <EventsTab /> : null}
      {activeTab === "cve" ? <CveTab /> : null}
      {activeTab === "feeds" ? <FeedsTab /> : null}
    </div>
  );
}
