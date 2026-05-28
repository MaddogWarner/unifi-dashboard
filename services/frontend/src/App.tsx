import { useQuery } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";
import { Footer } from "./components/Footer";
import { NavBar } from "./components/NavBar";
import { getAssessment, getDriftSnapshots } from "./lib/api";
import { Assessment } from "./pages/Assessment";
import { CVEAlerts } from "./pages/CVEAlerts";
import { Dashboard } from "./pages/Dashboard";
import { Firewall } from "./pages/Firewall";
import { Scanner } from "./pages/Scanner";
import { Settings } from "./pages/Settings";
import { ThreatFeeds } from "./pages/ThreatFeeds";
import { Threats } from "./pages/Threats";
import { VLANs } from "./pages/VLANs";

export default function App() {
  const assessment = useQuery({ queryKey: ["assessment"], queryFn: getAssessment });
  const drift = useQuery({ queryKey: ["drift-snapshots"], queryFn: getDriftSnapshots });
  const alert = Boolean((assessment.data?.fail_count ?? 0) > 0 || (drift.data?.length ?? 0) > 1);

  return (
    <div className="flex min-h-screen flex-col bg-slate-50">
      <NavBar alert={alert} />
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/firewall" element={<Firewall />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/cve" element={<CVEAlerts />} />
          <Route path="/threatfeeds" element={<ThreatFeeds />} />
          <Route path="/vlans" element={<VLANs />} />
          <Route path="/assessment" element={<Assessment />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}
