import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Footer } from "./components/Footer";
import { NavBar } from "./components/NavBar";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { useAuth } from "./contexts/AuthContext";
import { getAssessment, getDriftSnapshots, getSetupStatus } from "./lib/api";
import { Assessment } from "./pages/Assessment";
import { CVEAlerts } from "./pages/CVEAlerts";
import { Dashboard } from "./pages/Dashboard";
import { Firewall } from "./pages/Firewall";
import Login from "./pages/Login";
import { Scanner } from "./pages/Scanner";
import { Settings } from "./pages/Settings";
import Setup from "./pages/Setup";
import { ThreatFeeds } from "./pages/ThreatFeeds";
import { Threats } from "./pages/Threats";
import { VLANs } from "./pages/VLANs";

export default function App() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  const [setupChecked, setSetupChecked] = useState(false);
  const [configured, setConfigured] = useState(true);
  const assessment = useQuery({
    queryKey: ["assessment"],
    queryFn: getAssessment,
    enabled: isAuthenticated && configured
  });
  const drift = useQuery({
    queryKey: ["drift-snapshots"],
    queryFn: getDriftSnapshots,
    enabled: isAuthenticated && configured
  });
  const alert = Boolean((assessment.data?.fail_count ?? 0) > 0 || (drift.data?.length ?? 0) > 1);

  useEffect(() => {
    getSetupStatus()
      .then(({ configured: nextConfigured }) => setConfigured(nextConfigured))
      .catch(() => setConfigured(true))
      .finally(() => setSetupChecked(true));
  }, []);

  if (!setupChecked) return null;

  if (!configured) {
    return (
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    );
  }

  if (location.pathname === "/setup") {
    return <Navigate to={isAuthenticated ? "/" : "/login"} replace />;
  }

  if (location.pathname === "/login") {
    return isAuthenticated ? <Navigate to="/" replace /> : <Login />;
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-50">
      <NavBar alert={alert} />
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Routes>
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/firewall" element={<ProtectedRoute><Firewall /></ProtectedRoute>} />
          <Route path="/threats" element={<ProtectedRoute><Threats /></ProtectedRoute>} />
          <Route path="/cve" element={<ProtectedRoute><CVEAlerts /></ProtectedRoute>} />
          <Route
            path="/threatfeeds"
            element={<ProtectedRoute><ThreatFeeds /></ProtectedRoute>}
          />
          <Route path="/vlans" element={<ProtectedRoute><VLANs /></ProtectedRoute>} />
          <Route
            path="/assessment"
            element={<ProtectedRoute><Assessment /></ProtectedRoute>}
          />
          <Route path="/scanner" element={<ProtectedRoute><Scanner /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}
