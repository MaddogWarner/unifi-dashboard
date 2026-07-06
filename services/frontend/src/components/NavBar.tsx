import {
  Activity,
  ClipboardCheck,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  Network,
  Radar,
  Settings,
  Shield,
  ShieldAlert,
  ShieldBan,
  X
} from "lucide-react";
import { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";

import { Button } from "./Button";
import { useAuth } from "../contexts/AuthContext";

const links = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/firewall", label: "Firewall", icon: Shield },
  { to: "/threats", label: "Threats", icon: Activity },
  { to: "/cve", label: "CVE Alerts", icon: ShieldAlert },
  { to: "/threatfeeds", label: "Threat Feeds", icon: ShieldBan },
  { to: "/vlans", label: "VLANs", icon: Network },
  { to: "/assessment", label: "Assessment", icon: ClipboardCheck },
  { to: "/scanner", label: "Scanner", icon: Radar },
  { to: "/settings", label: "Settings", icon: Settings }
];

export function NavBar({ alert }: { alert: boolean }) {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  function handleLogout() {
    setMobileOpen(false);
    logout();
    navigate("/login");
  }

  const renderLinks = (mobile = false) =>
    links.map(({ to, label, icon: Icon }) => (
      <NavLink
        key={to}
        to={to}
        onClick={() => mobile && setMobileOpen(false)}
        className={({ isActive }) =>
          `flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
            isActive
              ? "bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300"
              : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
          }`
        }
      >
        <Icon className="h-4 w-4" />
        {label}
      </NavLink>
    ));

  return (
    <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3">
        <div className="flex items-center gap-2 font-semibold text-slate-950 dark:text-slate-50">
          <ListChecks className="h-5 w-5 text-brand-600" />
          <span>UniFi Security Dashboard</span>
          {alert ? <span className="h-2 w-2 rounded-full bg-rose-500" title="Assessment or drift alert" /> : null}
        </div>
        <nav className="hidden flex-wrap gap-1 md:flex">
          {renderLinks()}
        </nav>
        <Button
          type="button"
          onClick={handleLogout}
          className="ml-auto hidden items-center gap-2 md:flex"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </Button>
        <Button
          type="button"
          variant="quiet"
          className="ml-auto inline-flex items-center gap-2 md:hidden"
          onClick={() => setMobileOpen((current) => !current)}
          aria-expanded={mobileOpen}
          aria-controls="mobile-navigation"
          aria-label={mobileOpen ? "Close navigation menu" : "Open navigation menu"}
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </Button>
      </div>
      {mobileOpen ? (
        <div id="mobile-navigation" className="border-t border-slate-200 px-4 py-3 dark:border-slate-800 md:hidden">
          <nav className="mx-auto flex max-w-7xl flex-col gap-1">
            {renderLinks(true)}
            <Button type="button" onClick={handleLogout} className="mt-2 inline-flex items-center gap-2">
              <LogOut className="h-4 w-4" />
              Sign out
            </Button>
          </nav>
        </div>
      ) : null}
    </header>
  );
}
