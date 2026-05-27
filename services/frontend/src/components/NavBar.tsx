import { Activity, ClipboardCheck, LayoutDashboard, ListChecks, Network, Radar, Shield } from "lucide-react";
import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/firewall", label: "Firewall", icon: Shield },
  { to: "/threats", label: "Threats", icon: Activity },
  { to: "/vlans", label: "VLANs", icon: Network },
  { to: "/assessment", label: "Assessment", icon: ClipboardCheck },
  { to: "/scanner", label: "Scanner", icon: Radar }
];

export function NavBar({ alert }: { alert: boolean }) {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
        <div className="flex items-center gap-2 font-semibold text-slate-950">
          <ListChecks className="h-5 w-5 text-teal-700" />
          <span>UniFi Security Dashboard</span>
          {alert ? <span className="h-2 w-2 rounded-full bg-rose-500" title="Assessment or drift alert" /> : null}
        </div>
        <nav className="flex flex-wrap gap-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-2 rounded px-3 py-2 text-sm font-medium ${
                  isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
      </div>
    </header>
  );
}
