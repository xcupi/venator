import React from "react";
import { Link, useLocation } from "react-router-dom";
import { ShieldAlert, LayoutDashboard, FolderGit2, ScanSearch, Bug, LogOut } from "lucide-react";
import { logout } from "@/lib/api";

const items = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, testid: "nav-dashboard" },
  { to: "/projects", label: "Projects", icon: FolderGit2, testid: "nav-projects" },
  { to: "/scans", label: "Scans", icon: ScanSearch, testid: "nav-scans" },
  { to: "/findings", label: "Findings", icon: Bug, testid: "nav-findings" },
];

export default function Sidebar() {
  const loc = useLocation();
  return (
    <aside
      data-testid="sidebar"
      className="w-64 shrink-0 border-r border-zinc-800 bg-zinc-950 text-zinc-100 flex flex-col"
      style={{ fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace" }}
    >
      <div className="px-6 py-6 border-b border-zinc-800 flex items-center gap-3">
        <ShieldAlert className="text-emerald-400" size={22} />
        <div>
          <div className="text-sm font-bold tracking-wide">reflected-xss</div>
          <div className="text-xs text-zinc-500 -mt-0.5">hunter · local</div>
        </div>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {items.map(({ to, label, icon: Icon, testid }) => {
          const active = loc.pathname === to || (to !== "/" && loc.pathname.startsWith(to));
          return (
            <Link
              key={to}
              to={to}
              data-testid={testid}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                active
                  ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/30"
                  : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900 border border-transparent"
              }`}
            >
              <Icon size={16} />
              {label}
            </Link>
          );
        })}
      </nav>
      <div className="p-3 border-t border-zinc-800">
        <button
          data-testid="logout-btn"
          onClick={logout}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm text-zinc-400 hover:text-red-400 hover:bg-zinc-900"
        >
          <LogOut size={16} /> Logout
        </button>
      </div>
    </aside>
  );
}
