import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Activity, Bug, FolderGit2, ScanSearch, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

const Stat = ({ label, value, icon: Icon, tone = "emerald", testid }) => (
  <div
    data-testid={testid}
    className="border border-zinc-800 rounded-lg p-5 bg-zinc-900/50 flex items-start justify-between"
  >
    <div>
      <div className="text-[11px] uppercase tracking-widest text-zinc-500">{label}</div>
      <div className="text-3xl font-bold text-zinc-100 mt-1">{value}</div>
    </div>
    <div className={`text-${tone}-400`}><Icon size={22} /></div>
  </div>
);

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [recent, setRecent] = useState([]);
  useEffect(() => {
    (async () => {
      const s = await api.get("/dashboard/summary");
      setSummary(s.data);
      const scans = await api.get("/scans");
      setRecent(scans.data.slice(0, 6));
    })().catch(() => {});
  }, []);

  return (
    <div data-testid="dashboard-page" className="p-8 text-zinc-100">
      <div className="mb-6">
        <div className="text-xs text-zinc-500 tracking-widest">// OVERVIEW</div>
        <h1 className="text-3xl font-bold mt-1">Command Center</h1>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat testid="stat-projects" label="Projects" value={summary?.projects ?? "-"} icon={FolderGit2} />
        <Stat testid="stat-scans" label="Total Scans" value={summary?.scans ?? "-"} icon={ScanSearch} />
        <Stat testid="stat-active" label="Active Scans" value={summary?.active_scans ?? "-"} icon={Activity} tone="amber" />
        <Stat testid="stat-validated" label="Validated XSS" value={summary?.validated_findings ?? "-"} icon={ShieldCheck} tone="red" />
      </div>

      <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="border border-zinc-800 rounded-lg bg-zinc-900/40">
          <div className="px-5 py-3 border-b border-zinc-800 text-sm text-zinc-400">Recent scans</div>
          <ul data-testid="recent-scans" className="divide-y divide-zinc-800">
            {recent.length === 0 && (
              <li className="p-5 text-sm text-zinc-500">No scans yet. <Link to="/scans" className="text-emerald-400">Start one</Link>.</li>
            )}
            {recent.map((s) => (
              <li key={s.id} className="p-4 text-sm flex items-center justify-between">
                <div className="min-w-0">
                  <div className="truncate text-zinc-200">{s.target_url}</div>
                  <div className="text-xs text-zinc-500">{new Date(s.created_at).toLocaleString()}</div>
                </div>
                <span className={`text-xs px-2 py-1 rounded border ${
                  s.status === "COMPLETED" ? "text-emerald-300 border-emerald-500/40" :
                  s.status === "RUNNING" ? "text-amber-300 border-amber-500/40" :
                  s.status === "FAILED" ? "text-red-300 border-red-500/40" :
                  "text-zinc-400 border-zinc-700"}`}>
                  {s.status}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className="border border-zinc-800 rounded-lg bg-zinc-900/40 p-5 text-sm text-zinc-400 space-y-2">
          <div className="text-xs text-zinc-500 tracking-widest">// TIPS</div>
          <p><Bug size={14} className="inline text-emerald-400 mr-1" /> Add the bundled test target to a project (<code>test-target:5000</code>) to exercise every reflection type.</p>
          <p>The scanner runs out-of-process — you can safely close the UI while it works.</p>
          <p>Reports export to <code>JSON</code>, <code>CSV</code>, and <code>Markdown</code>.</p>
        </div>
      </div>
    </div>
  );
}
