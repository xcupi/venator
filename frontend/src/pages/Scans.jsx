import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Link } from "react-router-dom";
import { Play, Pause, Square, ExternalLink } from "lucide-react";

const statusColor = (s) => ({
  QUEUED: "text-zinc-400 border-zinc-700",
  RUNNING: "text-amber-300 border-amber-500/40",
  PAUSED: "text-blue-300 border-blue-500/40",
  STOPPING: "text-orange-300 border-orange-500/40",
  STOPPED: "text-zinc-400 border-zinc-700",
  COMPLETED: "text-emerald-300 border-emerald-500/40",
  FAILED: "text-red-300 border-red-500/40",
  AUTHENTICATION_REQUIRED: "text-fuchsia-300 border-fuchsia-500/40",
}[s] || "text-zinc-400 border-zinc-700");

export default function Scans() {
  const [projects, setProjects] = useState([]);
  const [scans, setScans] = useState([]);
  const [authProfiles, setAuthProfiles] = useState([]);
  const [form, setForm] = useState({
    project_id: "", target_url: "", max_urls: 100, max_depth: 3, auth_profile_id: "",
    fuzz_headers: true, fuzz_cookies: false, fuzz_cookie_names: "", fuzz_path: false,
  });

  const load = async () => {
    const [p, s, a] = await Promise.all([api.get("/projects"), api.get("/scans"), api.get("/auth-profiles")]);
    setProjects(p.data);
    setScans(s.data);
    setAuthProfiles(a.data);
    if (!form.project_id && p.data[0]) setForm((f) => ({ ...f, project_id: p.data[0].id }));
  };
  useEffect(() => { load().catch(() => {}); }, []);
  useEffect(() => {
    const t = setInterval(() => api.get("/scans").then((r) => setScans(r.data)).catch(() => {}), 3000);
    return () => clearInterval(t);
  }, []);

  const create = async (e) => {
    e.preventDefault();
    await api.post("/scans", {
      project_id: form.project_id,
      target_url: form.target_url,
      max_urls: Number(form.max_urls),
      max_depth: Number(form.max_depth),
      auth_profile_id: form.auth_profile_id || null,
      fuzz_headers: form.fuzz_headers,
      fuzz_cookies: form.fuzz_cookies,
      fuzz_cookie_names: form.fuzz_cookie_names
        ? form.fuzz_cookie_names.split(",").map((c) => c.trim()).filter(Boolean)
        : null,
      fuzz_path: form.fuzz_path,
    });
    setForm({ ...form, target_url: "" });
    load();
  };

  const act = async (id, action) => {
    await api.post(`/scans/${id}/action?action=${action}`);
    load();
  };

  return (
    <div data-testid="scans-page" className="p-8 text-zinc-100">
      <div className="text-xs text-zinc-500 tracking-widest">// RECON</div>
      <h1 className="text-3xl font-bold mt-1 mb-6">Scans</h1>

      <form onSubmit={create} className="grid md:grid-cols-6 gap-3 mb-8 border border-zinc-800 rounded-lg p-5 bg-zinc-900/40">
        <select
          data-testid="scan-project"
          className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
          value={form.project_id}
          onChange={(e) => setForm({ ...form, project_id: e.target.value, auth_profile_id: "" })}
          required
        >
          <option value="">Select project…</option>
          {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <input
          data-testid="scan-target"
          placeholder="http://test-target:5000/"
          className="md:col-span-2 bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
          value={form.target_url}
          onChange={(e) => setForm({ ...form, target_url: e.target.value })}
          required
        />
        <select
          data-testid="scan-auth-profile"
          className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
          value={form.auth_profile_id}
          onChange={(e) => setForm({ ...form, auth_profile_id: e.target.value })}
        >
          <option value="">(no auth)</option>
          {authProfiles.filter((a) => a.project_id === form.project_id && a.enabled).map((a) => (
            <option key={a.id} value={a.id}>{a.name} ({a.type})</option>
          ))}
        </select>
        <input
          data-testid="scan-max-urls" type="number" min={1}
          className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
          value={form.max_urls} onChange={(e) => setForm({ ...form, max_urls: e.target.value })}
        />
        <button data-testid="start-scan-btn" className="bg-emerald-500 hover:bg-emerald-400 text-zinc-900 font-semibold rounded px-3 py-2 text-sm flex items-center justify-center gap-2">
          <Play size={14} /> Queue scan
        </button>
        <div className="md:col-span-4 flex flex-wrap items-center gap-4 text-xs text-zinc-400">
          <span className="text-zinc-500">Injection points:</span>
          <label className="flex items-center gap-1.5">
            <input
              data-testid="scan-fuzz-headers" type="checkbox"
              checked={form.fuzz_headers}
              onChange={(e) => setForm({ ...form, fuzz_headers: e.target.checked })}
            />
            Request headers
          </label>
          <label className="flex items-center gap-1.5">
            <input
              data-testid="scan-fuzz-path" type="checkbox"
              checked={form.fuzz_path}
              onChange={(e) => setForm({ ...form, fuzz_path: e.target.checked })}
            />
            URL path
          </label>
          <label className="flex items-center gap-1.5">
            <input
              data-testid="scan-fuzz-cookies" type="checkbox"
              checked={form.fuzz_cookies}
              onChange={(e) => setForm({ ...form, fuzz_cookies: e.target.checked })}
            />
            Cookies
          </label>
          {form.fuzz_cookies && (
            <input
              data-testid="scan-fuzz-cookie-names"
              placeholder="cookie names (comma-separated)"
              className="flex-1 min-w-[200px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-xs"
              value={form.fuzz_cookie_names}
              onChange={(e) => setForm({ ...form, fuzz_cookie_names: e.target.value })}
            />
          )}
        </div>
      </form>

      <div className="border border-zinc-800 rounded-lg bg-zinc-900/40 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-zinc-900 text-zinc-500 text-[11px] uppercase tracking-widest">
            <tr>
              <th className="px-4 py-3 text-left">Target</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">URLs</th>
              <th className="px-4 py-3">Params</th>
              <th className="px-4 py-3">Candidates</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody data-testid="scans-list">
            {scans.length === 0 && (
              <tr><td colSpan={6} className="p-6 text-center text-zinc-500">No scans yet.</td></tr>
            )}
            {scans.map((s) => (
              <tr key={s.id} className="border-t border-zinc-800">
                <td className="px-4 py-3">
                  <div className="text-zinc-200 truncate max-w-md">{s.target_url}</div>
                  <div className="text-xs text-zinc-500">{new Date(s.created_at).toLocaleString()}</div>
                </td>
                <td className="px-4 py-3 text-center">
                  <span className={`text-xs px-2 py-1 rounded border ${statusColor(s.status)}`}>{s.status}</span>
                </td>
                <td className="px-4 py-3 text-center text-zinc-300">{s.stats?.urls_crawled ?? 0}</td>
                <td className="px-4 py-3 text-center text-zinc-300">{s.stats?.params_tested ?? 0}</td>
                <td className="px-4 py-3 text-center text-zinc-300">{s.stats?.candidates ?? 0}</td>
                <td className="px-4 py-3 text-right">
                  <div className="inline-flex gap-2">
                    {s.status === "RUNNING" && (
                      <button data-testid={`pause-${s.id}`} onClick={() => act(s.id, "pause")} className="text-blue-300 hover:text-blue-200"><Pause size={16} /></button>
                    )}
                    {s.status === "PAUSED" && (
                      <button data-testid={`resume-${s.id}`} onClick={() => act(s.id, "resume")} className="text-emerald-300 hover:text-emerald-200"><Play size={16} /></button>
                    )}
                    {(s.status === "RUNNING" || s.status === "PAUSED" || s.status === "QUEUED") && (
                      <button data-testid={`stop-${s.id}`} onClick={() => act(s.id, "stop")} className="text-red-300 hover:text-red-200"><Square size={16} /></button>
                    )}
                    <Link data-testid={`view-scan-${s.id}`} to={`/scans/${s.id}`} className="text-zinc-400 hover:text-emerald-300">
                      <ExternalLink size={16} />
                    </Link>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
