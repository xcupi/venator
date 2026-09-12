import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { KeyRound, Plus, Trash2, ShieldCheck, ShieldAlert, PlayCircle } from "lucide-react";

const TYPES = [
  { v: "cookie", l: "Cookie" },
  { v: "header", l: "Custom Header(s)" },
  { v: "bearer", l: "Bearer Token" },
  { v: "basic",  l: "HTTP Basic" },
];

const initialConfigFor = (t) => ({
  cookie: { cookies: [{ name: "session", value: "" }], check_url: "", login_indicators: ["Sign in", "/login"], authed_indicators: [] },
  header: { headers: [{ name: "X-Api-Key", value: "", sensitive: true }], check_url: "", login_indicators: [], authed_indicators: [] },
  bearer: { token: "", header_name: "Authorization", check_url: "", login_indicators: [], authed_indicators: [] },
  basic:  { username: "", password: "", check_url: "", login_indicators: [], authed_indicators: [] },
}[t]);

const statusPill = (st) => st === "VALID"
  ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/40"
  : st === "INVALID"
  ? "bg-red-500/10 text-red-300 border-red-500/40"
  : "bg-zinc-800 text-zinc-400 border-zinc-700";

export default function AuthProfiles() {
  const [projects, setProjects] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [form, setForm] = useState({
    project_id: "", name: "", type: "cookie", enabled: true,
    config: initialConfigFor("cookie"),
  });
  const [testResult, setTestResult] = useState({});
  const [error, setError] = useState("");

  const load = async () => {
    const [p, a] = await Promise.all([api.get("/projects"), api.get("/auth-profiles")]);
    setProjects(p.data);
    setProfiles(a.data);
    if (!form.project_id && p.data[0]) setForm((f) => ({ ...f, project_id: p.data[0].id }));
  };
  useEffect(() => { load().catch(() => {}); }, []);

  const setType = (t) => setForm((f) => ({ ...f, type: t, config: initialConfigFor(t) }));

  const create = async (e) => {
    e.preventDefault();
    setError("");
    try {
      await api.post("/auth-profiles", form);
      setForm({ ...form, name: "", config: initialConfigFor(form.type) });
      load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Create failed");
    }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this auth profile?")) return;
    await api.delete(`/auth-profiles/${id}`);
    load();
  };

  const test = async (id) => {
    setTestResult((r) => ({ ...r, [id]: { status: "TESTING" } }));
    try {
      const { data } = await api.post(`/auth-profiles/${id}/test`, {});
      setTestResult((r) => ({ ...r, [id]: data }));
    } catch (err) {
      setTestResult((r) => ({ ...r, [id]: { status: "INVALID", notes: err?.response?.data?.detail || String(err) } }));
    }
  };

  // ---------- Form editors per type ----------
  const CookieEditor = () => (
    <div className="space-y-2">
      {form.config.cookies.map((c, i) => (
        <div key={i} className="grid grid-cols-2 gap-2">
          <input data-testid={`cookie-name-${i}`} className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm" placeholder="name (e.g. session)"
            value={c.name} onChange={(e) => {
              const cookies = [...form.config.cookies]; cookies[i] = { ...c, name: e.target.value };
              setForm({ ...form, config: { ...form.config, cookies } });
            }}/>
          <input data-testid={`cookie-value-${i}`} type="password" className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm font-mono" placeholder="value"
            value={c.value} onChange={(e) => {
              const cookies = [...form.config.cookies]; cookies[i] = { ...c, value: e.target.value };
              setForm({ ...form, config: { ...form.config, cookies } });
            }}/>
        </div>
      ))}
      <button type="button" onClick={() => setForm({ ...form, config: { ...form.config, cookies: [...form.config.cookies, { name: "", value: "" }] } })}
              className="text-xs text-emerald-400 hover:underline">+ Add cookie</button>
    </div>
  );

  const HeaderEditor = () => (
    <div className="space-y-2">
      {form.config.headers.map((h, i) => (
        <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-center">
          <input className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm" placeholder="Header name"
            value={h.name} onChange={(e) => {
              const headers = [...form.config.headers]; headers[i] = { ...h, name: e.target.value };
              setForm({ ...form, config: { ...form.config, headers } });
            }}/>
          <input type={h.sensitive ? "password" : "text"} className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm font-mono" placeholder="value"
            value={h.value} onChange={(e) => {
              const headers = [...form.config.headers]; headers[i] = { ...h, value: e.target.value };
              setForm({ ...form, config: { ...form.config, headers } });
            }}/>
          <label className="text-[11px] text-zinc-400 flex items-center gap-1">
            <input type="checkbox" checked={!!h.sensitive} onChange={(e) => {
              const headers = [...form.config.headers]; headers[i] = { ...h, sensitive: e.target.checked };
              setForm({ ...form, config: { ...form.config, headers } });
            }}/>
            secret
          </label>
        </div>
      ))}
      <button type="button" onClick={() => setForm({ ...form, config: { ...form.config, headers: [...form.config.headers, { name: "", value: "", sensitive: true }] } })}
              className="text-xs text-emerald-400 hover:underline">+ Add header</button>
    </div>
  );

  const BearerEditor = () => (
    <div className="grid grid-cols-2 gap-2">
      <input className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm" placeholder="Header name (default Authorization)"
        value={form.config.header_name || ""} onChange={(e) => setForm({ ...form, config: { ...form.config, header_name: e.target.value } })}/>
      <input data-testid="bearer-token" type="password" className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm font-mono" placeholder="token"
        value={form.config.token || ""} onChange={(e) => setForm({ ...form, config: { ...form.config, token: e.target.value } })}/>
    </div>
  );

  const BasicEditor = () => (
    <div className="grid grid-cols-2 gap-2">
      <input className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm" placeholder="username"
        value={form.config.username || ""} onChange={(e) => setForm({ ...form, config: { ...form.config, username: e.target.value } })}/>
      <input type="password" className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm font-mono" placeholder="password"
        value={form.config.password || ""} onChange={(e) => setForm({ ...form, config: { ...form.config, password: e.target.value } })}/>
    </div>
  );

  const editor = { cookie: CookieEditor, header: HeaderEditor, bearer: BearerEditor, basic: BasicEditor }[form.type];

  return (
    <div data-testid="auth-profiles-page" className="p-8 text-zinc-100">
      <div className="text-xs text-zinc-500 tracking-widest">// AUTH</div>
      <h1 className="text-3xl font-bold mt-1 mb-6 flex items-center gap-2">
        <KeyRound className="text-emerald-400" size={24} /> Authentication Profiles
      </h1>

      <div className="grid lg:grid-cols-5 gap-6">
        <form onSubmit={create} className="lg:col-span-2 border border-zinc-800 rounded-lg bg-zinc-900/40 p-5 space-y-3">
          <div className="text-sm text-zinc-300">New profile</div>

          <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">Project</label>
          <select data-testid="ap-project" className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
            value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })} required>
            <option value="">Select…</option>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>

          <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">Name</label>
          <input data-testid="ap-name" className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
            value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />

          <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">Type</label>
          <div className="flex flex-wrap gap-2">
            {TYPES.map(({ v, l }) => (
              <button data-testid={`ap-type-${v}`} type="button" key={v} onClick={() => setType(v)}
                className={`text-xs px-3 py-1.5 rounded border ${form.type === v ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/40" : "text-zinc-400 border-zinc-700 hover:border-emerald-500/40"}`}>
                {l}
              </button>
            ))}
          </div>

          <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">Credentials</label>
          {editor && editor()}

          <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">Check URL (used by Test Auth)</label>
          <input data-testid="ap-check-url" className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
            placeholder="http://localhost:5000/dashboard"
            value={form.config.check_url || ""} onChange={(e) => setForm({ ...form, config: { ...form.config, check_url: e.target.value } })}/>

          <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">Login indicators (comma sep)</label>
          <input className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm"
            value={(form.config.login_indicators || []).join(", ")}
            onChange={(e) => setForm({ ...form, config: { ...form.config, login_indicators: e.target.value.split(",").map(s => s.trim()).filter(Boolean) } })}/>

          {error && <div className="text-red-400 text-xs">{String(error)}</div>}
          <button data-testid="ap-create-btn" type="submit" className="w-full flex items-center justify-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-zinc-900 font-semibold rounded py-2 text-sm">
            <Plus size={14} /> Create profile
          </button>
        </form>

        <div className="lg:col-span-3 border border-zinc-800 rounded-lg bg-zinc-900/40 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900 text-zinc-500 text-[11px] uppercase tracking-widest">
              <tr>
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Project</th>
                <th className="px-4 py-3">Secrets</th>
                <th className="px-4 py-3">Test</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody data-testid="ap-list">
              {profiles.length === 0 && <tr><td colSpan={6} className="p-6 text-center text-zinc-500">No auth profiles yet.</td></tr>}
              {profiles.map((p) => {
                const proj = projects.find((x) => x.id === p.project_id);
                const tr = testResult[p.id];
                const secretCount =
                  p.type === "cookie" ? (p.config.cookies || []).length :
                  p.type === "header" ? (p.config.headers || []).length :
                  p.type === "bearer" ? (p.config.token ? 1 : 0) :
                  p.type === "basic" ? (p.config.username ? 1 : 0) : 0;
                return (
                  <tr key={p.id} className="border-t border-zinc-800">
                    <td className="px-4 py-3 text-zinc-200">{p.name}</td>
                    <td className="px-4 py-3 text-center text-emerald-300 text-xs">{p.type}</td>
                    <td className="px-4 py-3 text-center text-zinc-400 text-xs">{proj?.name || "-"}</td>
                    <td className="px-4 py-3 text-center text-zinc-400 text-xs">{secretCount} masked</td>
                    <td className="px-4 py-3 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <button data-testid={`test-auth-${p.id}`} onClick={() => test(p.id)} className="text-xs text-emerald-400 hover:underline flex items-center gap-1">
                          <PlayCircle size={12} /> Test
                        </button>
                        {tr && (
                          <span data-testid={`test-result-${p.id}`} className={`text-[10px] px-2 py-0.5 rounded border ${statusPill(tr.status)}`}>
                            {tr.status === "VALID" ? <ShieldCheck className="inline" size={10} /> : <ShieldAlert className="inline" size={10} />} {tr.status}
                          </span>
                        )}
                      </div>
                      {tr?.notes && <div className="text-[10px] text-zinc-500 mt-1 truncate max-w-[180px]" title={tr.notes}>{tr.notes}</div>}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button data-testid={`delete-ap-${p.id}`} onClick={() => remove(p.id)} className="text-zinc-500 hover:text-red-400"><Trash2 size={16} /></button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
