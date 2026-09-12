import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Plus, Trash2 } from "lucide-react";

export default function Projects() {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({ name: "", description: "", allowed_domains: "", excluded_paths: "" });
  const [error, setError] = useState("");

  const load = async () => {
    const { data } = await api.get("/projects");
    setItems(data);
  };
  useEffect(() => { load().catch(() => {}); }, []);

  const create = async (e) => {
    e.preventDefault();
    setError("");
    try {
      await api.post("/projects", {
        name: form.name,
        description: form.description,
        allowed_domains: form.allowed_domains.split(",").map((s) => s.trim()).filter(Boolean),
        excluded_paths: form.excluded_paths.split(",").map((s) => s.trim()).filter(Boolean),
      });
      setForm({ name: "", description: "", allowed_domains: "", excluded_paths: "" });
      load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Create failed");
    }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this project and all its scans?")) return;
    await api.delete(`/projects/${id}`);
    load();
  };

  return (
    <div data-testid="projects-page" className="p-8 text-zinc-100">
      <div className="text-xs text-zinc-500 tracking-widest">// TARGETS</div>
      <h1 className="text-3xl font-bold mt-1 mb-6">Projects</h1>

      <div className="grid lg:grid-cols-3 gap-6">
        <form onSubmit={create} className="lg:col-span-1 border border-zinc-800 rounded-lg bg-zinc-900/40 p-5 space-y-3">
          <div className="text-sm text-zinc-300 mb-1">New project</div>
          {["name","description","allowed_domains","excluded_paths"].map((k) => (
            <div key={k}>
              <label className="block text-[11px] text-zinc-500 uppercase tracking-widest">{k.replace("_"," ")}</label>
              <input
                data-testid={`project-${k}`}
                className="w-full bg-zinc-950 border border-zinc-800 focus:border-emerald-500 rounded px-3 py-2 text-sm outline-none"
                value={form[k]}
                placeholder={k === "allowed_domains" ? "test-target, *.example.com" : k === "excluded_paths" ? "/logout, /admin" : ""}
                onChange={(e) => setForm({ ...form, [k]: e.target.value })}
                required={k === "name" || k === "allowed_domains"}
              />
            </div>
          ))}
          {error && <div className="text-red-400 text-xs">{String(error)}</div>}
          <button
            data-testid="create-project-btn"
            type="submit"
            className="w-full flex items-center justify-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-zinc-900 font-semibold rounded py-2 text-sm"
          >
            <Plus size={14} /> Create
          </button>
        </form>

        <div className="lg:col-span-2 border border-zinc-800 rounded-lg bg-zinc-900/40 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900 text-zinc-500 text-[11px] uppercase tracking-widest">
              <tr><th className="px-4 py-3 text-left">Name</th><th className="px-4 py-3 text-left">Scope</th><th className="px-4 py-3"></th></tr>
            </thead>
            <tbody data-testid="projects-list">
              {items.length === 0 && (
                <tr><td colSpan={3} className="p-6 text-center text-zinc-500">No projects yet.</td></tr>
              )}
              {items.map((p) => (
                <tr key={p.id} className="border-t border-zinc-800">
                  <td className="px-4 py-3">
                    <div className="text-zinc-200">{p.name}</div>
                    <div className="text-xs text-zinc-500 truncate max-w-md">{p.description}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-xs text-zinc-400"><span className="text-emerald-400">allow:</span> {p.allowed_domains.join(", ") || "-"}</div>
                    <div className="text-xs text-zinc-400"><span className="text-red-400">exclude:</span> {p.excluded_paths.join(", ") || "-"}</div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      data-testid={`delete-project-${p.id}`}
                      onClick={() => remove(p.id)}
                      className="text-zinc-500 hover:text-red-400"
                    ><Trash2 size={16} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
