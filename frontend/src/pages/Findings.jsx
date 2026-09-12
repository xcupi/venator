import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Link } from "react-router-dom";

const badge = (cls) => ({
  validated: "text-red-300 border-red-500/40",
  potential: "text-amber-300 border-amber-500/40",
  safely_encoded: "text-blue-300 border-blue-500/40",
  reflection_only: "text-zinc-300 border-zinc-700",
  false_positive: "text-zinc-500 border-zinc-800",
  csrf_token_required: "text-fuchsia-300 border-fuchsia-500/40",
}[cls] || "text-zinc-300 border-zinc-700");

export default function Findings() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    api.get("/findings")
      .then((r) => setRows(r.data))
      .catch((e) => setError(e?.message || "Failed to load"))
      .finally(() => setLoading(false));
  }, []);
  return (
    <div data-testid="findings-page" className="p-8 text-zinc-100">
      <div className="text-xs text-zinc-500 tracking-widest">// EXPLOITS</div>
      <h1 className="text-3xl font-bold mt-1 mb-6">All findings</h1>
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/40 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-zinc-900 text-zinc-500 text-[11px] uppercase tracking-widest">
            <tr>
              <th className="px-4 py-3 text-left">URL</th>
              <th className="px-4 py-3">Param</th>
              <th className="px-4 py-3">Context</th>
              <th className="px-4 py-3">Class</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={6} className="p-6 text-center text-zinc-500">Loading…</td></tr>}
            {!loading && error && <tr><td colSpan={6} className="p-6 text-center text-red-400">{String(error)}</td></tr>}
            {!loading && !error && rows.length === 0 && <tr><td colSpan={6} className="p-6 text-center text-zinc-500">No findings yet.</td></tr>}
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-zinc-800">
                <td className="px-4 py-3 text-zinc-200 truncate max-w-md">{r.method} {r.url}</td>
                <td className="px-4 py-3 text-center text-emerald-400">{r.param}</td>
                <td className="px-4 py-3 text-center text-zinc-300">{r.context}</td>
                <td className="px-4 py-3 text-center"><span className={`text-xs px-2 py-1 rounded border ${badge(r.classification)}`}>{r.classification}</span></td>
                <td className="px-4 py-3 text-center text-zinc-300">{r.severity}</td>
                <td className="px-4 py-3 text-right">
                  <Link to={`/scans/${r.scan_id}`} className="text-emerald-400 hover:underline text-xs">open scan</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
