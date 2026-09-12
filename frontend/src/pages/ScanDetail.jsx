import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "@/lib/api";
import { Download, RefreshCcw } from "lucide-react";

const BACKEND = process.env.REACT_APP_BACKEND_URL || "";

const badge = (cls) => ({
  validated: "bg-red-500/10 text-red-300 border-red-500/40",
  potential: "bg-amber-500/10 text-amber-300 border-amber-500/40",
  safely_encoded: "bg-blue-500/10 text-blue-300 border-blue-500/40",
  reflection_only: "bg-zinc-800 text-zinc-300 border-zinc-700",
  false_positive: "bg-zinc-900 text-zinc-500 border-zinc-800",
}[cls] || "bg-zinc-800 text-zinc-300 border-zinc-700");

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);

  const load = async () => {
    const [s, f] = await Promise.all([api.get(`/scans/${id}`), api.get(`/findings?scan_id=${id}`)]);
    setScan(s.data);
    setFindings(f.data);
  };
  useEffect(() => { load().catch(() => {}); const t = setInterval(load, 3000); return () => clearInterval(t); }, [id]);

  const exportUrl = (fmt) => {
    const token = localStorage.getItem("xss_token");
    return `${BACKEND}/api/scans/${id}/export?format=${fmt}&_t=${Date.now()}#${token}`;
  };
  const doExport = async (fmt) => {
    const res = await api.get(`/scans/${id}/export?format=${fmt}`, { responseType: "blob" });
    const url = URL.createObjectURL(res.data);
    const a = document.createElement("a");
    a.href = url; a.download = `scan-${id}.${fmt === "markdown" ? "md" : fmt}`; a.click();
    URL.revokeObjectURL(url);
  };

  if (!scan) return <div className="p-8 text-zinc-400">Loading…</div>;

  return (
    <div data-testid="scan-detail-page" className="p-8 text-zinc-100">
      <div className="text-xs text-zinc-500 tracking-widest">// SCAN</div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold mt-1 break-all">{scan.target_url}</h1>
          <div className="text-xs text-zinc-500 mt-1">
            status <span className="text-emerald-400">{scan.status}</span> · created {new Date(scan.created_at).toLocaleString()}
          </div>
        </div>
        <div className="flex gap-2">
          <button data-testid="export-json" onClick={() => doExport("json")} className="text-xs px-3 py-2 rounded border border-zinc-700 hover:border-emerald-500 hover:text-emerald-300 flex items-center gap-1"><Download size={12} /> JSON</button>
          <button data-testid="export-csv" onClick={() => doExport("csv")} className="text-xs px-3 py-2 rounded border border-zinc-700 hover:border-emerald-500 hover:text-emerald-300 flex items-center gap-1"><Download size={12} /> CSV</button>
          <button data-testid="export-md" onClick={() => doExport("markdown")} className="text-xs px-3 py-2 rounded border border-zinc-700 hover:border-emerald-500 hover:text-emerald-300 flex items-center gap-1"><Download size={12} /> Markdown</button>
          <button onClick={load} className="text-xs px-3 py-2 rounded border border-zinc-700 hover:border-emerald-500 flex items-center gap-1"><RefreshCcw size={12} /></button>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3 my-6">
        {[
          ["URLs crawled", scan.stats?.urls_crawled ?? 0],
          ["Params tested", scan.stats?.params_tested ?? 0],
          ["Candidates", scan.stats?.candidates ?? 0],
          ["Findings", findings.length],
        ].map(([l, v]) => (
          <div key={l} className="border border-zinc-800 rounded-lg p-4 bg-zinc-900/40">
            <div className="text-[11px] uppercase tracking-widest text-zinc-500">{l}</div>
            <div className="text-2xl font-bold mt-1">{v}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="border border-zinc-800 rounded-lg bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-3 border-b border-zinc-800 text-sm text-zinc-400">Findings ({findings.length})</div>
          <ul data-testid="findings-list" className="divide-y divide-zinc-800 max-h-[520px] overflow-auto">
            {findings.length === 0 && <li className="p-5 text-sm text-zinc-500">No findings yet.</li>}
            {findings.map((f) => (
              <li
                key={f.id}
                data-testid={`finding-${f.id}`}
                onClick={() => setSelected(f)}
                className={`p-4 text-sm cursor-pointer hover:bg-zinc-900 ${selected?.id === f.id ? "bg-zinc-900" : ""}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate text-zinc-200">{f.method} {f.url}</div>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${badge(f.classification)}`}>{f.classification}</span>
                </div>
                <div className="text-xs text-zinc-500 mt-1">
                  <span className="text-emerald-400">{f.param}</span> · context: {f.context} · severity: {f.severity}
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="border border-zinc-800 rounded-lg bg-zinc-900/40 p-5">
          <div className="text-sm text-zinc-400 mb-3">Evidence</div>
          {selected ? (
            <div className="space-y-3 text-xs" data-testid="evidence-panel">
              <div><span className="text-zinc-500">URL:</span> <span className="text-zinc-200">{selected.url}</span></div>
              <div><span className="text-zinc-500">Method:</span> {selected.method}</div>
              <div><span className="text-zinc-500">Param:</span> <span className="text-emerald-400">{selected.param}</span></div>
              <div><span className="text-zinc-500">Context:</span> {selected.context}</div>
              <div><span className="text-zinc-500">Classification:</span> {selected.classification}</div>
              <div><span className="text-zinc-500">Severity:</span> {selected.severity}</div>
              <div>
                <div className="text-zinc-500 mb-1">Request</div>
                <pre className="bg-zinc-950 border border-zinc-800 rounded p-3 text-emerald-300 overflow-auto">{selected.request_dump || "-"}</pre>
              </div>
              <div>
                <div className="text-zinc-500 mb-1">Response snippet</div>
                <pre className="bg-zinc-950 border border-zinc-800 rounded p-3 text-zinc-300 overflow-auto whitespace-pre-wrap">{selected.response_snippet || "-"}</pre>
              </div>
              {selected.payload && (
                <div>
                  <div className="text-zinc-500 mb-1">Payload</div>
                  <pre className="bg-zinc-950 border border-zinc-800 rounded p-3 text-red-300 overflow-auto">{selected.payload}</pre>
                </div>
              )}
            </div>
          ) : (
            <div className="text-zinc-500 text-sm">Select a finding to inspect evidence.</div>
          )}
        </div>
      </div>
    </div>
  );
}
