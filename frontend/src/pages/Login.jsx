import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "@/lib/api";
import { ShieldAlert, Loader2 } from "lucide-react";

export default function Login() {
  const [email, setEmail] = useState("admin@local.dev");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      nav("/");
    } catch (err) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      data-testid="login-page"
      className="min-h-screen flex items-center justify-center bg-zinc-950 text-zinc-100 px-6"
      style={{ fontFamily: "'JetBrains Mono', ui-monospace, monospace" }}
    >
      <div className="w-full max-w-sm border border-zinc-800 rounded-lg p-8 bg-zinc-900/60 backdrop-blur">
        <div className="flex items-center gap-3 mb-6">
          <ShieldAlert className="text-emerald-400" size={26} />
          <div>
            <div className="text-lg font-bold">reflected-xss-hunter</div>
            <div className="text-xs text-zinc-500">local reconnaissance console</div>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <label className="block text-xs text-zinc-500">EMAIL</label>
          <input
            data-testid="login-email"
            className="w-full bg-zinc-950 border border-zinc-800 focus:border-emerald-500 outline-none rounded px-3 py-2 text-sm"
            type="email" value={email} onChange={(e) => setEmail(e.target.value)}
          />
          <label className="block text-xs text-zinc-500">PASSWORD</label>
          <input
            data-testid="login-password"
            className="w-full bg-zinc-950 border border-zinc-800 focus:border-emerald-500 outline-none rounded px-3 py-2 text-sm"
            type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          />
          {error && (
            <div data-testid="login-error" className="text-red-400 text-xs">{String(error)}</div>
          )}
          <button
            data-testid="login-submit"
            type="submit"
            disabled={loading}
            className="w-full bg-emerald-500 hover:bg-emerald-400 text-zinc-900 font-semibold rounded py-2 text-sm flex items-center justify-center gap-2 disabled:opacity-60"
          >
            {loading && <Loader2 size={14} className="animate-spin" />}
            Sign in
          </button>
        </form>
        <div className="text-[11px] text-zinc-500 mt-6 leading-relaxed">
          Default local admin is <span className="text-emerald-300">admin@local.dev / admin123</span>.
          Override via <code>ADMIN_EMAIL</code> / <code>ADMIN_PASSWORD</code> in <code>.env</code>.
        </div>
      </div>
    </div>
  );
}
