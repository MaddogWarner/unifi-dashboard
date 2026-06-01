import type { FormEvent } from "react";
import { useState } from "react";

import { useAuth } from "../contexts/AuthContext";
import { apiLogin, apiRegister } from "../lib/api";

export default function Setup() {
  const auth = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 12) {
      setError("Password must be at least 12 characters");
      return;
    }

    setLoading(true);
    try {
      await apiRegister(email, password);
      const token = await apiLogin(email, password);
      await auth.login(token);
      window.location.href = "/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4 dark:bg-slate-950">
      <div className="w-full max-w-sm rounded border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-700 dark:bg-slate-900">
        <h1 className="mb-2 text-2xl font-bold text-slate-950 dark:text-slate-50">First-time setup</h1>
        <p className="mb-6 text-sm text-slate-500 dark:text-slate-400">
          Create the initial administrator account.
        </p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm text-slate-700 dark:text-slate-300">Email</label>
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm text-slate-700 dark:text-slate-300">
              Password <span className="text-slate-500">(min 12 characters)</span>
            </label>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm text-slate-700 dark:text-slate-300">Confirm password</label>
            <input
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              required
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
            />
          </div>
          {error ? <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p> : null}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded bg-teal-700 py-2 text-sm font-medium text-white transition-colors hover:bg-teal-600 disabled:opacity-50"
          >
            {loading ? "Creating account..." : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
