import { FormEvent, useState } from "react";
import { getToken } from "../api";

export default function ToolsPage() {
  const [fileA, setFileA] = useState<File | null>(null);
  const [fileB, setFileB] = useState<File | null>(null);
  const [summary, setSummary] = useState<string>("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function compare(e: FormEvent) {
    e.preventDefault();
    if (!fileA || !fileB) {
      setError("Pick two crawl JSON reports.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const body = new FormData();
      body.append("report_a", fileA);
      body.append("report_b", fileB);
      const token = getToken();
      const res = await fetch("/api/reports/compare", {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || res.statusText);
      setSummary(JSON.stringify(data.summary, null, 2));
      const html = `/api/reports/compare/html?token=${encodeURIComponent(token || "")}`;
      window.open(html, "_blank", "noopener");
    } catch (err: any) {
      setError(String(err.message || err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h1>Tools</h1>
      <p className="lead">Compare two crawl JSON reports (desktop Tools parity).</p>
      {error && <div className="error">{error}</div>}
      <form onSubmit={compare}>
        <div className="field">
          <label>Report A (JSON)</label>
          <input type="file" accept="application/json,.json" onChange={(e) => setFileA(e.target.files?.[0] || null)} />
        </div>
        <div className="field">
          <label>Report B (JSON)</label>
          <input type="file" accept="application/json,.json" onChange={(e) => setFileB(e.target.files?.[0] || null)} />
        </div>
        <button className="btn primary" type="submit" disabled={busy}>
          {busy ? "Comparing…" : "Compare reports"}
        </button>
      </form>
      {summary ? (
        <pre className="log" style={{ marginTop: "1rem" }}>
          {summary}
        </pre>
      ) : null}
    </section>
  );
}
