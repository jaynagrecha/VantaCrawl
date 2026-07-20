import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, getToken, Job } from "../api";

export default function JobPage() {
  const { id = "" } = useParams();
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [logExtra, setLogExtra] = useState("");

  useEffect(() => {
    if (!id) return;
    let alive = true;
    api
      .getJob(id)
      .then((j) => {
        if (alive) setJob(j);
      })
      .catch((err) => setError(String(err.message || err)));

    const token = getToken();
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/jobs/${id}/ws?token=${encodeURIComponent(token || "")}`);
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        setJob((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            status: data.status || prev.status,
            progress_json: data.progress || prev.progress_json,
            log_tail: data.log ? `${prev.log_tail || ""}${data.log}\n` : data.log_tail || prev.log_tail,
          };
        });
        if (data.log) setLogExtra((x) => (x + data.log + "\n").slice(-20000));
      } catch {
        /* ignore */
      }
    };
    const poll = setInterval(() => {
      api.getJob(id).then((j) => alive && setJob(j)).catch(() => undefined);
    }, 5000);
    return () => {
      alive = false;
      ws.close();
      clearInterval(poll);
    };
  }, [id]);

  const progress = job?.progress_json || {};
  const logText = useMemo(() => {
    const base = job?.log_tail || "";
    return (base + logExtra).slice(-24000);
  }, [job, logExtra]);

  if (!job) {
    return <div className="card muted">{error || "Loading job…"}</div>;
  }

  const reportReady = ["completed", "failed", "cancelled"].includes(job.status) || Boolean(job.report_html_path);
  const tok = encodeURIComponent(getToken() || "");
  const htmlUrl = `/api/reports/${job.id}/html?token=${tok}`;
  const txtUrl = `/api/reports/${job.id}/txt?token=${tok}`;
  const embedUrl = `/api/reports/${job.id}/embed?token=${tok}`;

  return (
    <div>
      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", gap: "1rem", flexWrap: "wrap" }}>
          <div>
            <h1>{job.title}</h1>
            <p className="mono muted" style={{ margin: 0 }}>
              {job.start_url}
            </p>
          </div>
          <div style={{ display: "flex", gap: ".5rem", alignItems: "center" }}>
            <span className={`badge ${job.status}`}>{job.status}</span>
            <button className="btn" type="button" onClick={() => api.pauseJob(job.id)}>
              Pause
            </button>
            <button className="btn" type="button" onClick={() => api.resumeJob(job.id)}>
              Resume
            </button>
            <button className="btn danger" type="button" onClick={() => api.stopJob(job.id)}>
              Stop
            </button>
            <Link className="btn" to="/">
              All jobs
            </Link>
          </div>
        </div>
        {error && <div className="error" style={{ marginTop: "1rem" }}>{error}</div>}
        {job.error_message && <div className="error" style={{ marginTop: "1rem" }}>{job.error_message}</div>}
        <div className="stats" style={{ marginTop: "1.1rem" }}>
          <div className="stat">
            <div className="stat-num">{String(progress.pages_crawled ?? "—")}</div>
            <div className="stat-label">Pages</div>
          </div>
          <div className="stat">
            <div className="stat-num">{String(progress.enum_hits ?? "—")}</div>
            <div className="stat-label">Enum hits</div>
          </div>
          <div className="stat">
            <div className="stat-num">{String(progress.findings ?? "—")}</div>
            <div className="stat-label">Findings</div>
          </div>
          <div className="stat">
            <div className="stat-num">{job.mode}</div>
            <div className="stat-label">Mode</div>
          </div>
        </div>
      </section>

      <section className="card">
        <h2>Live log</h2>
        <div className="log">{logText || "Waiting for worker output…"}</div>
      </section>

      <section className="card">
        <h2>Report</h2>
        {!reportReady ? (
          <p className="muted">HTML report appears when the worker finishes writing artifacts.</p>
        ) : (
          <>
            <div style={{ display: "flex", gap: ".6rem", marginBottom: ".75rem" }}>
              <a className="btn primary" href={htmlUrl} target="_blank" rel="noreferrer">
                Open HTML report
              </a>
              <a className="btn" href={txtUrl} target="_blank" rel="noreferrer">
                Download text
              </a>
            </div>
            <iframe className="report-frame" title="Report" src={embedUrl} />
          </>
        )}
      </section>
    </div>
  );
}
