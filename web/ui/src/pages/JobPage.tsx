import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, getToken, Job } from "../api";
import ScanActivity from "../components/ScanActivity";

function formatDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) return "—";
  const secs = Math.floor(totalSeconds);
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/** API stores UTC without timezone; browsers would otherwise treat that as local (IST +5:30 → inflated duration). */
function parseUtcMs(raw: string): number {
  const s = raw.trim();
  if (!s) return NaN;
  if (/[zZ]$/.test(s) || /[+-]\d{2}:?\d{2}$/.test(s)) {
    return Date.parse(s);
  }
  if (s.includes("T")) {
    return Date.parse(`${s}Z`);
  }
  return Date.parse(`${s.replace(" ", "T")}Z`);
}

function jobDurationSeconds(job: Job, nowMs: number): number | null {
  const startRaw = job.started_at || job.created_at;
  if (!startRaw) return null;
  const start = parseUtcMs(startRaw);
  if (!Number.isFinite(start)) return null;

  let end = nowMs;
  if (job.finished_at) {
    end = parseUtcMs(job.finished_at);
  } else if (job.status === "stopping" && job.updated_at) {
    // Freeze the clock when stop was requested so a hung stop does not keep counting
    end = parseUtcMs(job.updated_at);
  }
  if (!Number.isFinite(end)) return null;
  return Math.max(0, (end - start) / 1000);
}

export default function JobPage() {
  const { id = "" } = useParams();
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [logExtra, setLogExtra] = useState("");
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [artifacts, setArtifacts] = useState<{ name: string; path: string; size: number; kind: string }[]>([]);
  const logRef = useRef<HTMLDivElement | null>(null);
  const stickToBottom = useRef(true);

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
            started_at: data.started_at ?? prev.started_at,
            finished_at: data.finished_at ?? prev.finished_at,
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

  useEffect(() => {
    const active = job && ["queued", "running", "paused", "stopping", "scheduled"].includes(job.status);
    if (!active) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [job?.status]);

  useEffect(() => {
    if (!id || !job) return;
    if (!["completed", "failed", "cancelled"].includes(job.status) && !job.report_html_path) return;
    api.listArtifacts(id).then(setArtifacts).catch(() => setArtifacts([]));
  }, [id, job?.status, job?.report_html_path]);

  const progress = job?.progress_json || {};
  const logText = useMemo(() => {
    const base = job?.log_tail || "";
    return (base + logExtra).slice(-24000);
  }, [job, logExtra]);

  useEffect(() => {
    const el = logRef.current;
    if (!el || !stickToBottom.current) return;
    el.scrollTop = el.scrollHeight;
  }, [logText]);

  async function runAction(kind: "pause" | "resume" | "stop" | "force-cancel") {
    if (!job) return;
    setActionError("");
    try {
      if (kind === "pause") await api.pauseJob(job.id);
      if (kind === "resume") await api.resumeJob(job.id);
      if (kind === "stop") await api.stopJob(job.id);
      if (kind === "force-cancel") await api.forceCancelJob(job.id);
      const fresh = await api.getJob(job.id);
      setJob(fresh);
    } catch (err: any) {
      setActionError(String(err.message || err));
    }
  }

  if (!job) {
    return <div className="card muted">{error || "Loading job…"}</div>;
  }

  const reportReady = ["completed", "failed", "cancelled"].includes(job.status) || Boolean(job.report_html_path);
  const tok = encodeURIComponent(getToken() || "");
  const htmlUrl = `/api/reports/${job.id}/html?token=${tok}`;
  const txtUrl = `/api/reports/${job.id}/txt?token=${tok}`;
  const embedUrl = `/api/reports/${job.id}/embed?token=${tok}`;
  const logUrl = `/api/reports/${job.id}/log?token=${tok}`;
  const zipUrl = `/api/reports/${job.id}/bundle.zip?token=${tok}`;
  const durationSecs = jobDurationSeconds(job, nowMs);
  const durationLabel = durationSecs == null ? "—" : formatDuration(durationSecs);

  const canPause = job.status === "running" || job.status === "queued";
  const canResume = job.status === "paused" || job.status === "scheduled";
  const canStop = !["completed", "cancelled", "failed"].includes(job.status);

  const enumHits = (progress.enum_hit_urls as string[]) || [];
  const findings = (progress.findings_preview as { severity?: string; title?: string; url?: string }[]) || [];

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
          <div style={{ display: "flex", gap: ".5rem", alignItems: "center", flexWrap: "wrap" }}>
            <button className="btn" type="button" disabled={!canPause} onClick={() => runAction("pause")}>
              Pause
            </button>
            <button className="btn" type="button" disabled={!canResume} onClick={() => runAction("resume")}>
              Resume
            </button>
            <button
              className="btn danger"
              type="button"
              disabled={!canStop}
              onClick={() => runAction(job.status === "stopping" ? "force-cancel" : "stop")}
            >
              {job.status === "stopping" ? "Force cancel" : "Stop"}
            </button>
            <Link className="btn" to="/">
              All jobs
            </Link>
          </div>
        </div>
        {error && <div className="error" style={{ marginTop: "1rem" }}>{error}</div>}
        {actionError && <div className="error" style={{ marginTop: "1rem" }}>{actionError}</div>}
        {job.error_message && <div className="error" style={{ marginTop: "1rem" }}>{job.error_message}</div>}
        {job.status === "paused" ? (
          <p className="muted" style={{ marginTop: ".85rem" }}>
            Paused. Change expert settings on a new draft is not required — use Resume to continue. Settings patched via
            API while paused are applied on Resume.
          </p>
        ) : null}
        {/* Single status strip — no duplicate badge + "Stopping…" */}
        {["queued", "running", "paused", "stopping"].includes(job.status) ? (
          <ScanActivity status={job.status} />
        ) : (
          <div style={{ marginTop: "1rem" }}>
            <span className={`badge ${job.status}`}>{job.status}</span>
          </div>
        )}
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
            <div className="stat-num">{durationLabel}</div>
            <div className="stat-label">Duration</div>
          </div>
          <div className="stat">
            <div className="stat-num" style={{ fontSize: "1rem" }}>{job.mode}</div>
            <div className="stat-label">Mode</div>
          </div>
        </div>
      </section>

      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: "1rem" }}>
          <h2 style={{ margin: 0 }}>Live Logs</h2>
          <a className="btn" href={logUrl} download={`${job.id}_logs.txt`}>
            Export log
          </a>
        </div>
        <div
          ref={logRef}
          className="log"
          style={{ marginTop: ".75rem" }}
          onScroll={() => {
            const el = logRef.current;
            if (!el) return;
            const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
            stickToBottom.current = distance < 48;
          }}
        >
          {logText || "Waiting for worker output…"}
        </div>
      </section>

      {(enumHits.length > 0 || findings.length > 0) && (
        <section className="card">
          <h2>Results</h2>
          <div className="grid-2">
            <div>
              <h3 style={{ marginTop: 0 }}>Enum hits</h3>
              {enumHits.length === 0 ? (
                <p className="muted">None yet</p>
              ) : (
                <ul className="mono" style={{ fontSize: ".8rem", maxHeight: 240, overflow: "auto" }}>
                  {enumHits.slice(0, 60).map((url) => (
                    <li key={url}>
                      <a href={url} target="_blank" rel="noreferrer">
                        {url}
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h3 style={{ marginTop: 0 }}>Findings</h3>
              {findings.length === 0 ? (
                <p className="muted">None yet</p>
              ) : (
                <ul style={{ fontSize: ".85rem", maxHeight: 240, overflow: "auto", paddingLeft: "1.1rem" }}>
                  {findings.map((f, i) => (
                    <li key={`${f.url}-${i}`}>
                      <strong>{f.severity || "info"}</strong> — {f.title || "Finding"}
                      {f.url ? (
                        <>
                          {" "}
                          <a className="mono" href={f.url} target="_blank" rel="noreferrer">
                            {f.url}
                          </a>
                        </>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>
      )}

      <section className="card">
        <h2>Report & artifacts</h2>
        {!reportReady ? (
          <p className="muted">HTML report and artifacts appear when the worker finishes writing files.</p>
        ) : (
          <>
            <div style={{ display: "flex", gap: ".6rem", marginBottom: ".75rem", flexWrap: "wrap" }}>
              <a className="btn primary" href={htmlUrl} target="_blank" rel="noreferrer">
                Open HTML report
              </a>
              <a className="btn" href={txtUrl} target="_blank" rel="noreferrer">
                Download text
              </a>
              <a className="btn" href={zipUrl}>
                Download all (zip)
              </a>
            </div>
            {artifacts.length > 0 ? (
              <table className="table" style={{ marginBottom: "1rem" }}>
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Size</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {artifacts.map((a) => (
                    <tr key={a.path}>
                      <td className="mono">{a.name}</td>
                      <td className="muted">{Math.max(1, Math.round(a.size / 1024))} KB</td>
                      <td>
                        <a className="btn" href={`/api/reports/${job.id}/artifacts/${encodeURIComponent(a.path)}?token=${tok}`}>
                          Download
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            <iframe className="report-frame" title="Report" src={embedUrl} />
          </>
        )}
      </section>
    </div>
  );
}
