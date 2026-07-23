import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Job } from "../api";
import ScanActivity from "../components/ScanActivity";
import {
  canDeleteJob,
  formatJobStatus,
  formatModeLabel,
  formatScanCompleteness,
  scanCompletenessClass,
} from "../jobStatus";

function JobStatusBadges({ job }: { job: Job }) {
  const progress = (job.progress_json || {}) as Record<string, unknown>;
  const reportLabel =
    ["completed", "failed", "cancelled", "canceled"].includes(job.status)
      ? formatScanCompleteness(progress)
      : null;
  return (
    <div className="status-cell">
      <span className={`badge ${job.status}`}>{formatJobStatus(job.status)}</span>
      {reportLabel ? (
        <span className={`badge ${scanCompletenessClass(reportLabel)}`}>{reportLabel}</span>
      ) : null}
      <ScanActivity status={job.status} compact />
    </div>
  );
}

export default function DashboardPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  const [deletingId, setDeletingId] = useState("");

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .listJobs()
        .then((res) => {
          if (alive) setJobs(res.jobs);
        })
        .catch((err) => {
          if (alive) setError(String(err.message || err));
        });
    load();
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const deleteJob = async (job: Job) => {
    if (!canDeleteJob(job.status)) return;
    const ok = window.confirm(`Delete “${job.title || "this scan"}”? Reports and logs will be removed.`);
    if (!ok) return;
    setDeletingId(job.id);
    setError("");
    try {
      await api.deleteJob(job.id);
      setJobs((prev) => prev.filter((j) => j.id !== job.id));
    } catch (err) {
      setError(String((err as Error).message || err));
    } finally {
      setDeletingId("");
    }
  };

  const running = jobs.filter((j) => j.status === "running" || j.status === "queued").length;
  const completed = jobs.filter((j) => j.status === "completed").length;
  const cancelled = jobs.filter((j) => j.status === "cancelled" || j.status === "canceled").length;

  const stats = (
    <div className="stats stats-tri">
      <div className="stat">
        <div className="stat-num">{jobs.length}</div>
        <div className="stat-label">Jobs</div>
      </div>
      <div className="stat">
        <div className="stat-num">{running}</div>
        <div className="stat-label">Running</div>
      </div>
      <div className="stat">
        <div className="stat-num">{completed}</div>
        <div className="stat-label">Completed</div>
      </div>
      {cancelled > 0 ? (
        <div className="stat">
          <div className="stat-num">{cancelled}</div>
          <div className="stat-label">Cancelled</div>
        </div>
      ) : null}
    </div>
  );

  return (
    <div className="dash">
      <header className="dash-hero mobile-only">
        <div>
          <h1>Scan jobs</h1>
          <p className="lead">Live queue of crawls, enums, and security assessments.</p>
        </div>
        <Link className="btn primary dash-cta" to="/scans/new">
          New scan
        </Link>
      </header>
      <div className="mobile-only dash-stats">{stats}</div>

      <div className="grid-2">
        <section className="card dash-jobs-card">
          <div className="desktop-only">
            <h1>Scan jobs</h1>
            <p className="lead">Live queue of crawls, enums, and security assessments.</p>
          </div>
          {error && <div className="error">{error}</div>}
          {jobs.length === 0 ? (
            <div className="dash-empty">
              <p className="muted">No jobs yet. Start your first authorized scan.</p>
              <Link className="btn primary" to="/scans/new">
                New scan
              </Link>
            </div>
          ) : (
            <>
              <ul className="job-cards">
                {jobs.map((job) => {
                  const deletable = canDeleteJob(job.status);
                  return (
                    <li key={job.id} className="job-card-wrap">
                      <Link className="job-card" to={`/jobs/${job.id}`}>
                        <div className="job-card-top">
                          <div className="job-card-title">{job.title || "Untitled scan"}</div>
                          <JobStatusBadges job={job} />
                        </div>
                        <div className="job-card-url mono" title={job.start_url}>
                          {job.start_url}
                        </div>
                        <div className="job-card-foot">
                          <span className="job-card-mode">{formatModeLabel(job.mode)}</span>
                          <span className="job-card-open">Open →</span>
                        </div>
                      </Link>
                      {deletable ? (
                        <button
                          className="btn danger job-card-delete"
                          type="button"
                          disabled={deletingId === job.id}
                          onClick={() => deleteJob(job)}
                        >
                          {deletingId === job.id ? "Deleting…" : "Delete"}
                        </button>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
              <div className="table-wrap desktop-only">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Mode</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((job) => {
                      const deletable = canDeleteJob(job.status);
                      return (
                        <tr key={job.id}>
                          <td>{job.title}</td>
                          <td className="mono table-url" title={job.start_url}>
                            {job.start_url}
                          </td>
                          <td>
                            <JobStatusBadges job={job} />
                          </td>
                          <td className="muted">{formatModeLabel(job.mode)}</td>
                          <td>
                            <div className="job-row-actions">
                              <Link className="btn" to={`/jobs/${job.id}`}>
                                Open
                              </Link>
                              {deletable ? (
                                <button
                                  className="btn danger"
                                  type="button"
                                  disabled={deletingId === job.id}
                                  onClick={() => deleteJob(job)}
                                >
                                  {deletingId === job.id ? "Deleting…" : "Delete"}
                                </button>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
        <aside className="card desktop-only">
          <h2>Quick start</h2>
          <p className="muted">
            Confirm authorization, pick a mode, choose a bundled wordlist (or upload your own), tune speed, then
            watch live progress and open the VantaCrawl HTML report.
          </p>
          <Link className="btn primary" to="/scans/new">
            New scan
          </Link>
          <div style={{ marginTop: "1.25rem" }}>{stats}</div>
        </aside>
      </div>
    </div>
  );
}
