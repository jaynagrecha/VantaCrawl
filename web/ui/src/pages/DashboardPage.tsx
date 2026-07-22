import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Job } from "../api";
import ScanActivity from "../components/ScanActivity";

function modeLabel(mode: string) {
  return mode.replace(/_/g, " ");
}

export default function DashboardPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");

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

  const running = jobs.filter((j) => j.status === "running").length;
  const done = jobs.filter((j) => j.status === "completed").length;

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
        <div className="stat-num">{done}</div>
        <div className="stat-label">Done</div>
      </div>
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
                {jobs.map((job) => (
                  <li key={job.id}>
                    <Link className="job-card" to={`/jobs/${job.id}`}>
                      <div className="job-card-top">
                        <div className="job-card-title">{job.title || "Untitled scan"}</div>
                        <div className="status-cell">
                          <span className={`badge ${job.status}`}>{job.status}</span>
                          <ScanActivity status={job.status} compact />
                        </div>
                      </div>
                      <div className="job-card-url mono" title={job.start_url}>
                        {job.start_url}
                      </div>
                      <div className="job-card-foot">
                        <span className="job-card-mode">{modeLabel(job.mode)}</span>
                        <span className="job-card-open">Open →</span>
                      </div>
                    </Link>
                  </li>
                ))}
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
                    {jobs.map((job) => (
                      <tr key={job.id}>
                        <td>{job.title}</td>
                        <td className="mono table-url">{job.start_url}</td>
                        <td>
                          <div className="status-cell">
                            <span className={`badge ${job.status}`}>{job.status}</span>
                            <ScanActivity status={job.status} compact />
                          </div>
                        </td>
                        <td className="muted">{job.mode}</td>
                        <td>
                          <Link className="btn" to={`/jobs/${job.id}`}>
                            Open
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
        <section className="card desktop-only">
          <h2>Quick start</h2>
          <p className="muted">
            Confirm authorization, pick a mode, choose a bundled wordlist (or upload your own), tune speed, then
            watch live progress and open the VantaCrawl HTML report.
          </p>
          <Link className="btn primary" to="/scans/new">
            New scan
          </Link>
          <div style={{ marginTop: "1.25rem" }}>{stats}</div>
        </section>
      </div>
    </div>
  );
}
