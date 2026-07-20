import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Job } from "../api";

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

  return (
    <div>
      <div className="grid-2">
        <section className="card">
          <h1>Scan jobs</h1>
          <p className="lead">Live queue of crawls, enums, and security assessments.</p>
          {error && <div className="error">{error}</div>}
          {jobs.length === 0 ? (
            <p className="muted">No jobs yet. Start your first authorized scan.</p>
          ) : (
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
                    <td className="mono" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {job.start_url}
                    </td>
                    <td>
                      <span className={`badge ${job.status}`}>{job.status}</span>
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
          )}
        </section>
        <section className="card">
          <h2>Quick start</h2>
          <p className="muted">
            Confirm authorization, pick a mode (Fast Scan / Site Map / Full Audit), tune speed, then watch live
            progress and open the VantaCrawl HTML report.
          </p>
          <Link className="btn primary" to="/scans/new">
            New scan
          </Link>
          <div className="stats" style={{ marginTop: "1.25rem" }}>
            <div className="stat">
              <div className="stat-num">{jobs.length}</div>
              <div className="stat-label">Jobs</div>
            </div>
            <div className="stat">
              <div className="stat-num">{jobs.filter((j) => j.status === "running").length}</div>
              <div className="stat-label">Running</div>
            </div>
            <div className="stat">
              <div className="stat-num">{jobs.filter((j) => j.status === "completed").length}</div>
              <div className="stat-label">Done</div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
