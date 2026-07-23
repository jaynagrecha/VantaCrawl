import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, getToken, Job } from "../api";
import ScanActivity from "../components/ScanActivity";
import {
  canDeleteJob,
  formatJobStatus,
  formatScanCompleteness,
  scanCompletenessClass,
} from "../jobStatus";

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

function formatEta(seconds: unknown): string {
  if (seconds == null || seconds === "") return "—";
  const n = Number(seconds);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 60) return `~${Math.round(n)}s`;
  return `~${formatDuration(n)}`;
}

function phaseLabel(phase: unknown): string {
  const p = String(phase || "").toLowerCase();
  if (p === "crawl") return "Crawl";
  if (p === "enum") return "Directory enum";
  if (p === "api_recon") return "API recon";
  if (p === "download") return "Download";
  if (p === "security") return "Security";
  if (p === "recon") return "Recon";
  if (p === "starting") return "Starting";
  if (p === "complete" || p === "completed" || p === "final") return "Complete";
  if (p === "cancelled" || p === "canceled") return "Cancelled";
  if (p === "failed") return "Failed";
  if (p === "stopped") return "Stopped";
  if (p === "partial") return "Partial";
  return p ? p.charAt(0).toUpperCase() + p.slice(1) : "Running";
}

function tileValue(value: unknown, fallback = "0"): string {
  if (value == null || value === "") return fallback;
  return String(value);
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

/** Match backend user_output.format_duration_friendly for Progress: lines. */
function formatDurationFriendly(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const rem = total % 3600;
  const minutes = Math.floor(rem / 60);
  const secs = rem % 60;
  if (hours) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  if (minutes) return `${minutes}m ${String(secs).padStart(2, "0")}s`;
  return `${secs}s`;
}

/** Prefer crawl elapsed_seconds; fall back to job wall clock before first stats. */
function scanDurationSeconds(
  job: Job,
  progress: Record<string, unknown>,
  nowMs: number,
  elapsedSyncedAtMs: number
): number | null {
  const crawl = Number(progress.elapsed_seconds);
  const active = ["queued", "running", "paused", "stopping", "scheduled"].includes(job.status);
  const hasCrawlClock =
    Number.isFinite(crawl) &&
    crawl >= 0 &&
    (crawl > 0 || Number(progress.pages_crawled) > 0 || Number(progress.findings) > 0);

  if (hasCrawlClock) {
    if (!active || job.status === "paused") return crawl;
    // Soft tick between worker progress publishes (~1.5s)
    const drift = Math.max(0, (nowMs - elapsedSyncedAtMs) / 1000);
    return crawl + Math.min(drift, 3);
  }
  return jobDurationSeconds(job, nowMs);
}

function withLiveElapsed(text: string, elapsedSecs: number | null): string {
  if (!text.startsWith("Progress:") || elapsedSecs == null || !Number.isFinite(elapsedSecs)) {
    return text;
  }
  const label = formatDurationFriendly(elapsedSecs);
  return text.replace(/(?:\d+h\s+\d{2}m|\d+m\s+\d{2}s|\d+s)\s+elapsed/, `${label} elapsed`);
}

export default function JobPage() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [logExtra, setLogExtra] = useState("");
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [artifacts, setArtifacts] = useState<{ name: string; path: string; size: number; kind: string }[]>([]);
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const logRef = useRef<HTMLDivElement | null>(null);
  const stickToBottom = useRef(true);
  const elapsedSyncedAtRef = useRef(Date.now());
  const lastElapsedRef = useRef<number | null>(null);

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

  // If Stop hangs on in-flight HTTP, escalate to force-cancel automatically
  useEffect(() => {
    if (!id || !job || job.status !== "stopping") return;
    const t = setTimeout(() => {
      api
        .forceCancelJob(id)
        .then(() => api.getJob(id))
        .then((j) => setJob(j))
        .catch(() => undefined);
    }, 8000);
    return () => clearTimeout(t);
  }, [id, job?.status]);

  useEffect(() => {
    if (!id || !job) return;
    if (!["completed", "failed", "cancelled"].includes(job.status) && !job.report_html_path) return;
    api.listArtifacts(id).then(setArtifacts).catch(() => setArtifacts([]));
  }, [id, job?.status, job?.report_html_path]);

  const progress = job?.progress_json || {};
  useEffect(() => {
    const e = Number(progress.elapsed_seconds);
    if (!Number.isFinite(e)) return;
    if (lastElapsedRef.current !== e) {
      lastElapsedRef.current = e;
      elapsedSyncedAtRef.current = Date.now();
    }
  }, [progress.elapsed_seconds]);

  const logText = useMemo(() => {
    const base = job?.log_tail || "";
    return (base + logExtra).slice(-24000);
  }, [job, logExtra]);

  useEffect(() => {
    const el = logRef.current;
    if (!el || !stickToBottom.current) return;
    el.scrollTop = el.scrollHeight;
  }, [logText]);

  async function runAction(kind: "pause" | "resume" | "stop" | "force-cancel" | "summary-report") {
    if (!job) return;
    setActionError("");
    try {
      if (kind === "pause") await api.pauseJob(job.id);
      if (kind === "resume") await api.resumeJob(job.id);
      if (kind === "stop") await api.stopJob(job.id);
      if (kind === "force-cancel") await api.forceCancelJob(job.id);
      if (kind === "summary-report") await api.buildSummaryReport(job.id);
      const fresh = await api.getJob(job.id);
      setJob(fresh);
    } catch (err: any) {
      setActionError(String(err.message || err));
    }
  }

  if (!job) {
    return <div className="card muted">{error || "Loading job…"}</div>;
  }

  const jobFinished = ["completed", "failed", "cancelled"].includes(job.status);
  const reportReady = Boolean(job.report_html_path);
  const tok = encodeURIComponent(getToken() || "");
  const htmlUrl = `/api/reports/${job.id}/html?token=${tok}`;
  const techUrl = `/api/reports/${job.id}/technical.html?token=${tok}`;
  const txtUrl = `/api/reports/${job.id}/txt?token=${tok}`;
  const embedUrl = `/api/reports/${job.id}/embed?token=${tok}`;
  const logUrl = `/api/reports/${job.id}/log?token=${tok}`;
  const zipUrl = `/api/reports/${job.id}/bundle.zip?token=${tok}`;
  const durationSecs = scanDurationSeconds(job, progress as Record<string, unknown>, nowMs, elapsedSyncedAtRef.current);
  const durationLabel = durationSecs == null ? "—" : formatDuration(durationSecs);
  const progressLine = withLiveElapsed(
    String(progress.progress_text || ""),
    durationSecs
  );

  const canPause = job.status === "running" || job.status === "queued";
  const canResume = job.status === "paused" || job.status === "scheduled";
  const canStop = !["completed", "cancelled", "failed"].includes(job.status);
  const canDelete = canDeleteJob(job.status);

  async function deleteThisJob() {
    if (!job || !canDelete) return;
    const ok = window.confirm(`Delete “${job.title || "this scan"}”? Reports and logs will be removed.`);
    if (!ok) return;
    setDeleting(true);
    setActionError("");
    try {
      await api.deleteJob(job.id);
      nav("/");
    } catch (err) {
      setActionError(String((err as Error).message || err));
      setDeleting(false);
    }
  }

  const enumHits = (progress.enum_hit_urls as string[]) || [];
  const enumHitCount = Number(progress.enum_hits) || 0;
  const phaseKeyForHits = String(progress.phase || "");
  const isApiReconHits = phaseKeyForHits === "api_recon";
  const isSubReconHits =
    phaseKeyForHits === "recon" &&
    (Number(progress.subdomain_probes_total) > 0 ||
      String(progress.enum_probing || "")
        .toLowerCase()
        .includes("subdomain"));
  const hitsListLabel = isApiReconHits ? "API hits" : isSubReconHits ? "Sub hits" : "Enum hits";
  const findings =
    (progress.findings_preview as {
      severity?: string;
      title?: string;
      url?: string;
      category?: string;
      secret_type?: string;
      impact?: string;
      validation?: string;
      impact_summary?: string;
      evidence_masked?: string;
      evidence_full?: string;
    }[]) || [];

  return (
    <div>
      <section className="card">
        <div className="page-head">
          <div className="page-head-copy">
            <h1>{job.title}</h1>
            <p className="mono muted page-head-url">
              {job.start_url}
            </p>
          </div>
          <div className="page-actions">
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
            {canDelete ? (
              <button className="btn danger" type="button" disabled={deleting} onClick={deleteThisJob}>
                {deleting ? "Deleting…" : "Delete"}
              </button>
            ) : null}
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
          <div className="status-cell" style={{ marginTop: "1rem" }}>
            <span className={`badge ${job.status}`}>{formatJobStatus(job.status)}</span>
            {(() => {
              const reportLabel = formatScanCompleteness(progress);
              return reportLabel ? (
                <span className={`badge ${scanCompletenessClass(reportLabel)}`}>{reportLabel}</span>
              ) : null;
            })()}
          </div>
        )}
        {(() => {
          const pct = Math.max(0, Math.min(100, Number(progress.progress_pct) || 0));
          const wordsDone = Number(progress.enum_words_tested) || 0;
          const wordsTotal = Number(progress.enum_words_total) || 0;
          const pagesEst = Number(progress.pages_estimate) || 0;
          const pages = Number(progress.pages_crawled) || 0;
          const active = ["queued", "running", "paused", "stopping"].includes(job.status);
          const health = String(progress.health || (active ? "Waiting" : "—"));
          const healthClass =
            health === "Challenged" || health === "Degraded"
              ? "warn"
              : health === "Slowing" || health === "Noisy" || health === "Waiting"
                ? "caution"
                : "ok";
          const heartbeat = String(progress.heartbeat || "");
          const backoffRem = Number(progress.backoff_remaining_seconds) || 0;
          const heartbeatLine =
            heartbeat ||
            (backoffRem > 0.4 ? `Waiting on WAF backoff… ${Math.ceil(backoffRem)}s` : "");
          const probingLine = String(progress.enum_probing || "");
          const phaseKey = String(progress.phase || "");
          const isApiRecon = phaseKey === "api_recon";
          const isSubRecon =
            phaseKey === "recon" &&
            (Number(progress.subdomain_probes_total) > 0 ||
              (Number(progress.enum_words_total) > 0 &&
                String(progress.enum_probing || "")
                  .toLowerCase()
                  .includes("subdomain")));
          const hitsLabel = isApiRecon ? "API hits" : isSubRecon ? "Sub hits" : "Enum hits";
          const wordsLabel = isApiRecon ? "API probes" : isSubRecon ? "Subdomains" : "Enum words";
          const probingValue =
            isApiRecon || isSubRecon
              ? String(progress.enum_current_path || progress.enum_current_word || "—")
              : String(progress.enum_current_word || "—");
          const wordsHint = isApiRecon
            ? probingLine || "Active API path probes completed / planned"
            : isSubRecon
              ? probingLine || "Subdomain hosts probed / planned"
              : probingLine || "Words tried from the directory wordlist";
          const probingHint = isApiRecon
            ? probingLine || "Current API path under test (including during WAF backoff)"
            : isSubRecon
              ? probingLine || "Current subdomain host under test"
              : probingLine || "Current folder/file name under test";
          const etaHint =
            phaseKey === "enum"
              ? "Based on enum-phase speed (not whole-job time). Hidden until warm-up."
              : isApiRecon
                ? "Based on API probe speed. Hidden until warm-up."
                : undefined;
          const tiles: { label: string; value: string; hint?: string; tone?: string }[] = [
            { label: "Phase", value: phaseLabel(progress.phase), tone: "phase" },
            { label: "Progress", value: `${pct}%` },
            {
              label: "Pages",
              value: pagesEst > 0 ? `${pages}/${pagesEst}` : tileValue(pages),
            },
            { label: hitsLabel, value: tileValue(progress.enum_hits) },
            { label: "Findings", value: tileValue(progress.findings) },
            { label: "Duration", value: durationLabel },
            { label: "Queue", value: tileValue(progress.queue_size) },
            {
              label: wordsLabel,
              value:
                wordsTotal > 0
                  ? `${wordsDone.toLocaleString()}/${wordsTotal.toLocaleString()}`
                  : tileValue(wordsDone),
              hint: wordsHint,
            },
            {
              label: "ETA",
              value: formatEta(progress.eta_seconds),
              hint: etaHint,
            },
            {
              label: "Probing",
              value: probingValue,
              hint: probingHint,
              tone: "text",
            },
            {
              label: "Health",
              value: health,
              hint: String(progress.health_detail || "Waiting for worker progress events"),
              tone: healthClass,
            },
            {
              label: "Blocks",
              value: tileValue(progress.challenge_events ?? progress.blocks),
              hint:
                Number(progress.access_deny_count || 0) > 0
                  ? `WAF/bot challenges — separate from ${progress.access_deny_count} HTTP access denie(s) (401/403)`
                  : "WAF/bot challenges (403/429/etc.) — not the same as Errors or bare Netlify 403s",
            },
            {
              label: "Denies",
              value: tileValue(progress.access_deny_count),
              hint: "HTTP 401/403/405 without a WAF fingerprint (common on Netlify/Vercel)",
            },
            {
              label: "Errors",
              value:
                progress.error_rate_pct != null && Number(progress.errors) > 0
                  ? `${tileValue(progress.errors)} (${progress.error_rate_pct}%)`
                  : tileValue(progress.errors),
              hint: "Failed page fetches — rate matters more than raw count",
            },
            {
              label: "Pages/min",
              value: tileValue(progress.urls_per_minute),
            },
            {
              label: "Protections",
              value: String(progress.protections_label || "none"),
              hint:
                Array.isArray(progress.protections_detail) && progress.protections_detail.length
                  ? "Evidence-backed inventory below — active vs passive"
                  : Array.isArray(progress.protections) && progress.protections.length
                    ? `Detected: ${(progress.protections as string[]).join(", ")}`
                    : "Bot/WAF fingerprints seen so far",
              tone: "text",
            },            { label: "Mode", value: job.mode, tone: "text" },
          ];
          const journal = Array.isArray(progress.block_journal) ? progress.block_journal : [];
          const protectionsDetail = Array.isArray(progress.protections_detail)
            ? (progress.protections_detail as Array<{
                vendor?: string;
                display?: string;
                category_label?: string;
                confidence?: number;
                confidence_label?: string;
                scope?: string;
                active?: boolean;
                tier?: string;
                evidence?: string[];
                challenge_count?: number;
                sample_urls?: string[];
              }>)
            : [];
          const outcome = (progress.outcome_breakdown || {}) as Record<string, number>;
          const outcomeLine = [
            outcome.waf_challenge_responses != null
              ? `WAF challenges: ${outcome.waf_challenge_responses}`
              : "",
            outcome.http_403_responses != null ? `HTTP 403: ${outcome.http_403_responses}` : "",
            outcome.http_429_responses != null ? `HTTP 429: ${outcome.http_429_responses}` : "",
            outcome.access_denies != null ? `Access denies: ${outcome.access_denies}` : "",
            outcome.scope_denied_urls != null ? `Scope skipped: ${outcome.scope_denied_urls}` : "",
            outcome.connection_failures != null
              ? `Conn. failures: ${outcome.connection_failures}`
              : "",
          ]
            .filter(Boolean)
            .join(" · ");
          const statusCounts = (progress.block_status_counts || {}) as Record<string, number>;
          const denyCounts = (progress.access_deny_status_counts || {}) as Record<string, number>;
          const statusSummary = Object.entries(statusCounts)
            .sort((a, b) => Number(b[1]) - Number(a[1]))
            .slice(0, 6)
            .map(([code, count]) => `${code}×${count}`)
            .join(" · ");
          const denySummary = Object.entries(denyCounts)
            .sort((a, b) => Number(b[1]) - Number(a[1]))
            .slice(0, 4)
            .map(([code, count]) => `${code}×${count}`)
            .join(" · ");
          const tierLabel = (tier?: string) => {
            switch (tier) {
              case "confirmed_active":
                return "Confirmed active";
              case "page_level":
                return "Page-level control";
              case "passive":
                return "Passive indicator";
              case "unconfirmed":
                return "Unconfirmed";
              case "conflicting":
                return "Conflicting fingerprint";
              default:
                return tier || "Detected";
            }
          };
          return (
            <div className="progress-panel" style={{ marginTop: "1.1rem" }}>
              <div className="progress-track" aria-hidden="true">
                <div className={`progress-fill ${active ? "live" : ""}`} style={{ width: `${pct}%` }} />
              </div>
              <p className="progress-line muted">
                {progressLine || (active ? "Waiting for first progress update…" : "—")}
              </p>
              {probingLine ? (
                <p
                  className="progress-probing"
                  title={
                    isApiRecon
                      ? "Current API path being probed"
                      : "Current directory/file name being probed"
                  }
                >
                  {probingLine}
                </p>
              ) : null}
              {heartbeatLine ? (
                <p className="progress-heartbeat" title="Scanner is paused briefly after a WAF/rate-limit signal">
                  {heartbeatLine}
                </p>
              ) : null}
              <div className="stats cockpit">
                {tiles.map((t) => (
                  <div
                    key={t.label}
                    className={`stat ${t.tone ? `stat-${t.tone}` : ""}`}
                    title={t.hint || undefined}
                  >
                    <div className="stat-num">{t.value}</div>
                    <div className="stat-label">{t.label}</div>
                  </div>
                ))}
              </div>
              {outcomeLine ? (
                <p className="muted outcome-breakdown" title="Request outcome split — not the same as Blocks vs Denies tiles">
                  {outcomeLine}
                </p>
              ) : null}
              {protectionsDetail.length > 0 ? (
                <div className="protections-inventory">
                  <div className="block-journal-head">
                    <h3>Protections inventory</h3>
                    <span className="muted">Evidence · confidence · scope</span>
                  </div>
                  <p className="muted block-journal-help">
                    Confirmed active needs vendor identity (cookie/header) plus challenge behaviour.
                    Page-level CAPTCHAs stay separate from site-wide edge WAFs. Passive = JS/string
                    shadow only.
                  </p>
                  <ul className="protections-list">
                    {protectionsDetail.map((row) => (
                      <li key={row.vendor || row.display} className={`prot-item tier-${row.tier || "unconfirmed"}`}>
                        <div className="prot-item-head">
                          <strong>{row.display || row.vendor}</strong>
                          <span className="badge prot-tier">{tierLabel(row.tier)}</span>
                          <span className="muted">
                            {row.confidence_label || "Low"} · {row.category_label || ""} · scope{" "}
                            {row.scope || "host"}
                          </span>
                        </div>
                        {row.evidence && row.evidence.length ? (
                          <div className="prot-evidence mono">
                            {row.evidence.slice(0, 6).join(" · ")}
                            {row.evidence.length > 6 ? ` · +${row.evidence.length - 6}` : ""}
                          </div>
                        ) : null}
                        {row.sample_urls && row.sample_urls.length ? (
                          <div className="prot-urls muted" title={row.sample_urls.join("\n")}>
                            Affects: {row.sample_urls[0]}
                            {row.challenge_count ? ` · ${row.challenge_count} challenge hit(s)` : ""}
                          </div>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {(journal.length > 0 || statusSummary || denySummary) && (
                <div className="block-journal">
                  <div className="block-journal-head">
                    <h3>Block / challenge journal</h3>
                    {statusSummary ? (
                      <span className="muted" title="WAF/bot challenge HTTP statuses only">
                        WAF: {statusSummary}
                      </span>
                    ) : null}
                  </div>
                  <p className="muted block-journal-help">
                    WAF statuses above are bot-wall challenges only — not bare 401/403 permission
                    denials. Those count in the Denies tile
                    {denySummary ? ` (${denySummary})` : ""}. When there are no WAF catches yet,
                    a few recent deny samples may appear below (not a full list). Full headers +
                    body snippets land in the defense report.
                  </p>
                  {journal.length === 0 ? (
                    <p className="muted">Waiting for the first WAF challenge…</p>
                  ) : (
                    <ul className="block-journal-list">
                      {[...journal].reverse().map((ev: any, idx: number) => {
                        const signal = String(ev.signal || "block");
                        const prots = (ev.protections || []).filter(
                          (p: string) => p && p.toLowerCase() !== signal.toLowerCase()
                        );
                        return (
                        <li key={`${ev.url}-${ev.time}-${ev.time_unix || idx}-${idx}`} className="block-journal-item">
                          <div className="block-journal-meta">
                            <span className="badge status">HTTP {ev.status || "?"}</span>
                            <span className="badge signal" title="Challenge / block signal">
                              {signal}
                            </span>
                            {prots.slice(0, 3).map((p: string) => (
                              <span key={p} className="badge prot" title="Protection fingerprint">
                                {p}
                              </span>
                            ))}
                            <span className="muted" title="Event time (IST)">
                              {ev.time || ""}
                            </span>
                          </div>
                          <div className="block-journal-url" title={ev.url}>
                            {ev.url}
                          </div>
                          {ev.reason ? <div className="block-journal-reason">{ev.reason}</div> : null}
                        </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              )}
            </div>
          );
        })()}
      </section>

      <section className="card">
        <div className="section-head">
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

      {(enumHits.length > 0 || enumHitCount > 0 || findings.length > 0) && (
        <section className="card">
          <h2>Results</h2>
          <div className="grid-2">
            <div>
              <h3 style={{ marginTop: 0 }}>
                {hitsListLabel}
                {enumHitCount > 0 ? (
                  <span className="muted" style={{ fontWeight: 400, marginLeft: ".35rem" }}>
                    ({enumHitCount})
                  </span>
                ) : null}
              </h3>
              {enumHits.length === 0 ? (
                <p className="muted">
                  {enumHitCount > 0
                    ? `${enumHitCount} recorded — URL list not synced yet (refreshing…)`
                    : "None yet"}
                </p>
              ) : (
                <ul className="hits-list mono">
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
            <div className="findings-panel">
              <h3 style={{ marginTop: 0 }}>Findings</h3>
              {findings.length === 0 ? (
                <p className="muted">None yet</p>
              ) : (
                <ul className="findings-list">
                  {findings.map((f, i) => {
                    const secretKey = `${f.url || ""}-${i}`;
                    const impact = String(f.impact || "");
                    const title = String(f.title || "");
                    const impactFromTitle =
                      /Impact:\s*(possible_credential|stealable_credential)/i.exec(title)?.[1] ||
                      "";
                    const effectiveImpact = impact || impactFromTitle;
                    const isCredentialImpact =
                      effectiveImpact === "possible_credential" ||
                      effectiveImpact === "stealable_credential" ||
                      /Cookie\s+`[^`]+`/i.test(title);
                    const isSecretCategory =
                      f.category === "secrets_exposure" ||
                      Boolean(f.secret_type) ||
                      isCredentialImpact;
                    const hasEvidence = Boolean(f.evidence_full || f.evidence_masked);
                    const masked = f.evidence_masked || "";
                    const full = f.evidence_full || "";
                    const looksMasked = (s: string) => /…|\.\.\./.test(s) || s.includes("***");
                    const canReveal =
                      isSecretCategory &&
                      Boolean(full) &&
                      !looksMasked(full) &&
                      (full.length > masked.length || full !== masked || Boolean(masked));
                    const patternEvidence = !isSecretCategory
                      ? full || masked || ""
                      : "";
                    const shown = revealedSecrets[secretKey]
                      ? full || masked || ""
                      : masked || (canReveal ? "••••" : full || "");
                    return (
                      <li key={secretKey} className="finding-item">
                        <div className="finding-meta">
                          <strong className={`badge ${f.severity || "info"}`}>
                            {f.severity || "info"}
                          </strong>
                          {effectiveImpact ? (
                            <span className="secret-type-pill" title={f.impact_summary || ""}>
                              {effectiveImpact}
                              {f.validation ? `/${f.validation}` : ""}
                            </span>
                          ) : null}
                          {f.secret_type ? (
                            <span className="secret-type-pill">{f.secret_type}</span>
                          ) : null}
                        </div>
                        <div className="finding-title">{f.title || "Finding"}</div>
                        {f.url ? (
                          <a className="finding-url mono" href={f.url} target="_blank" rel="noreferrer">
                            {f.url}
                          </a>
                        ) : null}
                        {isSecretCategory && hasEvidence ? (
                          <div className="secret-reveal-row">
                            <span className="muted">matched:</span>
                            <code className="mono">{shown}</code>
                            {canReveal ? (
                              <button
                                className="btn secret-reveal-btn"
                                type="button"
                                onClick={() =>
                                  setRevealedSecrets((prev) => ({
                                    ...prev,
                                    [secretKey]: !prev[secretKey],
                                  }))
                                }
                              >
                                {revealedSecrets[secretKey] ? "Hide" : "Show full"}
                              </button>
                            ) : null}
                          </div>
                        ) : null}
                        {!isSecretCategory && patternEvidence ? (
                          <div className="secret-reveal-row">
                            <span className="muted">matched:</span>
                            <code className="mono">{patternEvidence}</code>
                          </div>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </section>
      )}

      <section className="card">
        <h2>Report & artifacts</h2>
        {!reportReady ? (
          <div>
            <p className="muted">
              {jobFinished
                ? "This job may still be linked to a thin summary. Rebuild the full assessment (explanations + recommendations) from findings collected so far."
                : "Full assessment report (with explanations) is written on stop/cancel from findings so far."}
            </p>
            {jobFinished ? (
              <button
                className="btn primary"
                type="button"
                style={{ marginTop: ".75rem" }}
                onClick={() => runAction("summary-report")}
              >
                Rebuild full assessment report
              </button>
            ) : null}
          </div>
        ) : (
          <>
            <div className="page-actions report-actions">
              <a className="btn primary" href={htmlUrl} target="_blank" rel="noreferrer">
                Open assessment report
              </a>
              <a className="btn" href={techUrl} target="_blank" rel="noreferrer">
                Open technical report
              </a>
              <a className="btn" href={txtUrl} target="_blank" rel="noreferrer">
                Download assessment text
              </a>
              <a className="btn" href={zipUrl}>
                Download all (zip)
              </a>
              {jobFinished ? (
                <button className="btn" type="button" onClick={() => runAction("summary-report")}>
                  Rebuild full assessment
                </button>
              ) : null}
            </div>
            <p className="muted" style={{ marginTop: 0, marginBottom: ".85rem" }}>
              Assessment = executive + engineer dual report with explanations and recommendations.
              If you only see a thin cancel summary, click <strong>Rebuild full assessment</strong>.
            </p>
            {artifacts.length > 0 ? (
              <div className="artifact-block">
                <div className="artifact-block-head">
                  <h3>Files</h3>
                  <span className="muted">{artifacts.length} artifact{artifacts.length === 1 ? "" : "s"}</span>
                </div>
                <ul className="artifact-list">
                  {artifacts.map((a) => {
                    const kb = Math.max(1, Math.round(a.size / 1024));
                    const href = `/api/reports/${job.id}/artifacts/${encodeURIComponent(a.path)}?token=${tok}`;
                    const kind = (a.kind || "").trim();
                    return (
                      <li key={a.path} className="artifact-row">
                        <div className="artifact-info">
                          <div className="artifact-name mono" title={a.name}>
                            {a.name}
                          </div>
                          <div className="artifact-meta">
                            <span>{kb} KB</span>
                            {kind ? <span className="artifact-kind">{kind}</span> : null}
                          </div>
                        </div>
                        <a className="btn primary artifact-dl" href={href} download={a.name}>
                          Download
                        </a>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}
            <iframe className="report-frame" title="Report" src={embedUrl} />
          </>
        )}
      </section>
    </div>
  );
}
