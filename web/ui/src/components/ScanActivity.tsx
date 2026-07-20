type Props = {
  status: string;
  compact?: boolean;
  label?: string;
};

const ACTIVE = new Set(["queued", "running", "stopping", "paused"]);

export default function ScanActivity({ status, compact = false, label }: Props) {
  if (!ACTIVE.has(status)) return null;

  const text =
    label ||
    (status === "queued"
      ? "Queued — waiting for worker…"
      : status === "paused"
        ? "Paused"
        : status === "stopping"
          ? "Stopping…"
          : "Scanning in progress");

  // Compact mode: pulse icon only (badge already shows the status text)
  if (compact) {
    return (
      <div
        className={`scan-activity compact icon-only ${status}`}
        role="status"
        aria-label={text}
        title={text}
      >
        <div className="scan-radar" aria-hidden="true">
          <span className="scan-ring" />
          <span className="scan-ring delay" />
          <span className="scan-core" />
          <span className="scan-sweep" />
        </div>
      </div>
    );
  }

  return (
    <div className={`scan-activity ${status}`} role="status" aria-live="polite">
      <div className="scan-radar" aria-hidden="true">
        <span className="scan-ring" />
        <span className="scan-ring delay" />
        <span className="scan-core" />
        <span className="scan-sweep" />
      </div>
      <div className="scan-activity-copy">
        <strong>{text}</strong>
        {status === "running" ? (
          <span className="muted">Live updates stream below as the crawl, enum, and security passes run.</span>
        ) : null}
        {status === "stopping" ? (
          <span className="muted">Waiting for in-flight requests to unwind. Click Force cancel if it hangs.</span>
        ) : null}
      </div>
      {status === "running" || status === "queued" ? (
        <div className="scan-bars" aria-hidden="true">
          <span />
          <span />
          <span />
          <span />
        </div>
      ) : null}
    </div>
  );
}
