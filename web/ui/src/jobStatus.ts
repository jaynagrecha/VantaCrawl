/** Active / in-flight jobs cannot be deleted (must finish or stop first). */
export function canDeleteJob(status: string) {
  return !["queued", "running", "paused", "stopping", "scheduled"].includes(status);
}

/** Job lifecycle badge label — never show raw snake_case / lowercase in the UI. */
export function formatJobStatus(status: string): string {
  const s = String(status || "").trim().toLowerCase();
  const labels: Record<string, string> = {
    queued: "Queued",
    scheduled: "Scheduled",
    running: "Running",
    paused: "Paused",
    stopping: "Stopping",
    completed: "Completed",
    cancelled: "Cancelled",
    canceled: "Cancelled",
    failed: "Failed",
    stopped: "Stopped",
  };
  return labels[s] || (s ? s.charAt(0).toUpperCase() + s.slice(1) : "Unknown");
}

/** Mode / profile slug → readable label (`full_audit` → `full audit`). */
export function formatModeLabel(mode: string): string {
  return String(mode || "")
    .replace(/_/g, " ")
    .trim();
}

/**
 * Report completeness from progress / snapshot — separate from job lifecycle.
 * A job can be Completed while the assessment report is still Partial (mid-export).
 */
export function formatScanCompleteness(progress: Record<string, unknown> | null | undefined): string | null {
  if (!progress || typeof progress !== "object") return null;
  const raw = String(
    progress.scan_status || progress.report_status || progress.scan_completeness || ""
  )
    .trim()
    .toLowerCase();
  if (raw === "final" || raw === "complete" || raw === "completed") return "Report final";
  if (raw === "partial") return "Report partial";
  if (raw === "stopped") return "Report stopped";
  return null;
}

export function scanCompletenessClass(label: string | null): string {
  if (!label) return "";
  if (label.includes("final")) return "report-final";
  if (label.includes("partial")) return "report-partial";
  if (label.includes("stopped")) return "report-stopped";
  return "";
}
