/** Active / in-flight jobs cannot be deleted (must finish or stop first). */
export function canDeleteJob(status: string) {
  return !["queued", "running", "paused", "stopping", "scheduled"].includes(status);
}
