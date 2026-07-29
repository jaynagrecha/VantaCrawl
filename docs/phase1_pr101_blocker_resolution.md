# Phase-1 PR #101 blocker resolution

**Branch:** `cursor/phase1-xss-gate-metrics-32cd`  
**Do not merge** until an independent final audit re-runs.  
**Do not begin Phase 2.**

## Blockers addressed

### 1. Provenance identity (`scan_id` empty on ledger)

**Root cause:** `crawl_orchestrator` called `run_active_vuln_probes` without `scan_id`. `CrawlStats.scan_id` was only assigned during report finalization, so active-probe ledger rows were written with `scan_id=""` and `candidate_id` prefixed `scan:`. Provenance later used the job UUID.

**Residual after first fix tip `4de75e2`:** CSRF (`exploit_probes.probe_csrf`) and a second DOM-clobber ledger writer omitted `scan_id`, leaving 54/1175 active-probe rows empty. Lab job `8117ed46-…` confirmed functional gates still passed while the identity invariant failed.

**Fix path:**

```
POST /api/jobs
→ worker runner  (CrawlStats.scan_id = job.id)
→ crawl_orchestrator  (ensure stats/config scan_id; pass scan_id= into probes)
→ security_scan.run_active_vuln_probes  (resolve arg → stats → once-only UUID; set ProbeModeSettings.scan_id)
→ active_probe_kit / exploit_probes / dom_clobber.verify
→ CrawlStats.record_request  (auto-binds stats.scan_id onto every active_probe row)
→ finalize_phase1_runtime  (same sid; provenance cites confirming ledger candidate_id)
```

### 2. Incomplete dependency-boundary gate

**Root cause:** `browser_fetch.py` was absent from `production_roots`; unresolved modules returned an empty import set (silent pass).

**Fix:** Fail-closed roots (must exist), include `browser_fetch.py`, resolve entry modules or raise, detect `horizon_benchmark` with importer→import chains, assert `browser_fetch` in closure.

### 3. Selenium lock gap

**Root cause:** `dom_clobber/verify.py` `_run_negative_controls` called `browser.driver.get("about:blank")` (and post-analyze `resolve_property`) outside `selenium_driver_lock`.

**Fix:** Hold the shared process-global RLock for the entire negative/replay sequence (re-entrant with `analyze_clobber_page`).

## Explicit non-goals

- No merge of PR #101 in this task
- No Phase 2
- No PR #100 changes
- No new vulnerability/payload families or Horizon fixture aliases
- No Cloudflare / DNS / WAF / proxy changes

## Validation expectations

Fresh production Lab job against `https://horizon-catalog.onrender.com/` must show:

- every active-probe ledger `scan_id` == job UUID (zero empty)
- provenance `scan_id` / `candidate_id` match confirming ledger rows
- reflected XSS confirmed; encoded terminal_negative; DOM-clobber vuln confirmed; safe not browser-confirmed
- negative-control FP 0/7
- boundary gate includes `browser_fetch` with zero Horizon imports
