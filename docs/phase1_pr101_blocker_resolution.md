# Phase-1 PR #101 blocker resolution

**Branch:** `cursor/phase1-xss-gate-metrics-32cd`  
**Do not merge** until an independent final audit re-runs.

## Blockers addressed

### 1. Provenance identity (`scan_id` empty on ledger)

**Root cause:** `crawl_orchestrator` called `run_active_vuln_probes` without `scan_id`. `CrawlStats.scan_id` was only assigned during report finalization, so every active-probe ledger row was written with `scan_id=""` and `candidate_id` prefixed `scan:`. Provenance later used the job UUID.

**Fix path:**

```
POST /api/jobs
→ worker runner  (CrawlStats.scan_id = job.id)
→ crawl_orchestrator  (ensure stats/config scan_id; pass scan_id= into probes)
→ security_scan.run_active_vuln_probes  (resolve arg → stats → once-only UUID; set ProbeModeSettings.scan_id)
→ active_probe_kit  (refuse missing identity; candidate_id = {scan_id}:cand:{path}:{family})
→ request_ledger  (every active_probe row carries scan_id)
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

- every active-probe ledger `scan_id` == job UUID
- provenance `scan_id` / `candidate_id` match confirming ledger rows
- reflected XSS confirmed; encoded terminal_negative; DOM-clobber vuln confirmed; safe not browser-confirmed
- negative-control FP 0/7
- boundary gate includes `browser_fetch` with zero Horizon imports
