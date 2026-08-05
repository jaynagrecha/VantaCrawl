# Phase-1 PR #101 blocker resolution

**Branch:** `cursor/phase1-xss-gate-metrics-32cd`  
**PR tip:** `dc452cefca134397b075e74c25028a3979749c58`  
**Do not merge** until an independent final audit re-runs.  
**Do not begin Phase 2.**

## Blockers addressed

### 1. Provenance identity (`scan_id` empty on ledger)

**Root cause:** `crawl_orchestrator` called `run_active_vuln_probes` without `scan_id`. `CrawlStats.scan_id` was only assigned during report finalization, so active-probe ledger rows were written with `scan_id=""` and `candidate_id` prefixed `scan:`. Provenance later used the job UUID.

**Residual after tip `4de75e2`:** CSRF (`exploit_probes.probe_csrf`) and a second DOM-clobber ledger writer omitted `scan_id` (54/1175 empty rows on job `8117ed46-…`).

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

## Fresh production Lab validation

| Field | Value |
|-------|-------|
| Tip SHA | `dc452cefca134397b075e74c25028a3979749c58` |
| API deploy | `dep-d9l4rq2d0e5s73eqb92g` @ tip |
| Worker deploy | `dep-d9l4rs1t0dsc73fq2v60` @ tip |
| Lab job | `0d0f3167-1f70-4a1f-ae3c-8297d1f605ae` |
| Target | `https://horizon-catalog.onrender.com/` |
| Suite | 767 passed, 33 warnings |
| Active-probe ledger empty `scan_id` | **0 / 1167** |
| Reflected XSS | `terminal_confirmed` / `browser_execution_confirmed` |
| Encoded XSS | `terminal_negative` / `reflected_only` (0 browser confirms) |
| DOM-clobber vuln | `terminal_confirmed` / `browser_execution_confirmed` |
| DOM-clobber safe | `terminal_negative` / `clobbered_value_consumed` (0 browser confirms) |
| Negative-control FP | **0 / 7** |
| Dependency closure | 37 modules; `browser_fetch` included; 0 Horizon imports/literals |

Artifacts: `/opt/cursor/artifacts/phase1_blocker_resolution_r2/` (and timestamped copy).

## Explicit non-goals

- No merge of PR #101 in this task
- No Phase 2
- No PR #100 changes
- No new vulnerability/payload families or Horizon fixture aliases
- No Cloudflare / DNS / WAF / proxy changes

## Verdict

**READY FOR INDEPENDENT FINAL AUDIT**
