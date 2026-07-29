# Stacked PR Integrity & Live-Verification Audit

**Date:** 2026-07-29  
**Branches audited:** PR #97 `cursor/dom-clobber-generic-verify-32cd`, PR #98 `cursor/verifier-framework-phase1-32cd`  
**Audit branch:** `cursor/stacked-pr-integrity-audit-32cd`  
**Phase 2:** not started  
**Auto-merge:** none (verdicts only)

---

## Claim (evidence-backed)

> VantaCrawl has a generic DOM-clobber verifier and a generic verification framework. Individual family capabilities are reported according to their implementation and live-validation maturity.

**Not claimed:** the entire Phase-1 set is dynamically live-verified.

---

## PART A — PR #97 genericity

### Hardcode sweep (production)

Search of production scanner modules for Horizon domain/routes, `defaultConfig`, `appSettings`, randomized fixture IDs (`d58cf6a6`, `cfgBlob…`, `markup_…`, etc.): **0 hits**.

Property names appear only in tests, Horizon playground fixtures, and generated evidence.

### Required DOM-clobber audit table

See `pr97_dom_clobber_audit_table.md` / `.json`.

| target | randomized | confirmed? | result_state |
|---|---|---|---|
| non-Horizon vuln | route+param+property | yes | `controlled_request_confirmed` |
| non-Horizon safe | same IDs | no (not high-confirmed) | `clobbered_value_consumed` |
| Horizon `/xss/dom-clobber` | no | yes | `browser_execution_confirmed` |
| Horizon `/xss/dom-clobber-safe` | no | no | `clobbered_value_consumed` |
| Horizon `app-settings` | no | yes | `browser_execution_confirmed` |
| Horizon `media-embed` | no | no | `clobbered_value_consumed` (partial) |
| Horizon `widget-cfg` | no | no findings | form-only surface not exercised end-to-end in this pass |

Randomized fixture lived only under `/tmp/rand_dom_clobber_app/` — **not** added to production code.

Discovery correctly preferred global `cfgBlobd58cf6a6` over local alias `tmpAliasd58cf6a6`.

### PR #96

**Closed as superseded** (not merged): https://github.com/jaynagrecha/VantaCrawl/pull/96

### PR #97 residual notes

- Safe controls correctly avoid E-tier confirmation; they still emit ladder-C medium observations.
- `widget-cfg` (form id clobber) and `media-embed` need fuller Lab coverage before claiming those variants live-validated individually.
- Live Render `horizon-catalog` is **stale** relative to PR #97 playground (variants 404; `/oob/.../proof.js` 404). Local playground from stacked tip used for evidence. Deploy of updated fixtures is a blocker before production Lab recall.

### Verdict — PR #97: **merge**

Generic source-to-sink verifier is demonstrated on Horizon + non-Horizon randomized app without production hardcodes. Merge when ready; do not treat as auto-merged by this audit.

---

## PART B — PR #98 classification audit

### Prior claim

`155 = 48 supported_active + 89 passive_manual + 18 unsupported` — **inflated**.  
`supported_active` was assigned whenever a registry `cap_id` existed (contract/adapter presence).

### Revised (maturity-aware, this audit branch)

| bucket | count |
|---|---|
| catalog_fixtures | **155** |
| supported_active | **39** |
| passive_manual | **98** |
| unsupported | **18** |

### Capability maturity counts

| maturity | count |
|---|---|
| contract_only | 107 |
| registered_adapter | 9 |
| executable_unvalidated | 34 |
| live_validated | **5** (DOM-clobber fixtures after this audit’s live marks) |

**Published live recall denominator = 5** (live_validated only).

### Demotions from the former “48”

Examples moved out of `supported_active`:

- CSRF `/csrf/action` → `passive_manual` (`incomplete_lifecycle:replay`)
- Partial XSS subtypes (`/xss/angular`, `postmessage`, `stored`, `svg`, `dom`, …) → `passive_manual`
- Authz/private/graphql “supported_required” without Phase-1 impl → `unsupported` / contract_only

Full matrix: `fixture_inventory_revised.json`.

### Verdict — PR #98: **changes required**

Must land maturity-aware classification + anti-inflation tests (this audit branch) before merge. Do **not** publish live recall from the prior 48.

---

## PART C — Phase-1 live samples (no merge)

Local Horizon playground `http://127.0.0.1:19081` (PR #97/#98 tip). Render deploy skipped (Render MCP unauthorized / no workspace selected).

Lifecycle samples: `phase1_lifecycle_rows.json`

| family | sample result_state | notes |
|---|---|---|
| SQLi | differential_signal | probe+behavior; not marked live_validated catalog-wide |
| RCE | marker_output_signal | not full server_exec on arith surface |
| command_injection | server_execution_confirmed | sample TP signal |
| SSTI | server_execution_confirmed | sample TP signal |
| XSS | html_injection | browser ladder incomplete on sample |
| SSRF | reflected_only | no attributable OOB in this window |
| open redirect | server_execution_confirmed | sample TP signal |
| traversal | differential_signal | canary not configured |
| CRLF | server_execution_confirmed | sample TP signal |
| CSRF | no honest CSRF confirm | demoted maturity |
| DOM clobber | browser_execution_confirmed | **live_validated** |

Weak states were **not** converted into true positives for recall.

### Safe / Extended / Lab denominators (inventory)

- **supported_active denominator (executable):** 39  
- **live_validated published live recall denominator:** 5  
- Full mode benchmark matrix against live Render **not** completed (fixtures undeployed). Local Lab samples only.

### Negative-control FP rate (empty ledger evaluator)

Evaluator with visitation-only stats: TP numerator 0; control FP from manufactured confirms: 0 in anti-inflation tests.

DOM-clobber safe fixtures: **0** E-tier confirms in live Lab runs (FP rate 0 for confirmation tier).

---

## PART D — Anti-inflation tests

Added `tests/test_anti_inflation_audit.py` covering:

- contract-only ≠ supported_active  
- registered stub ≠ supported_active  
- routed / sent probe ≠ verified  
- expected state cannot rewrite scanner evidence  
- visitation ≠ recall  
- evaluator cannot manufacture baseline/control/replay success  
- live recall excludes non-`live_validated`  
- unsupported/passive outside active denominator  
- negative-control / replay failure block confirmation  
- SSRF without callback ≠ success  
- fixture markers ≠ production proof  

Focused suite: **30 passed** (anti-inflation + framework). Dom-clobber tests included in broader run: **116 passed**, 1 unrelated pre-existing failure (`vantacrawl_api` missing).

---

## PART E — Merge decision

| PR | Verdict |
|---|---|
| **#97** | **merge** (manual; after optional deploy of Horizon fixtures) |
| **#98** | **changes required** (maturity recalculation + anti-inflation — see audit branch) |
| **#96** | **closed superseded** (done) |

### Stacked-branch / rebase plan

1. Merge PR #97 → `main` (human).  
2. Deploy Horizon Catalog from that commit (proof.js + variants).  
3. Rebase PR #98 onto updated `main`; ensure no duplicate #97 commit (currently #98 = #97 + `7dd2a19`).  
4. Merge or cherry-pick `cursor/stacked-pr-integrity-audit-32cd` into #98 (maturity + tests + claim).  
5. Re-run full suite + live Safe/Extended/Lab against deployed Horizon.  
6. Only then consider #98 merge.  
7. **Do not begin Phase 2.**

### Exact remaining blockers

1. Human merge of #97 (not performed by this audit).  
2. Deploy updated Horizon fixtures to Render (`app-settings` / `widget-cfg` / `media-embed` / `/oob/.../proof.js` missing on live).  
3. Land maturity-aware inventory on #98 (this branch) — drop inflated 48.  
4. Complete live Safe/Extended/Lab benchmark matrices post-deploy; expand `live_validated` only with full lifecycle evidence.  
5. DOM-clobber `widget-cfg` form path + `media-embed` sink confirmation gaps.  
6. CSRF incomplete replay lifecycle.  
7. SSRF live OOB attribution not demonstrated in this audit window.  
8. XSS browser sample did not reach `browser_execution_confirmed` in the Phase-1 sample pass.  
9. Render MCP unauthorized here — deploy must be done with authenticated workspace.

---

## Evidence index

- `/opt/cursor/artifacts/stacked_audit/pr97_dom_clobber_audit_table.md`
- `/opt/cursor/artifacts/stacked_audit/rand_live_verify.json`
- `/opt/cursor/artifacts/stacked_audit/rand_discovery.json`
- `/opt/cursor/artifacts/stacked_audit/horizon_dom_clobber_live.json`
- `/opt/cursor/artifacts/stacked_audit/phase1_lifecycle_rows.json`
- `/opt/cursor/artifacts/stacked_audit/fixture_inventory_revised.json`
- `/opt/cursor/artifacts/stacked_audit/live_validated_caps.json`
- `/opt/cursor/artifacts/stacked_audit/pytest_anti_inflation.txt`
