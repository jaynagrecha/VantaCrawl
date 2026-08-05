# Phase-2 Task 1 — Generic CORS Verification

## Current CORS behaviour

Passive detection lives in `security_scan.check_cors` and is invoked once per host from
`crawl_orchestrator` when `cors_check` is enabled. The probe issues a Python HTTP `GET`
with `Origin: https://evil.example` and emits a finding only when:

- `Access-Control-Allow-Origin: *` **and** `Access-Control-Allow-Credentials: true`, or
- ACAO equals the probed Origin **and** ACAC is true.

Severity is refined by `finding_impact.assess_cors` using cookie/path heuristics.
Reflection without credentials is intentionally silent. There is **no** browser proof that
cross-origin JavaScript can read the response body.

`tier_security.py` has no CORS logic. Product API `CORSMiddleware` (`cors_origins`) is
unrelated to target scanning.

## Existing passive checks

| Component | Role |
|-----------|------|
| `security_scan.check_cors` | Header probe + FindingProof |
| `crawl_orchestrator` | Once-per-host scheduling, emit `cors` |
| `finding_impact.assess_cors` | Severity ladder |
| `finding_proof.proof_has_cors_headers` | Confirmation gate for reports |
| `recon_extract` | Inventory ACAO/ACAC/ACAM/ACAH |

Passive header observation is retained. It must never be silently mapped to
`terminal_confirmed` / active browser confirmation.

## Required browser proof architecture

A real CORS proof needs two origins:

| Role | Host |
|------|------|
| Origin A (target) | Application under test (e.g. Horizon Catalog in Lab) |
| Origin B (proof) | Project-owned VantaCrawl API proof page |

Architecture decision: **use the VantaCrawl API as the controlled proof origin**.

1. Scanner mints a short-lived HMAC-signed token bound to
   `scan_id`, `candidate_id`, `probe_id`, `nonce`, `target_url`, `target_origin`,
   credential mode, and expected canary.
2. Shared Selenium driver (under `selenium_driver_lock`) navigates to
   `{cors_proof_origin_base}/api/cors-proof/run?t=<token>`.
3. Server validates the token, rejects private/link-local/metadata destinations and
   origin mismatches, and serves a fixed HTML template that embeds **only** the
   allowlisted target URL from the token (never an arbitrary client-supplied URL).
4. Page JavaScript performs `fetch(target, {mode:'cors', credentials})` and writes a
   structured result (`readable`, status, canary_found, body_len, body_hash) into the DOM.
5. Selenium reads the result. Confirmation requires readability **and** canary match
   (or explicitly classified sensitive content), replay success, and a negative-control
   origin/probe that does not obtain the same read.
6. The proof endpoint is not a public proxy: no unauthenticated arbitrary fetch, no
   persistence of target response bodies, short TTL, authorization-bound tokens.

Python `Origin` header requests alone are **not** treated as browser proof.

## Credential prerequisites

- Credentialed mode (`credentials: include`) only when a controlled fixture/session is
  available and authorization is clear.
- Missing session → `controlled_session_unavailable` / confirmation unavailable — not confirmed.
- Artifacts redact Cookie / Set-Cookie / Authorization / bearer / session identifiers.
- Record only whether credentials were attached.

## Verifier contract

Package: `verifiers/cors/` implementing `VulnerabilityVerifier` via a thin adapter
(`CorsVerifier`) and dedicated modules for discovery, proof minting, browser execution,
classification, and orchestration.

Methods: discover → baseline/controls → probes → execute → collect_evidence → classify →
reproduce → severity → remediation.

Canonical confirmed state: `cors_browser_read_confirmed`.

## Evidence model

Every browser proof binds: `scan_id`, `candidate_id`, `probe_id`, `nonce`,
`browser_context_id`, target URL/origin, proof origin, method, credential mode,
status, content-type, preflight result, readable flag, canary expected/observed,
correlation decision, replay, negative-control result.

Cross-candidate / cross-scan / wrong-origin / stale-nonce evidence is rejected.

## Negative controls

1. Wildcard + credentials headers alone → not confirmed (browser blocks).
2. Public unauthenticated cross-origin read → not automatically high severity.
3. Reflected Origin without browser-readable sensitive/canary content → not confirmed.
4. Trusted-only allowlist endpoint → negative for our proof origin.
5. Disallowed / mismatched origin → unreadable.
6. Missing credentials / session → confirmation unavailable.
7. Preflight denial → negative/inconclusive.
8. Navigation/timeout/WAF → not a vulnerability.
9. Stale marker / foreign candidate evidence → rejected.

## Safety limits

- Proof origin accepts only signed, job-bound tokens.
- Exact authorized target origin only.
- SSRF-safe URL validation (no private/link-local/metadata).
- Shared Selenium RLock for the full browser transaction.
- No Horizon domains/routes/markers in production packages.

## Reporting / lifecycle binding

- Findings are deduped per **host+path+state**, not per host, so a public
  `uncredentialed_public_read` cannot collapse a later `cors_browser_read_confirmed`.
- Finalize prefers ledger rows with `probe_role` `cors_classified` /
  `cors_browser_read_confirmed` over raw `cors_browser_proof` decisions such as
  `confirmed_current_probe` (so ACAO:*+ACAC:true stays `wildcard_with_credentials_invalid`).
- Emitted proofs include a redacted HTTP request/response carrying ACAO/ACAC so
  report impact gates can accept browser-confirmed CORS without storing secrets.

## Limitations

- Requires `cors_proof_origin_base` (or `public_base_url`) configured to a distinct origin
  from the target.
- Same-origin API SPA cannot serve as proof against the API itself.
- Null-origin sandbox proofs are out of scope for this first slice (recorded as
  confirmation unavailable when only `Origin: null` is relevant).
- Impact/sensitivity classification is conservative without explicit canary or
  classified sensitive content.
- Trusted-allowlist fixtures that never reflect the proof Origin may remain
  `discovery_missing` (still non-confirmed).

## Stop conditions

- If no safe two-origin host exists → `BLOCKED — CONTROLLED SECOND ORIGIN REQUIRED`.
- Do not fake browser proof with Python-only Origin probes.
- Do not merge this PR as part of Task 1 delivery; independent audit first.

## Files expected to change

- `docs/phase2_cors_verification.md` (this file)
- `verifiers/cors/*` (new package)
- `verifiers/__init__.py`, `verifiers/maturity.py`, `verifiers/contract.py`
- `verifiers/runtime/surfaces.py`, `execution_plan.py` (cors family wiring)
- `web/api/vantacrawl_api/routes/cors_proof.py` (new)
- `web/api/vantacrawl_api/main.py`, `config.py`
- `crawl_config.py`, `crawl_orchestrator.py` / active verify hook
- `security_scan.py` (passive observation enrichment feeding candidates)
- Benchmark-only: `vuln_playground/vulns/cookies_csrf_cors.py`, related fixtures,
  `horizon_benchmark/manifest.json` entries as needed
- `tests/test_cors_*.py` and Phase-1 regression coverage updates
