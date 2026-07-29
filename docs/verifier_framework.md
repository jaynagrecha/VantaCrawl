# Generic vulnerability verification framework (Phase 1)

**Product claim (exact):**

> VantaCrawl dynamically discovers and verifies supported vulnerability classes
> using family-specific evidence contracts. Horizon Catalog measures
> supported-active recall separately from passive/manual and unsupported coverage.

This is **not** a claim that every web vulnerability is automatically detectable,
that all catalog fixtures are actively verified, or that entire-catalog coverage
is 100%.

## Layers

1. Surface discovery  
2. Input modelling  
3. Candidate generation  
4. Probe scheduling  
5. Request/browser execution  
6. Evidence collection  
7. Negative controls  
8. Reproduction  
9. Result-state classification  
10. Finding emission  
11. Benchmark evaluation (Horizon-only; never rewrites scanner states)

## Verifier contract

Every family implements `VulnerabilityVerifier` (`verifiers/base.py`):

- `discover_candidates(context)`
- `build_baseline` / `build_controls` / `build_probes`
- `execute` / `collect_evidence` / `classify`
- `reproduce` / `severity` / `remediation`

Visiting a route, scheduling a probe, or sending one request is **never**
active verification. Active verification requires controllable input, a
context-appropriate probe, security-relevant behavioral difference, replay,
negative controls, and attributable proof.

## Horizon Catalog

Horizon is the formal ground-truth **benchmark** only.

Production scanner / verifier code must not hardcode Horizon:

- domains, routes, endpoint names
- parameter / field names
- expected response strings, fixture markers, proof values
- framework names, vulnerability labels tied to fixtures

Benchmark inventory, expected states, and support classification live under
`horizon_benchmark/` and may read the local catalog for measurement.

## Honest statuses (fixture-level)

| Status | Meaning |
|--------|---------|
| `actively_verified` | Evidence contract satisfied + replay + negative controls |
| `passively_confirmed` | Passive/manual signal only |
| `manual_validation_required` | Partial signal; human required |
| `confirmation_unavailable` | Prerequisite missing (browser/OOB/canary) |
| `unsupported` | No verifier capability |
| `negative_control_passed` | Control correctly stayed unconfirmed |
| `missed_fixture` | Supported-active expected but not discovered/scheduled |
| `inconclusive` | Instrumentation or classification incomplete |

## Phase 1 families

SQLi, command injection/RCE, SSTI, XSS, SSRF, open redirect, traversal/LFI,
CRLF, CSRF, DOM clobbering.

Phase 2/3 backlog: see `docs/verifier_backlog.md`.

## Metrics (never collapse to one “100%”)

Report separately: catalog discovery, routing, probe execution, verification,
emission, result-state completeness, supported-active TP recall, negative-control
FP rate, passive/manual inventory, unsupported count, confirmation-unavailable,
cleanup success.
