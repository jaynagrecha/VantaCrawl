# Dynamic DOM-clobber source-to-sink verification

**Claim (exact):** Dynamic DOM-clobber source-to-sink verification for supported
browser and injection contexts.

This is **not** a claim of universal DOM-clobber discovery. Production scanner
code must not hardcode Horizon Catalog routes, parameter names, property names
(e.g. `defaultConfig`), fixture proof assets, expected DOM IDs, or
benchmark-only markers.

## Lifecycle

```
1. Controllable HTML discovery
   inject unique inert marker into crawled params/fields
   classify: encoded | text reflection | live DOM insertion | stored render
   record injection context (body / attribute / script / URL / DOM API)

2. Clobber candidate discovery (dynamic)
   static: parse page scripts for globals / .href|.src|.url|.action reads
   browser: inventory window/document named properties, element id/name
   prioritize candidates later used as dangerous sinks

3. Context-aware structure generation
   single-global <a id=prop href=PROOF>
   nested <form id=prop><input name=url value=PROOF>
   URL-bearing href/src/action/data/value
   fresh nonce + probe_id + candidate_id + isolated browser session per attempt

4. Source-to-sink verification
   controllable HTML → named property collision → app read → sink → proof
   browser instrumentation records who performed the sink (app vs scanner)

5. Negative controls + replay
   baseline, non-colliding random ID, random unused property,
   clobber without proof URL, clean-context replay

6. Confirmation states (strict ladder)
   see contract below — only browser_execution_confirmed or
   controlled_request_confirmed may be high-severity confirmed vulns
```

## Confirmation-state contract

| State | Meaning | Severity ceiling |
|-------|---------|------------------|
| `html_injection_confirmed` | Attacker-controlled HTML element created in DOM | info / low |
| `named_property_clobbered` | Chosen global/document/form property resolves to attacker DOM | low |
| `clobbered_value_consumed` | Application JavaScript read the attacker-controlled property | medium |
| `sink_context_candidate` | Value reached a dangerous sink API; no execution/request proof | medium (unverified) |
| `clobber_without_sink` | Collision occurred; application did not use it dangerously | info |
| `controlled_request_confirmed` | Application initiated request to scanner-owned proof URL | **high (confirmed)** |
| `browser_execution_confirmed` | Controlled proof script ran via application-originated sink | **high (confirmed)** |
| `blocked_by_csp` | Path existed; CSP blocked execution | medium (unverified) |
| `reflected_only` | Input reflected; not live-inserted / not consumed | info |
| `inconclusive` | Browser/proof instrumentation unavailable | — |
| `negative` | Negative control / non-reproducible | — |

Ladder A→E for reports:

- **A** HTML injection only → `html_injection_confirmed`
- **B** DOM property clobbering → `named_property_clobbered`
- **C** Clobbered value consumed → `clobbered_value_consumed`
- **D** Dangerous sink reached → `sink_context_candidate`
- **E** Browser execution / controlled request → `browser_execution_confirmed` / `controlled_request_confirmed`

Safe mode: inert injection + collision + sink observation only; **never**
loads executable proof JavaScript. Max state: `clobber_without_sink` or
`sink_context_candidate`.

Extended: controlled same-origin / scanner-owned **network** proof
(`controlled_request_confirmed`).

Lab: executable proof + nested structures + strict negative controls + replay.

## Anti self-confirmation

Proof correlation requires: `scan_id`, endpoint id, parameter/field id,
candidate property, `probe_id`, browser session id, nonce, expected proof path,
and request initiator when available.

Ignored: scanner HTTP-client fetches, crawler fetches, preflight/health checks,
earlier probe callbacks, manually loaded proof URLs, scanner-initiated redirects.
The scanner injecting a `<script>` itself never counts as confirmation.

## Horizon Catalog (benchmark only)

Horizon exposes vulnerable + negative-control routes with varied property shapes
and sinks. VantaCrawl must discover injection points and clobber properties
**dynamically**. Fixture-side aliases added only to match scanner param
allowlists are forbidden.

## Browser-dependent limitations

See § “Limitations” at end of this document and
`dom_clobber/limitations.py`.

## Modules

| Module | Responsibility |
|--------|----------------|
| `dom_clobber/contract.py` | States, severity, report schema |
| `dom_clobber/discovery.py` | HTML marker injection classification; static candidate extract |
| `dom_clobber/payloads.py` | Dynamic clobber HTML generation |
| `dom_clobber/proof.py` | Scanner-owned proof URL minting + correlation helpers |
| `dom_clobber/browser.py` | CDP/Selenium instrumentation for verify |
| `dom_clobber/verify.py` | Orchestration, negative controls, finding emission |
| `active_probe_kit.py` | Mode-gated pass after generic probes |
| `vuln_playground/...` | Benchmark fixtures only |

## Limitations (non-exhaustive)

- Named-property clobber behavior differs across browsers (Chrome vs Firefox vs Safari).
- Some nested form/collection clobbers are Chrome-specific or version-gated.
- CSP `script-src` / `default-src` can block proof script execution even when
  `script.src` is assigned (`blocked_by_csp`).
- Shadow DOM / closed trees may hide injection.
- Stored XSS / multi-step render chains need a later crawl of the render URL.
- Static script analysis misses heavily obfuscated or WASM-only consumers.
- Without a configured callback/proof base, Lab/Extended cannot mint
  scanner-owned proof URLs → `inconclusive` for E-tier.
- Fragment/hash injection and some DOM API sinks require browser evaluate;
  Safe mode will not execute proofs there.
