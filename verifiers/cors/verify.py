"""CORS verification orchestration — discovery, browser proof, controls, findings."""

from __future__ import annotations

import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from verifiers.cors.browser import run_cors_browser_proof
from verifiers.cors.classify import classify_cors, lifecycle_outcome_for
from verifiers.cors.contract import (
    STATE_CORS_BROWSER_READ_CONFIRMED,
    STATE_PROOF_ORIGIN_UNAVAILABLE,
    build_cors_report,
    is_confirmed,
    remediation_text,
)
from verifiers.cors.discovery import (
    CorsObservation,
    candidates_from_observation,
    observation_from_response,
)
from verifiers.cors.proof import mint_proof_token, proof_origin_configured, proof_page_url
from verifiers.cors.url_safety import origin_of
from verifiers.evidence import new_nonce, new_probe_id

Finding = Tuple[str, str, str, Optional[str], Dict[str, Any]]


def _with_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    for k, v in params.items():
        pairs = [(a, b) for a, b in pairs if a != k]
        pairs.append((k, v))
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs), parsed.fragment)
    )


def _redact_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk in ("cookie", "set-cookie", "authorization"):
            out[str(k)] = "[redacted]"
        else:
            out[str(k)] = str(v)[:200]
    return out


def _extract_canary(body: str, hint: str = "") -> str:
    if hint and hint in (body or ""):
        return hint
    # Generic marker patterns used by controlled fixtures (not Horizon-specific hosts)
    for token in ("VCCORS_", "CORS_CANARY_", "cors-canary="):
        idx = (body or "").find(token)
        if idx >= 0:
            frag = (body or "")[idx : idx + 64]
            for sep in ("<", " ", '"', "'", "&", "\n"):
                if sep in frag:
                    frag = frag.split(sep, 1)[0]
            return frag
    return hint or ""


async def _http_probe(
    client: Any,
    url: str,
    *,
    origin: str,
) -> Tuple[int, Dict[str, str], str]:
    resp = await client.get(url, headers={"Origin": origin}, timeout=15)
    status = int(getattr(resp, "status_code", 0) or 0)
    headers = {str(k): str(v) for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    return status, headers, body


def _record(
    stats: Any,
    *,
    scan_id: str,
    candidate_id: str,
    probe_id: str,
    nonce: str,
    url: str,
    result_state: str,
    probe_role: str,
    meta: Dict[str, Any],
) -> None:
    if stats is None or not hasattr(stats, "record_request"):
        return
    try:
        stats.record_request(
            phase="active_probe",
            source="cors",
            url=url,
            status=int(meta.get("status") or 0),
            final_url=url,
            response_type=str(meta.get("content_type") or ""),
            bytes=int(meta.get("body_len") or 0),
            outcome=result_state,
            scan_id=scan_id,
            candidate_id=candidate_id,
            probe_id=probe_id,
            nonce=nonce,
            probe_role=probe_role,
            result_state=result_state,
            probe_class="cors",
            probe_name=str(meta.get("probe_name") or "cors_browser_proof"),
            parameter="origin",
            classification=str(meta.get("classification") or ""),
            payload_redacted="[cors-proof]",
            browser_context_id=str(meta.get("browser_context_id") or ""),
        )
    except TypeError:
        # Older signature — best effort
        try:
            stats.record_request(
                phase="active_probe",
                source="cors",
                url=url,
                status=int(meta.get("status") or 0),
                final_url=url,
                outcome=result_state,
            )
        except Exception:
            pass
    except Exception:
        pass


async def verify_cors_url(
    client: Any,
    url: str,
    *,
    mode: str = "lab",
    scan_id: str = "",
    stats: Any = None,
    proof_origin_base: str = "",
    proof_secret: str = "",
    browser_available: bool = True,
    session_available: bool = False,
    credential_mode: str = "omit",
    output_callback: Optional[Callable[[str], None]] = None,
) -> List[Finding]:
    """Run passive observation + optional browser CORS proof for one URL."""
    findings: List[Finding] = []
    log = output_callback or (lambda _m: None)
    target_origin = origin_of(url)
    if not target_origin:
        return findings

    proof_base = (proof_origin_base or "").rstrip("/")
    proof_ok = proof_origin_configured(proof_base) and bool(proof_secret)
    # Proof origin must differ from target origin
    if proof_ok and origin_of(proof_base + "/") == target_origin:
        proof_ok = False

    # Passive observation with a synthetic probe origin equal to proof origin when available
    probe_origin = origin_of(proof_base + "/") if proof_ok else "https://cors-proof.invalid"
    status, headers, body = await _http_probe(client, url, origin=probe_origin)
    canary_hint = ""
    # Prefer injecting a scanner-owned canary when the URL accepts query params
    nonce = f"VCCORS_{new_nonce(8)}"
    canary = f"VCCORS_{secrets.token_hex(8)}"
    canary_url = _with_query(url, canary=canary)
    st2, hdr2, body2 = await _http_probe(client, canary_url, origin=probe_origin)
    if canary in (body2 or ""):
        url = canary_url
        status, headers, body = st2, hdr2, body2
        canary_hint = canary
    else:
        canary_hint = _extract_canary(body)
        canary = canary_hint

    obs = observation_from_response(
        url,
        headers,
        request_origin=probe_origin,
        status=status,
        content_type=headers.get("content-type") or headers.get("Content-Type") or "",
        canary_hint=canary_hint,
    )
    if not obs:
        return findings

    cands = candidates_from_observation(obs, scan_id=scan_id)
    if not cands:
        return findings
    cand = cands[0]
    candidate_id = cand.candidate_id

    # Metrics counters on stats
    metrics = getattr(stats, "cors_metrics", None)
    if stats is not None and not isinstance(metrics, dict):
        stats.cors_metrics = {
            "candidates_discovered": 0,
            "candidates_scheduled": 0,
            "candidates_attempted": 0,
            "passive_header_observations": 0,
            "browser_read_attempts": 0,
            "browser_read_confirmed": 0,
            "credentialed_read_confirmed": 0,
            "confirmation_unavailable": 0,
            "negative_controls_executed": 0,
            "negative_control_false_positives": 0,
            "replay_pass": 0,
            "replay_fail": 0,
            "nonterminal_inconclusive": 0,
        }
        metrics = stats.cors_metrics
    if isinstance(metrics, dict):
        metrics["candidates_discovered"] = int(metrics.get("candidates_discovered") or 0) + 1
        metrics["passive_header_observations"] = int(metrics.get("passive_header_observations") or 0) + 1

    browser_result = None
    replay_result = None
    negative_result = None
    probe_id = new_probe_id("cors")
    sensitive = bool(canary)
    public_only = (not sensitive) and (not obs.acac)

    if mode in ("extended", "lab") and proof_ok and browser_available:
        if isinstance(metrics, dict):
            metrics["candidates_scheduled"] = int(metrics.get("candidates_scheduled") or 0) + 1
            metrics["candidates_attempted"] = int(metrics.get("candidates_attempted") or 0) + 1
            metrics["browser_read_attempts"] = int(metrics.get("browser_read_attempts") or 0) + 1
        try:
            token = mint_proof_token(
                secret=proof_secret,
                scan_id=scan_id,
                candidate_id=candidate_id,
                probe_id=probe_id,
                nonce=nonce,
                target_url=url,
                target_origin=target_origin,
                credential_mode=credential_mode if session_available else "omit",
                canary=canary,
            )
            page = proof_page_url(proof_base, token)
            cm = credential_mode if session_available else "omit"
            browser_result = run_cors_browser_proof(
                proof_page_url=page,
                expected_scan_id=scan_id,
                expected_candidate_id=candidate_id,
                expected_probe_id=probe_id,
                expected_nonce=nonce,
                expected_target_url=url,
                expected_canary=canary,
            )
            _record(
                stats,
                scan_id=scan_id,
                candidate_id=candidate_id,
                probe_id=probe_id,
                nonce=nonce,
                url=url,
                result_state=str(browser_result.get("decision") or ""),
                probe_role="cors_browser_proof",
                meta={**browser_result, "probe_name": "cors_browser_proof", "classification": ",".join(obs.selection_reasons)},
            )

            # Replay
            replay_pid = new_probe_id("cors_replay")
            replay_nonce = f"VCCORS_{new_nonce(8)}"
            # Keep same canary URL for replay binding
            rtoken = mint_proof_token(
                secret=proof_secret,
                scan_id=scan_id,
                candidate_id=candidate_id,
                probe_id=replay_pid,
                nonce=replay_nonce,
                target_url=url,
                target_origin=target_origin,
                credential_mode=cm,
                canary=canary,
            )
            replay_result = run_cors_browser_proof(
                proof_page_url=proof_page_url(proof_base, rtoken),
                expected_scan_id=scan_id,
                expected_candidate_id=candidate_id,
                expected_probe_id=replay_pid,
                expected_nonce=replay_nonce,
                expected_target_url=url,
                expected_canary=canary,
            )
            _record(
                stats,
                scan_id=scan_id,
                candidate_id=candidate_id,
                probe_id=replay_pid,
                nonce=replay_nonce,
                url=url,
                result_state=str(replay_result.get("decision") or ""),
                probe_role="cors_replay",
                meta={**replay_result, "probe_name": "cors_replay"},
            )
            if isinstance(metrics, dict):
                if replay_result.get("readable") and (
                    not canary or replay_result.get("canary_found")
                ):
                    metrics["replay_pass"] = int(metrics.get("replay_pass") or 0) + 1
                else:
                    metrics["replay_fail"] = int(metrics.get("replay_fail") or 0) + 1

            # Negative control: trusted-deny style — fetch a URL path that should not
            # reflect our proof origin. Use target origin with a guaranteed-missing path
            # OR when ACAO is open, use a different canary that must not appear.
            neg_pid = new_probe_id("cors_neg")
            neg_nonce = f"VCCORS_{new_nonce(8)}"
            neg_canary = f"VCCORS_NEG_{secrets.token_hex(6)}"
            neg_url = _with_query(url, canary=neg_canary, cors_neg="1")
            # For open reflection endpoints, body will contain neg_canary — that would
            # make negative fail. Use a disjoint path under same origin that is unlikely
            # to allow CORS: /__vc_cors_denied__
            denied = f"{target_origin}/__vc_cors_denied_{secrets.token_hex(4)}"
            try:
                ntoken = mint_proof_token(
                    secret=proof_secret,
                    scan_id=scan_id,
                    candidate_id=candidate_id,
                    probe_id=neg_pid,
                    nonce=neg_nonce,
                    target_url=denied,
                    target_origin=target_origin,
                    credential_mode="omit",
                    canary=neg_canary,
                )
                negative_result = run_cors_browser_proof(
                    proof_page_url=proof_page_url(proof_base, ntoken),
                    expected_scan_id=scan_id,
                    expected_candidate_id=candidate_id,
                    expected_probe_id=neg_pid,
                    expected_nonce=neg_nonce,
                    expected_target_url=denied,
                    expected_canary=neg_canary,
                )
            except Exception:
                negative_result = {
                    "readable": False,
                    "canary_found": False,
                    "correlation_ok": True,
                    "decision": "browser_read_blocked",
                }
            if isinstance(metrics, dict):
                metrics["negative_controls_executed"] = (
                    int(metrics.get("negative_controls_executed") or 0) + 1
                )
                if negative_result.get("readable") and negative_result.get("canary_found"):
                    metrics["negative_control_false_positives"] = (
                        int(metrics.get("negative_control_false_positives") or 0) + 1
                    )
            _record(
                stats,
                scan_id=scan_id,
                candidate_id=candidate_id,
                probe_id=neg_pid,
                nonce=neg_nonce,
                url=denied,
                result_state=str(negative_result.get("decision") or ""),
                probe_role="cors_negative_control",
                meta={**negative_result, "probe_name": "cors_negative_control"},
            )
        except ValueError as exc:
            log(f"CORS proof mint failed: {exc}")
            browser_result = None
    elif mode in ("extended", "lab") and not proof_ok:
        if isinstance(metrics, dict):
            metrics["confirmation_unavailable"] = int(metrics.get("confirmation_unavailable") or 0) + 1

    classified = classify_cors(
        mode=mode,
        selection_reasons=obs.selection_reasons,
        acao=obs.acao,
        acac=obs.acac,
        proof_origin_available=proof_ok,
        browser_available=browser_available,
        credential_mode=credential_mode if session_available else "omit",
        session_available=session_available,
        browser_result=browser_result,
        replay_result=replay_result,
        negative_result=negative_result,
        sensitive=sensitive,
        public_only=public_only,
    )
    state = str(classified.get("result_state") or "")
    if isinstance(metrics, dict):
        if is_confirmed(state):
            metrics["browser_read_confirmed"] = int(metrics.get("browser_read_confirmed") or 0) + 1
            if (credential_mode if session_available else "omit") == "include":
                metrics["credentialed_read_confirmed"] = (
                    int(metrics.get("credentialed_read_confirmed") or 0) + 1
                )
        if lifecycle_outcome_for(state) == "terminal_inconclusive":
            metrics["nonterminal_inconclusive"] = int(metrics.get("nonterminal_inconclusive") or 0) + 1

    report = build_cors_report(
        state=state,
        target_origin=target_origin,
        proof_origin=origin_of(proof_base + "/") if proof_base else "",
        credential_mode=credential_mode if session_available else "omit",
        readable=bool((browser_result or {}).get("readable")),
        replay_ok=bool((replay_result or {}).get("readable")) if replay_result else None,
        negative_control_ok=(
            not (
                (negative_result or {}).get("readable")
                and (negative_result or {}).get("canary_found")
            )
            if negative_result
            else None
        ),
        confidence=str(classified.get("confidence") or "medium"),
        prerequisites={
            "proof_origin": proof_ok,
            "browser": browser_available,
            "session": session_available,
        },
        limitations=(
            "Confirmation requires a distinct controlled proof origin and browser-readable "
            "canary evidence. Header-only observations are not active confirmations."
        ),
    )

    # Emit finding for confirmed or noteworthy passive credentialed reflection
    emit = is_confirmed(state) or (
        state == STATE_PROOF_ORIGIN_UNAVAILABLE and obs.acac and obs.acao
    ) or (
        "wildcard_with_credentials_header" in obs.selection_reasons
        and mode == "safe"
    ) or (
        "reflected_origin" in obs.selection_reasons and obs.acac and mode == "safe"
    )
    # In lab/extended, prefer active classification; still emit confirmed + informative passive
    if mode in ("extended", "lab"):
        emit = is_confirmed(state) or state in (
            "uncredentialed_public_read",
            "wildcard_with_credentials_invalid",
            "reflected_origin_without_sensitive_read",
            "passive_header_observed",
        )

    if emit:
        sev = str(classified.get("severity") or "info")
        detail = f"CORS {state} on {urlparse(url).path or '/'}"
        evidence = (
            f"acao={obs.acao}; acac={obs.acac}; state={state}; "
            f"readable={bool((browser_result or {}).get('readable'))}; "
            f"canary={bool((browser_result or {}).get('canary_found'))}"
        )
        meta = {
            "verification": classified.get("verification"),
            "confidence": classified.get("confidence"),
            "result_state": state,
            "lifecycle_outcome": lifecycle_outcome_for(state),
            "proof": {
                "cors": report,
                "headers_redacted": _redact_headers(headers),
                "selection_reasons": list(obs.selection_reasons),
                "browser": {
                    k: (browser_result or {}).get(k)
                    for k in (
                        "decision",
                        "readable",
                        "canary_found",
                        "status",
                        "browser_context_id",
                        "correlation_ok",
                        "body_hash",
                        "body_len",
                    )
                },
            },
            "remediation": remediation_text(),
            "scan_id": scan_id,
            "candidate_id": candidate_id,
            "probe_id": probe_id,
            "nonce": nonce,
            "family": "cors",
        }
        # Avoid leaking canary values / secrets in meta
        findings.append(("cors", sev, detail, evidence, meta))

    return findings


async def verify_cors_candidates(
    client: Any,
    urls: List[str],
    **kwargs: Any,
) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for u in urls:
        key = origin_of(u) + (urlparse(u).path or "/")
        if key in seen:
            continue
        seen.add(key)
        out.extend(await verify_cors_url(client, u, **kwargs))
    return out
