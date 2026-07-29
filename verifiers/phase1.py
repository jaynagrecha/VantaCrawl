"""Phase-1 family verifiers (generic contracts; no Horizon route hardcodes).

These verifiers define discovery/evidence contracts and can classify evidence
produced by the shared active-probe runtime. They must not import catalog paths
or fixture markers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from verifiers.base import (
    Candidate,
    Evidence,
    Probe,
    SurfaceContext,
    VerificationResult,
    VulnerabilityVerifier,
)
from verifiers.contract import (
    STATE_BROWSER_EXEC,
    STATE_CANARY,
    STATE_CONFIRMATION_UNAVAILABLE,
    STATE_DIFFERENTIAL,
    STATE_HTML_INJECTION,
    STATE_INCONCLUSIVE,
    STATE_NEGATIVE,
    STATE_OOB_CALLBACK,
    STATE_PROBABLE,
    STATE_REFLECTION_ONLY,
    STATE_SERVER_EXEC,
    STATE_SINK_CANDIDATE,
    evidence_skeleton,
    is_actively_confirmed,
)
from verifiers.evidence import (
    arithmetic_proof_present,
    body_hash,
    looks_reflected,
    new_nonce,
    new_probe_id,
    response_snap,
    with_query_param,
)
from verifiers.registry import register

# Generic param-name heuristics (not Horizon-specific allowlists of fixture params)
_SQL_PARAM = re.compile(
    r"(?i)^(id|uid|user_id|cat|category|item|pid|order|sort|query|q|search|filter|name)$"
)
_XSS_PARAM = re.compile(
    r"(?i)^(q|query|search|s|keyword|term|name|title|message|comment|text|content|input|html|body)$"
)
_RCE_PARAM = re.compile(r"(?i)^(cmd|command|exec|shell|host|ping|expr|input)$")
_SSTI_PARAM = re.compile(r"(?i)^(name|template|tmpl|render|view|preview|expr)$")
_SSRF_PARAM = re.compile(
    r"(?i)^(url|uri|link|src|source|dest|destination|redirect_uri|callback|feed|target|fetch|proxy|image)$"
)
_REDIR_PARAM = re.compile(
    r"(?i)^(next|url|redirect|return|returnurl|continue|dest|destination|goto|target)$"
)
_TRAV_PARAM = re.compile(
    r"(?i)^(path|file|filename|filepath|include|page|doc|download|template)$"
)
_CRLF_PARAM = re.compile(r"(?i)^(q|query|search|header|name|x)$")


def _params_from_context(ctx: SurfaceContext) -> List[str]:
    names = list(ctx.query_params.keys()) + list(ctx.form_fields)
    # de-dupe preserve order
    seen = set()
    out = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _candidate(
    family: str,
    ctx: SurfaceContext,
    param: str,
    channel: str = "query",
) -> Candidate:
    return Candidate(
        family=family,
        parameter=param,
        channel=channel,
        url=ctx.url,
        method=ctx.method,
        baseline_value=str(ctx.query_params.get(param) or "1"),
        candidate_id=new_probe_id("cand"),
    )


class _HttpFamilyVerifier(VulnerabilityVerifier):
    param_re = re.compile(r".*")
    family = "unknown"
    capability_id = "unknown"
    supported_modes: Sequence[str] = ("safe", "extended", "lab")
    phase = 1

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {"http_client": True}

    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        out = []
        for name in _params_from_context(context):
            if self.param_re.match(name):
                ch = "form" if name in context.form_fields and name not in context.query_params else "query"
                out.append(_candidate(self.family, context, name, ch))
        return out

    async def execute(self, candidate: Candidate, probe: Probe, runtime: Any) -> Any:
        client = getattr(runtime, "client", runtime)
        url = with_query_param(candidate.url, candidate.parameter, probe.payload)
        method = (candidate.method or "GET").upper()
        if method == "POST":
            return await client.post(candidate.url, data={candidate.parameter: probe.payload})
        return await client.get(url)

    def collect_evidence(
        self,
        candidate: Candidate,
        probe: Probe,
        response: Any,
        runtime: Any,
        *,
        baseline: Any = None,
        controls: Optional[List[Any]] = None,
    ) -> Evidence:
        snap = response_snap(response)
        base = baseline if isinstance(baseline, dict) else {}
        return Evidence(
            result_state=STATE_INCONCLUSIVE,
            detail=f"{self.family} probe={probe.name}",
            evidence_line=f"status={snap['status']} hash={snap['body_hash']}",
            structured={
                "probe": probe.name,
                "response": {k: snap[k] for k in ("status", "body_hash", "final_url")},
                "baseline_hash": base.get("body_hash"),
                "reflected": looks_reflected(snap["body"], probe.nonce or probe.payload[:32]),
            },
            confidence="low",
        )

    def classify(
        self,
        candidate: Candidate,
        baseline: Any,
        controls: Sequence[Any],
        evidence: Evidence,
    ) -> Evidence:
        return evidence

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        return []


@register
class SqliVerifier(_HttpFamilyVerifier):
    family = "sqli"
    capability_id = "sqli_boolean_error_time"
    param_re = _SQL_PARAM

    def build_controls(self, candidate: Candidate) -> List[Probe]:
        n = new_nonce(4)
        return [Probe(name="inert_nonce", payload=f"VCCTRL_{n}", role="control", nonce=n, probe_id=new_probe_id())]

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        probes = [
            Probe(name="sqli_quote", payload="'", role="probe", probe_id=new_probe_id()),
            Probe(name="sqli_bool_true", payload="' AND '1'='1", role="probe", meta={"pair": "true"}, probe_id=new_probe_id()),
            Probe(name="sqli_bool_false", payload="' AND '1'='2", role="probe", meta={"pair": "false"}, probe_id=new_probe_id()),
        ]
        if mode == "lab":
            probes.append(
                Probe(name="sqli_time", payload="' AND SLEEP(2)-- ", role="probe", meta={"min_ms": 1500}, probe_id=new_probe_id())
            )
        return probes

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        # Contract: never confirm from a single SQL-looking string alone.
        # Active kit performs differential/replay; adapter maps those states.
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        if st in (STATE_SERVER_EXEC, "execution_confirmed", STATE_DIFFERENTIAL, STATE_PROBABLE):
            if evidence.structured.get("replay_ok") is False:
                evidence.result_state = STATE_INCONCLUSIVE
                evidence.detail = "SQLi differential without replay"
            elif evidence.structured.get("waf_contaminated"):
                evidence.result_state = "blocked_by_waf"
            else:
                evidence.result_state = st if st != "execution_confirmed" else STATE_SERVER_EXEC
                evidence.verification = "confirmed" if is_actively_confirmed(evidence.result_state) else "verified"
                evidence.confidence = "high" if is_actively_confirmed(evidence.result_state) else "medium"
                evidence.severity = "high"
        elif st == STATE_REFLECTION_ONLY:
            evidence.result_state = STATE_REFLECTION_ONLY
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "normalized_differential+replay+false_payload; no single error-string TP"
        )
        return evidence


@register
class RceVerifier(_HttpFamilyVerifier):
    family = "rce"
    capability_id = "rce_arith_marker"
    param_re = _RCE_PARAM

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        n = new_nonce(4)
        return [
            Probe(name="rce_arith", payload="7319+284", role="probe", meta={"arith": "7603"}, probe_id=new_probe_id(), nonce=n),
            Probe(name="rce_marker", payload=f";printf VC_RCE_{n}", role="probe", meta={"marker": f"VC_RCE_{n}"}, probe_id=new_probe_id(), nonce=n),
        ]

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        body = evidence.structured.get("body") or ""
        arith = evidence.structured.get("arith") or "7603"
        payload = evidence.structured.get("payload") or ""
        if st in (STATE_SERVER_EXEC, "execution_confirmed") or arithmetic_proof_present(body, arith, payload):
            if evidence.structured.get("replay_ok") is False:
                evidence.result_state = STATE_INCONCLUSIVE
            elif looks_reflected(body, payload) and not arithmetic_proof_present(body, arith, payload):
                evidence.result_state = STATE_REFLECTION_ONLY
            else:
                evidence.result_state = STATE_SERVER_EXEC
                evidence.severity = "high"
                evidence.verification = "confirmed"
                evidence.confidence = "high"
        elif evidence.structured.get("marker") and evidence.structured.get("marker") in body:
            evidence.result_state = "marker_output_signal"
            evidence.severity = "medium"
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "harmless arith/marker; absent in baseline; not mere reflection; replay"
        )
        return evidence


@register
class SstiVerifier(_HttpFamilyVerifier):
    family = "ssti"
    capability_id = "ssti_arith_generic"
    param_re = _SSTI_PARAM

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        return [
            Probe(name="ssti_jinja", payload="{{7319+284}}", role="probe", meta={"arith": "7603"}, probe_id=new_probe_id()),
            Probe(name="ssti_dollar", payload="${7319+284}", role="probe", meta={"arith": "7603"}, probe_id=new_probe_id()),
            Probe(name="ssti_hash", payload="#{7319+284}", role="probe", meta={"arith": "7603"}, probe_id=new_probe_id()),
        ]

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        body = evidence.structured.get("body") or ""
        payload = evidence.structured.get("payload") or ""
        if arithmetic_proof_present(body, "7603", payload) or st in (STATE_SERVER_EXEC, "execution_confirmed"):
            evidence.result_state = STATE_SERVER_EXEC
            evidence.severity = "high"
            evidence.verification = "confirmed"
            evidence.confidence = "high"
        elif looks_reflected(body, payload):
            evidence.result_state = STATE_REFLECTION_ONLY
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "safe arith across generic template syntaxes; evaluated vs reflected"
        )
        return evidence


@register
class XssVerifier(_HttpFamilyVerifier):
    family = "xss"
    capability_id = "xss_reflection_browser_ladder"
    param_re = _XSS_PARAM

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {
            "http_client": True,
            "browser": bool((context.extras or {}).get("browser_available")),
        }

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        n = new_nonce(4)
        tok = f"VCXSS_{n}"
        probes = [
            Probe(name="xss_reflect", payload=tok, role="probe", meta={"token": tok}, nonce=n, probe_id=new_probe_id()),
            Probe(
                name="xss_breakout",
                payload=f'"><b id="{tok}">{tok}</b>',
                role="probe",
                meta={"token": tok},
                nonce=n,
                probe_id=new_probe_id(),
            ),
        ]
        if mode == "lab":
            probes.append(
                Probe(
                    name="xss_event",
                    payload=f'"><svg onload="document.body.dataset.vc=\'{tok}\'">',
                    role="probe",
                    meta={"token": tok, "needs_browser": True},
                    nonce=n,
                    probe_id=new_probe_id(),
                )
            )
        return probes

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        if st == STATE_BROWSER_EXEC:
            if evidence.structured.get("app_consumed") is False:
                evidence.result_state = STATE_SINK_CANDIDATE
                evidence.verification = "unverified"
            else:
                evidence.result_state = STATE_BROWSER_EXEC
                evidence.severity = "high"
                evidence.verification = "confirmed"
                evidence.confidence = "high"
        elif st in (STATE_HTML_INJECTION, "html_injection", STATE_SINK_CANDIDATE, "attribute_breakout"):
            evidence.result_state = st if st != "html_injection" else STATE_HTML_INJECTION
            evidence.severity = "medium"
        elif st in (STATE_REFLECTION_ONLY, "reflected_only"):
            evidence.result_state = STATE_REFLECTION_ONLY
            evidence.severity = "info"
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "ladder reflection→DOM→breakout→sink→browser_exec; scanner scripts never confirm"
        )
        return evidence


@register
class SsrfVerifier(_HttpFamilyVerifier):
    family = "ssrf"
    capability_id = "ssrf_oob_attributed"
    param_re = _SSRF_PARAM

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {
            "http_client": True,
            "oob": bool((context.extras or {}).get("callback_base")),
        }

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        n = new_nonce(8)
        return [
            Probe(name="ssrf_oob", payload="", role="probe", meta={"oob": True, "nonce": n}, nonce=n, probe_id=new_probe_id()),
        ]

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        if st == STATE_OOB_CALLBACK:
            if evidence.structured.get("attributable") is False:
                evidence.result_state = STATE_CONFIRMATION_UNAVAILABLE
            else:
                evidence.result_state = STATE_OOB_CALLBACK
                evidence.severity = "high"
                evidence.verification = "confirmed"
                evidence.confidence = "high"
        elif st == STATE_REFLECTION_ONLY:
            evidence.result_state = STATE_REFLECTION_ONLY
        elif not evidence.structured.get("oob_configured", True):
            evidence.result_state = STATE_CONFIRMATION_UNAVAILABLE
        else:
            evidence.result_state = st or STATE_CONFIRMATION_UNAVAILABLE
        evidence.structured["evidence_contract"] = (
            "unique nonce+scan/probe binding; server-originated; no reflected-URL TP"
        )
        return evidence


@register
class RedirectVerifier(_HttpFamilyVerifier):
    family = "redirect"
    capability_id = "redirect_controlled_host"
    param_re = _REDIR_PARAM

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        host = "redirect-proof.vantacrawl-lab.example"
        n = new_nonce(4)
        return [
            Probe(
                name="redirect_ext",
                payload=f"https://{host}/{n}",
                role="probe",
                meta={"proof_host": host},
                nonce=n,
                probe_id=new_probe_id(),
            )
        ]

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        if st in (STATE_SERVER_EXEC, "execution_confirmed"):
            evidence.result_state = STATE_SERVER_EXEC
            evidence.severity = "medium"
            evidence.verification = "confirmed"
        elif looks_reflected(evidence.structured.get("body") or "", evidence.structured.get("payload") or ""):
            evidence.result_state = STATE_REFLECTION_ONLY
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "Location/JS/meta navigation to controlled host; never classify as SSRF"
        )
        return evidence


@register
class TraversalVerifier(_HttpFamilyVerifier):
    family = "traversal"
    capability_id = "traversal_canary"
    param_re = _TRAV_PARAM

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {
            "http_client": True,
            "canary": bool((context.extras or {}).get("traversal_canary")),
        }

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        return [
            Probe(name="trav_dotdot", payload="../" * 6 + "etc/passwd", role="probe", probe_id=new_probe_id()),
            Probe(name="trav_canary", payload="", role="probe", meta={"canary": True}, probe_id=new_probe_id()),
        ]

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        if st == STATE_CANARY:
            evidence.result_state = STATE_CANARY
            evidence.severity = "high"
            evidence.verification = "confirmed"
            evidence.confidence = "high"
        elif st in (STATE_DIFFERENTIAL, STATE_SERVER_EXEC, "execution_confirmed"):
            evidence.result_state = st if st != "execution_confirmed" else STATE_SERVER_EXEC
        elif not evidence.structured.get("canary_configured", True):
            evidence.result_state = STATE_CONFIRMATION_UNAVAILABLE
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "exact canary content; absent in baseline; no generic error-string TP"
        )
        return evidence


@register
class CrlfVerifier(_HttpFamilyVerifier):
    family = "crlf"
    capability_id = "crlf_response_header"
    param_re = _CRLF_PARAM

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        n = new_nonce(4)
        return [
            Probe(
                name="crlf_header",
                payload=f"%0d%0aX-VC-CRLF-{n}: 1",
                role="probe",
                meta={"header": f"x-vc-crlf-{n}"},
                nonce=n,
                probe_id=new_probe_id(),
            )
        ]

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        hdrs = {k.lower(): v for k, v in (evidence.structured.get("headers") or {}).items()}
        proof_hdr = (evidence.structured.get("header") or "").lower()
        if proof_hdr and proof_hdr in hdrs:
            evidence.result_state = STATE_SERVER_EXEC
            evidence.severity = "medium"
            evidence.verification = "confirmed"
        elif st in (STATE_SERVER_EXEC, "execution_confirmed"):
            evidence.result_state = STATE_SERVER_EXEC
            evidence.verification = "confirmed"
            evidence.severity = "medium"
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "proof as distinct response header; not body/URL echo alone; replay"
        )
        return evidence


@register
class CsrfVerifier(VulnerabilityVerifier):
    family = "csrf"
    capability_id = "csrf_state_change"
    supported_modes = ("safe", "extended", "lab")
    phase = 1

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {"http_client": True, "session": bool((context.extras or {}).get("session"))}

    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        # State-changing forms only — never flag every tokenless form.
        if (context.method or "GET").upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            if not context.form_fields:
                return []
        if not context.form_fields:
            return []
        return [
            Candidate(
                family=self.family,
                parameter=",".join(context.form_fields[:6]),
                channel="form",
                url=context.url,
                method="POST",
                candidate_id=new_probe_id("cand"),
                meta={"fields": list(context.form_fields)},
            )
        ]

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        return [
            Probe(name="csrf_cross_origin", payload="", role="probe", meta={"forged_origin": True}, probe_id=new_probe_id()),
            Probe(name="csrf_negative_same_origin", payload="", role="control", meta={"forged_origin": False}, probe_id=new_probe_id()),
        ]

    async def execute(self, candidate, probe, runtime):
        client = getattr(runtime, "client", runtime)
        headers = {}
        if probe.meta.get("forged_origin"):
            headers["Origin"] = "https://evil.example"
            headers["Referer"] = "https://evil.example/"
        data = {f: "test" for f in (candidate.meta.get("fields") or ["email"])}
        return await client.post(candidate.url, data=data, headers=headers)

    def collect_evidence(self, candidate, probe, response, runtime, *, baseline=None, controls=None):
        snap = response_snap(response)
        return Evidence(
            result_state=STATE_INCONCLUSIVE,
            structured={"response": snap, "probe": probe.name},
            evidence_line=f"csrf status={snap['status']}",
        )

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        if st in (STATE_SERVER_EXEC, "execution_confirmed", "state_change_confirmed"):
            if evidence.structured.get("negative_control_changed"):
                evidence.result_state = STATE_INCONCLUSIVE
                evidence.detail = "CSRF candidate failed negative control"
            else:
                evidence.result_state = "state_change_confirmed"
                evidence.severity = "high"
                evidence.verification = "confirmed"
                evidence.confidence = "high"
        else:
            evidence.result_state = st or STATE_NEGATIVE
        evidence.structured["evidence_contract"] = (
            "cross-site state change with controlled session; negative control unchanged"
        )
        return evidence


@register
class DomClobberVerifier(VulnerabilityVerifier):
    family = "dom_clobber"
    capability_id = "dom_clobber_source_to_sink"
    supported_modes = ("safe", "extended", "lab")
    phase = 1

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {
            "http_client": True,
            "browser": bool((context.extras or {}).get("browser_available")),
        }

    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        # Any param that reflects live HTML is a candidate — names discovered dynamically.
        out = []
        for name in _params_from_context(context):
            out.append(_candidate(self.family, context, name))
        return out

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        # Actual structures are generated by dom_clobber.payloads from discovered properties.
        return [
            Probe(name="dom_clobber_dynamic", payload="", role="probe", meta={"dynamic": True}, probe_id=new_probe_id())
        ]

    async def execute(self, candidate, probe, runtime):
        return None

    def collect_evidence(self, candidate, probe, response, runtime, *, baseline=None, controls=None):
        return Evidence(result_state=STATE_INCONCLUSIVE, structured={})

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        evidence.result_state = st or STATE_INCONCLUSIVE
        if st == STATE_BROWSER_EXEC:
            evidence.severity = "high"
            evidence.verification = "confirmed"
            evidence.confidence = "high"
        evidence.structured["evidence_contract"] = (
            "HTML inject→property clobber→app read→sink→controlled proof; random-property negatives"
        )
        return evidence


def load_phase1() -> List[VulnerabilityVerifier]:
    """Ensure all Phase-1 verifiers are registered; return instances."""
    return [
        SqliVerifier(),
        RceVerifier(),
        SstiVerifier(),
        XssVerifier(),
        SsrfVerifier(),
        RedirectVerifier(),
        TraversalVerifier(),
        CrlfVerifier(),
        CsrfVerifier(),
        DomClobberVerifier(),
    ]


# Eager registration side effects via decorators above
load_phase1()
