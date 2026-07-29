"""DOM-clobber confirmation-state contract and report helpers.

Production scanner code must not hardcode Horizon routes, parameter names,
property names, fixture assets, or benchmark markers.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Strict confirmation ladder (screenshot / acceptance contract)
STATE_HTML_INJECTION_CONFIRMED = "html_injection_confirmed"
STATE_NAMED_PROPERTY_CLOBBERED = "named_property_clobbered"
STATE_CLOBBERED_VALUE_CONSUMED = "clobbered_value_consumed"
STATE_SINK_CONTEXT_CANDIDATE = "sink_context_candidate"
STATE_CLOBBER_WITHOUT_SINK = "clobber_without_sink"
STATE_CONTROLLED_REQUEST_CONFIRMED = "controlled_request_confirmed"
STATE_BROWSER_EXECUTION_CONFIRMED = "browser_execution_confirmed"
STATE_BLOCKED_BY_CSP = "blocked_by_csp"
STATE_REFLECTED_ONLY = "reflected_only"
STATE_INCONCLUSIVE = "inconclusive"
STATE_NEGATIVE = "negative"

# High-severity confirmed states only
CONFIRMED_VULN_STATES = frozenset(
    {
        STATE_BROWSER_EXECUTION_CONFIRMED,
        STATE_CONTROLLED_REQUEST_CONFIRMED,
    }
)

# Safe mode must never escalate past these
SAFE_MODE_MAX_STATES = frozenset(
    {
        STATE_HTML_INJECTION_CONFIRMED,
        STATE_NAMED_PROPERTY_CLOBBERED,
        STATE_CLOBBERED_VALUE_CONSUMED,
        STATE_SINK_CONTEXT_CANDIDATE,
        STATE_CLOBBER_WITHOUT_SINK,
        STATE_REFLECTED_ONLY,
        STATE_INCONCLUSIVE,
        STATE_NEGATIVE,
        STATE_BLOCKED_BY_CSP,
    }
)

# Dangerous sinks we prioritize when correlating reads → use
PRIORITY_SINKS = (
    "script.src",
    "iframe.src",
    "object.data",
    "embed.src",
    "link.href",
    "location",
    "location.href",
    "window.open",
    "fetch",
    "XMLHttpRequest.open",
    "WebSocket",
    "Worker",
    "import",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval",
    "Function",
    "setTimeout",
    "form.action",
)

SEVERITY_FOR_STATE = {
    STATE_BROWSER_EXECUTION_CONFIRMED: "high",
    STATE_CONTROLLED_REQUEST_CONFIRMED: "high",
    STATE_BLOCKED_BY_CSP: "medium",
    STATE_SINK_CONTEXT_CANDIDATE: "medium",
    STATE_CLOBBERED_VALUE_CONSUMED: "medium",
    STATE_NAMED_PROPERTY_CLOBBERED: "low",
    STATE_HTML_INJECTION_CONFIRMED: "info",
    STATE_CLOBBER_WITHOUT_SINK: "info",
    STATE_REFLECTED_ONLY: "info",
    STATE_INCONCLUSIVE: "info",
    STATE_NEGATIVE: "info",
}


def severity_for(state: str) -> str:
    return SEVERITY_FOR_STATE.get(state, "info")


def is_confirmed_vuln(state: str) -> bool:
    return state in CONFIRMED_VULN_STATES


def clamp_state_for_mode(state: str, mode: str) -> str:
    """Safe mode never reports executable / controlled-request confirmation."""
    m = (mode or "safe").strip().lower()
    if m == "safe" and state in CONFIRMED_VULN_STATES:
        return STATE_SINK_CONTEXT_CANDIDATE
    if m == "safe" and state not in SAFE_MODE_MAX_STATES:
        return STATE_INCONCLUSIVE
    return state


def build_dom_clobber_report(
    *,
    url: str,
    method: str,
    parameter: str,
    injected_structure_redacted: str,
    clobbered_property: str,
    original_type: str = "",
    post_injection_type: str = "",
    consuming_script_url: str = "",
    sink_name: str = "",
    sink_argument_redacted: str = "",
    proof_nonce: str = "",
    probe_id: str = "",
    scan_id: str = "",
    browser_session_id: str = "",
    validation_state: str,
    confidence: str,
    replay_ok: Optional[bool] = None,
    negative_control_ok: Optional[bool] = None,
    csp_effect: str = "",
    ladder_stage: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    severity_rationale: str = "",
) -> Dict[str, Any]:
    """Structured finding extras for DOM-clobber reports (A–E ladder)."""
    return {
        "family": "dom_clobber",
        "claim": (
            "Dynamic DOM-clobber source-to-sink verification for supported "
            "browser and injection contexts."
        ),
        "url": url,
        "method": method,
        "parameter": parameter,
        "injected_dom_structure_redacted": (injected_structure_redacted or "")[:500],
        "clobbered_property_path": clobbered_property,
        "original_property_type": original_type,
        "post_injection_property_type": post_injection_type,
        "consuming_script_url": consuming_script_url,
        "sink_name": sink_name,
        "sink_argument_redacted": (sink_argument_redacted or "")[:300],
        "proof_nonce": proof_nonce,
        "probe_id": probe_id,
        "scan_id": scan_id,
        "browser_session_id": browser_session_id,
        "validation_state": validation_state,
        "confidence": confidence,
        "replay_result": replay_ok,
        "negative_control_result": negative_control_ok,
        "csp_effect": csp_effect,
        "ladder_stage": ladder_stage,
        "severity_rationale": severity_rationale,
        "evidence": dict(evidence or {}),
        "stages": {
            "A_html_injection": validation_state
            not in (STATE_REFLECTED_ONLY, STATE_NEGATIVE, STATE_INCONCLUSIVE),
            "B_property_clobber": validation_state
            in (
                STATE_NAMED_PROPERTY_CLOBBERED,
                STATE_CLOBBERED_VALUE_CONSUMED,
                STATE_SINK_CONTEXT_CANDIDATE,
                STATE_CLOBBER_WITHOUT_SINK,
                STATE_CONTROLLED_REQUEST_CONFIRMED,
                STATE_BROWSER_EXECUTION_CONFIRMED,
                STATE_BLOCKED_BY_CSP,
            ),
            "C_value_consumed": validation_state
            in (
                STATE_CLOBBERED_VALUE_CONSUMED,
                STATE_SINK_CONTEXT_CANDIDATE,
                STATE_CONTROLLED_REQUEST_CONFIRMED,
                STATE_BROWSER_EXECUTION_CONFIRMED,
                STATE_BLOCKED_BY_CSP,
            ),
            "D_sink_reached": validation_state
            in (
                STATE_SINK_CONTEXT_CANDIDATE,
                STATE_CONTROLLED_REQUEST_CONFIRMED,
                STATE_BROWSER_EXECUTION_CONFIRMED,
                STATE_BLOCKED_BY_CSP,
            ),
            "E_execution_or_controlled_request": validation_state in CONFIRMED_VULN_STATES,
        },
    }
