"""Shared result states and evidence contracts for generic verifiers.

Production code must not hardcode Horizon routes, parameters, markers, or domains.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Optional

# Universal / family result states (scanner-produced; evaluator must not rewrite)
STATE_DISCOVERED_ONLY = "discovered_only"
STATE_INPUT_IDENTIFIED = "input_identified"
STATE_PROBE_SENT = "probe_sent"
STATE_BEHAVIOR_CHANGED = "behavior_changed"
STATE_DIFFERENTIAL = "differential_signal"
STATE_REFLECTION_ONLY = "reflected_only"
STATE_HTML_INJECTION = "html_injection_confirmed"
STATE_BROWSER_EXEC = "browser_execution_confirmed"
STATE_SERVER_EXEC = "server_execution_confirmed"
STATE_OOB_CALLBACK = "oob_callback_confirmed"
STATE_AUTHZ_BYPASS = "authorization_bypass_confirmed"
STATE_STATE_CHANGE = "state_change_confirmed"
STATE_SENSITIVE_RESOURCE = "sensitive_resource_confirmed"
STATE_MISCONFIG = "misconfiguration_confirmed"
STATE_PASSIVE_INDICATOR = "passive_indicator"
STATE_MANUAL = "manual_validation_required"
STATE_BLOCKED_WAF = "blocked_by_waf"
STATE_BLOCKED_CSP = "blocked_by_csp"
STATE_RATE_LIMITED = "rate_limited"
STATE_CONFIRMATION_UNAVAILABLE = "confirmation_unavailable"
STATE_INCONCLUSIVE = "inconclusive"
STATE_NEGATIVE = "negative"
STATE_UNSUPPORTED = "unsupported"
STATE_CANARY = "canary_file_confirmed"
STATE_EXECUTION_CONFIRMED = "execution_confirmed"  # ledger alias for server exec
STATE_PROBABLE = "probable"
STATE_ATTR_BREAKOUT = "attribute_breakout"
STATE_SINK_CANDIDATE = "sink_context_candidate"
STATE_MARKER = "marker_output_signal"
STATE_CONTROLLED_REQUEST = "controlled_request_confirmed"

# Fixture-level honest statuses (benchmark reporting)
STATUS_ACTIVELY_VERIFIED = "actively_verified"
STATUS_PASSIVELY_CONFIRMED = "passively_confirmed"
STATUS_MANUAL = "manual_validation_required"
STATUS_CONFIRMATION_UNAVAILABLE = "confirmation_unavailable"
STATUS_UNSUPPORTED = "unsupported"
STATUS_NEGATIVE_CONTROL_PASSED = "negative_control_passed"
STATUS_MISSED = "missed_fixture"
STATUS_INCONCLUSIVE = "inconclusive"

# Phase-2 CORS confirmed browser-read state (imported as string to avoid cycles)
STATE_CORS_BROWSER_READ = "cors_browser_read_confirmed"

CONFIRMED_ACTIVE_STATES: FrozenSet[str] = frozenset(
    {
        STATE_BROWSER_EXEC,
        STATE_SERVER_EXEC,
        STATE_OOB_CALLBACK,
        STATE_CANARY,
        STATE_EXECUTION_CONFIRMED,
        STATE_AUTHZ_BYPASS,
        STATE_STATE_CHANGE,
        STATE_SENSITIVE_RESOURCE,
        STATE_CONTROLLED_REQUEST,
        STATE_CORS_BROWSER_READ,
    }
)

# Failure-stage taxonomy (benchmark)
FAILURE_STAGES = (
    "not_discovered",
    "not_parameterized",
    "not_scheduled",
    "mode_excluded",
    "prerequisite_missing",
    "probe_not_sent",
    "form_not_submitted",
    "browser_unavailable",
    "callback_unavailable",
    "request_failed",
    "response_classification_failed",
    "negative_control_failed",
    "replay_failed",
    "proof_not_attributable",
    "finding_not_emitted",
    "result_state_mismatch",
    "cleanup_failed",
    "unsupported",
)

PRODUCT_CLAIM = (
    "VantaCrawl has a generic DOM-clobber verifier and a generic verification "
    "framework. Individual family capabilities are reported according to their "
    "implementation and live-validation maturity. Horizon Catalog measures "
    "supported-active recall separately from passive/manual and unsupported "
    "coverage; published live recall counts only live_validated fixtures."
)


def is_actively_confirmed(result_state: str) -> bool:
    return (result_state or "") in CONFIRMED_ACTIVE_STATES


def map_fixture_status(
    *,
    bucket: str,
    classification: str,
    discovered: bool,
    probe_sent: bool,
    result_state: str,
    expected_result_state: str,
    must_not_confirm: bool,
    match: bool,
    confirmation_unavailable: bool = False,
) -> str:
    """Map ledger/evaluation signals to an honest fixture-level status."""
    b = (bucket or "").lower()
    state = (result_state or "").strip()
    if b in ("unsupported",):
        return STATUS_UNSUPPORTED
    if b in ("passive_manual", "passive"):
        if state in (STATE_PASSIVE_INDICATOR, STATE_MISCONFIG) or match:
            return STATUS_PASSIVELY_CONFIRMED
        return STATUS_MANUAL
    # supported_active
    if must_not_confirm:
        if is_actively_confirmed(state):
            return STATUS_INCONCLUSIVE  # FP path; evaluator marks fail separately
        if match or state in (STATE_NEGATIVE, "", STATE_REFLECTION_ONLY, "not_applicable"):
            return STATUS_NEGATIVE_CONTROL_PASSED
        return STATUS_NEGATIVE_CONTROL_PASSED if not is_actively_confirmed(state) else STATUS_INCONCLUSIVE
    if confirmation_unavailable or state == STATE_CONFIRMATION_UNAVAILABLE:
        return STATUS_CONFIRMATION_UNAVAILABLE
    if not discovered:
        return STATUS_MISSED
    if not probe_sent and expected_result_state:
        return STATUS_MISSED
    if match and is_actively_confirmed(state):
        return STATUS_ACTIVELY_VERIFIED
    if match and state in (
        STATE_REFLECTION_ONLY,
        STATE_DIFFERENTIAL,
        STATE_PROBABLE,
        STATE_HTML_INJECTION,
        STATE_SINK_CANDIDATE,
        STATE_NEGATIVE,
    ):
        # Expected non-exec states that still satisfy the fixture contract
        return STATUS_ACTIVELY_VERIFIED if expected_result_state == state else STATUS_INCONCLUSIVE
    if match:
        return STATUS_ACTIVELY_VERIFIED
    if state == STATE_INCONCLUSIVE:
        return STATUS_INCONCLUSIVE
    if state in (STATE_MANUAL, STATE_PASSIVE_INDICATOR):
        return STATUS_MANUAL
    if not probe_sent:
        return STATUS_MISSED
    return STATUS_INCONCLUSIVE


def evidence_skeleton(
    *,
    family: str,
    capability_id: str,
    result_state: str,
    scan_id: str = "",
    probe_id: str = "",
    candidate_id: str = "",
    endpoint: str = "",
    parameter: str = "",
    browser_session_id: str = "",
    nonce: str = "",
    baseline_hash: str = "",
    control_ok: Optional[bool] = None,
    replay_ok: Optional[bool] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "family": family,
        "capability_id": capability_id,
        "result_state": result_state,
        "scan_id": scan_id,
        "probe_id": probe_id,
        "candidate_id": candidate_id,
        "endpoint": endpoint,
        "parameter": parameter,
        "browser_session_id": browser_session_id,
        "nonce": nonce,
        "baseline_hash": baseline_hash,
        "negative_control_ok": control_ok,
        "replay_ok": replay_ok,
        "actively_confirmed": is_actively_confirmed(result_state),
        "details": dict(extra or {}),
    }
