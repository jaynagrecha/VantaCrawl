"""CORS verifier states, severity, and report helpers — production-generic."""

from __future__ import annotations

from typing import Any, Dict, Optional

# Passive observations (never auto-confirm)
STATE_PASSIVE_HEADER_OBSERVED = "passive_header_observed"
STATE_WILDCARD_ORIGIN_OBSERVED = "wildcard_origin_observed"
STATE_REFLECTED_ORIGIN_OBSERVED = "reflected_origin_observed"
STATE_CREDENTIALS_FLAG_OBSERVED = "credentials_flag_observed"

# Non-confirmed / blocked
STATE_BROWSER_READ_BLOCKED = "browser_read_blocked"
STATE_PREFLIGHT_BLOCKED = "preflight_blocked"
STATE_ORIGIN_NOT_ALLOWED = "origin_not_allowed"
STATE_UNCREDENTIALED_PUBLIC_READ = "uncredentialed_public_read"
STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ = "reflected_origin_without_sensitive_read"
STATE_WILDCARD_WITH_CREDENTIALS_INVALID = "wildcard_with_credentials_invalid"
STATE_CREDENTIAL_PREREQUISITE_MISSING = "credential_prerequisite_missing"
STATE_CONTROLLED_SESSION_UNAVAILABLE = "controlled_session_unavailable"
STATE_PROOF_ORIGIN_UNAVAILABLE = "proof_origin_unavailable"
STATE_CONFIRMATION_UNAVAILABLE = "confirmation_unavailable"
STATE_INCONCLUSIVE = "inconclusive"
STATE_NEGATIVE = "negative"

# Confirmed active
STATE_CORS_BROWSER_READ_CONFIRMED = "cors_browser_read_confirmed"

CONFIRMED_STATES = frozenset({STATE_CORS_BROWSER_READ_CONFIRMED})

TERMINAL_NEGATIVE_STATES = frozenset(
    {
        STATE_NEGATIVE,
        STATE_BROWSER_READ_BLOCKED,
        STATE_PREFLIGHT_BLOCKED,
        STATE_ORIGIN_NOT_ALLOWED,
        STATE_WILDCARD_WITH_CREDENTIALS_INVALID,
        STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
    }
)

UNAVAILABLE_STATES = frozenset(
    {
        STATE_CONFIRMATION_UNAVAILABLE,
        STATE_CREDENTIAL_PREREQUISITE_MISSING,
        STATE_CONTROLLED_SESSION_UNAVAILABLE,
        STATE_PROOF_ORIGIN_UNAVAILABLE,
        STATE_INCONCLUSIVE,
    }
)


def is_confirmed(state: str) -> bool:
    return (state or "") in CONFIRMED_STATES


def severity_for(
    state: str,
    *,
    credential_mode: str = "omit",
    sensitive: bool = False,
    public_only: bool = False,
) -> str:
    """Severity depends on proof, not headers alone."""
    if not is_confirmed(state):
        if state in (
            STATE_PASSIVE_HEADER_OBSERVED,
            STATE_WILDCARD_ORIGIN_OBSERVED,
            STATE_REFLECTED_ORIGIN_OBSERVED,
            STATE_CREDENTIALS_FLAG_OBSERVED,
        ):
            return "info"
        if state == STATE_UNCREDENTIALED_PUBLIC_READ:
            return "low" if public_only else "info"
        return "info"
    if credential_mode == "include" and sensitive:
        return "high"
    if sensitive:
        return "medium"
    if public_only:
        return "low"
    return "medium"


def remediation_text() -> str:
    return (
        "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins; "
        "never blindly reflect the Origin header. Send Vary: Origin. Enable "
        "Access-Control-Allow-Credentials only when necessary and never with a wildcard "
        "origin. Deny null and untrusted origins. Correctly handle preflight "
        "(Access-Control-Allow-Methods/Headers). Reduce sensitive data in cross-origin "
        "readable responses."
    )


def build_cors_report(
    *,
    state: str,
    target_origin: str,
    proof_origin: str,
    credential_mode: str,
    readable: bool,
    replay_ok: Optional[bool],
    negative_control_ok: Optional[bool],
    confidence: str,
    prerequisites: Dict[str, Any],
    limitations: str,
) -> Dict[str, Any]:
    return {
        "family": "cors",
        "observation_vs_confirmation": (
            "confirmation" if is_confirmed(state) else "observation_or_non_confirmed"
        ),
        "result_state": state,
        "target_origin": target_origin,
        "proof_origin": proof_origin,
        "credential_mode": credential_mode,
        "browser_readable": bool(readable),
        "replay_ok": replay_ok,
        "negative_control_ok": negative_control_ok,
        "confidence": confidence,
        "prerequisites": dict(prerequisites or {}),
        "limitations": limitations,
        "remediation": remediation_text(),
        "safe_reproduction": (
            "Open the controlled proof origin page with a job-bound token and observe "
            "whether fetch() can read the target response body. Do not paste session "
            "cookies into reports."
        ),
    }
