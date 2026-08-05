"""Map CORS observations + browser evidence to strict result states."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from verifiers.cors.contract import (
    STATE_BROWSER_READ_BLOCKED,
    STATE_CONFIRMATION_UNAVAILABLE,
    STATE_CONTROLLED_SESSION_UNAVAILABLE,
    STATE_CORS_BROWSER_READ_CONFIRMED,
    STATE_CREDENTIAL_PREREQUISITE_MISSING,
    STATE_INCONCLUSIVE,
    STATE_NEGATIVE,
    STATE_ORIGIN_NOT_ALLOWED,
    STATE_PASSIVE_HEADER_OBSERVED,
    STATE_PREFLIGHT_BLOCKED,
    STATE_PROOF_ORIGIN_UNAVAILABLE,
    STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
    STATE_UNCREDENTIALED_PUBLIC_READ,
    STATE_WILDCARD_WITH_CREDENTIALS_INVALID,
    is_confirmed,
    severity_for,
)


def classify_cors(
    *,
    mode: str,
    selection_reasons: List[str],
    acao: str,
    acac: bool,
    proof_origin_available: bool,
    browser_available: bool,
    credential_mode: str,
    session_available: bool,
    browser_result: Optional[Dict[str, Any]],
    replay_result: Optional[Dict[str, Any]],
    negative_result: Optional[Dict[str, Any]],
    sensitive: bool,
    public_only: bool,
) -> Dict[str, Any]:
    reasons = list(selection_reasons or [])
    br = browser_result or {}
    rr = replay_result or {}
    nr = negative_result or {}

    # Wildcard + credentials is invalid in browsers — never confirm from headers alone.
    if acao == "*" and acac and not (br.get("readable") and br.get("canary_found")):
        # If browser somehow ran, it should be blocked
        if br.get("decision") in ("browser_read_blocked", "readable_canary_missing") or br.get("readable") is False:
            return {
                "result_state": STATE_WILDCARD_WITH_CREDENTIALS_INVALID,
                "severity": "info",
                "confidence": "high",
                "verification": "not_exploitable",
            }
        return {
            "result_state": STATE_WILDCARD_WITH_CREDENTIALS_INVALID,
            "severity": "info",
            "confidence": "high",
            "verification": "header_only",
        }

    if not proof_origin_available:
        return {
            "result_state": STATE_PROOF_ORIGIN_UNAVAILABLE,
            "severity": "info",
            "confidence": "high",
            "verification": "confirmation_unavailable",
        }

    if mode in ("extended", "lab") and not browser_available:
        return {
            "result_state": STATE_CONFIRMATION_UNAVAILABLE,
            "severity": "info",
            "confidence": "medium",
            "verification": "manual_validation_required",
        }

    if credential_mode == "include" and not session_available:
        # Still allow uncredentialed probe path separately; this branch is for
        # credentialed confirmation attempts.
        if not br:
            return {
                "result_state": STATE_CONTROLLED_SESSION_UNAVAILABLE,
                "severity": "info",
                "confidence": "high",
                "verification": "confirmation_unavailable",
            }

    if not br:
        # Passive-only path
        if "passive_header_observation" in reasons or acao:
            return {
                "result_state": STATE_PASSIVE_HEADER_OBSERVED,
                "severity": "info",
                "confidence": "medium",
                "verification": "passive",
            }
        return {
            "result_state": STATE_INCONCLUSIVE,
            "severity": "info",
            "confidence": "low",
            "verification": "unverified",
        }

    decision = str(br.get("decision") or "")
    if decision in ("navigation_or_timeout", "browser_unavailable"):
        return {
            "result_state": STATE_INCONCLUSIVE,
            "severity": "info",
            "confidence": "low",
            "verification": "inconclusive",
        }
    if decision == "stale_or_mismatched_evidence":
        return {
            "result_state": STATE_NEGATIVE,
            "severity": "info",
            "confidence": "high",
            "verification": "rejected_mismatched_evidence",
        }
    if decision == "browser_read_blocked" or br.get("readable") is False:
        if "origin_not_allowed" in reasons or decision == "browser_read_blocked":
            return {
                "result_state": STATE_BROWSER_READ_BLOCKED,
                "severity": "info",
                "confidence": "high",
                "verification": "negative",
            }
        return {
            "result_state": STATE_ORIGIN_NOT_ALLOWED,
            "severity": "info",
            "confidence": "high",
            "verification": "negative",
        }
    if decision == "preflight_blocked":
        return {
            "result_state": STATE_PREFLIGHT_BLOCKED,
            "severity": "info",
            "confidence": "high",
            "verification": "negative",
        }

    readable = bool(br.get("readable"))
    canary_found = bool(br.get("canary_found"))
    correlation_ok = bool(br.get("correlation_ok"))
    replay_ok = bool(rr.get("readable")) and (
        (not br.get("canary_expected")) or bool(rr.get("canary_found"))
    ) and bool(rr.get("correlation_ok"))
    # Negative control must NOT obtain the same sensitive read
    neg_bad = bool(nr.get("readable")) and bool(nr.get("canary_found")) and bool(nr.get("correlation_ok"))
    negative_ok = (not nr) or (not neg_bad)

    if readable and not canary_found and not sensitive:
        # Reflected Origin without sensitive/canary content is not confirmation.
        if "reflected_origin" in reasons or acac:
            return {
                "result_state": STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
                "severity": "info",
                "confidence": "medium",
                "verification": "not_confirmed",
            }
        # Public/non-sensitive cross-origin read (e.g. ACAO *)
        if credential_mode != "include":
            return {
                "result_state": STATE_UNCREDENTIALED_PUBLIC_READ,
                "severity": severity_for(
                    STATE_UNCREDENTIALED_PUBLIC_READ, public_only=True
                ),
                "confidence": "medium",
                "verification": "browser_read_public",
            }
        return {
            "result_state": STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
            "severity": "info",
            "confidence": "medium",
            "verification": "not_confirmed",
        }

    if readable and correlation_ok and (canary_found or sensitive) and replay_ok and negative_ok:
        return {
            "result_state": STATE_CORS_BROWSER_READ_CONFIRMED,
            "severity": severity_for(
                STATE_CORS_BROWSER_READ_CONFIRMED,
                credential_mode=credential_mode,
                sensitive=bool(canary_found or sensitive),
                public_only=public_only,
            ),
            "confidence": "high",
            "verification": "confirmed",
            "replay_ok": True,
            "negative_control_ok": True,
        }

    if readable and correlation_ok and (canary_found or sensitive) and not replay_ok:
        return {
            "result_state": STATE_INCONCLUSIVE,
            "severity": "info",
            "confidence": "medium",
            "verification": "replay_failed",
        }

    if readable and correlation_ok and (canary_found or sensitive) and not negative_ok:
        return {
            "result_state": STATE_INCONCLUSIVE,
            "severity": "info",
            "confidence": "medium",
            "verification": "negative_control_failed",
        }

    if "reflected_origin" in reasons and not canary_found:
        return {
            "result_state": STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
            "severity": "info",
            "confidence": "medium",
            "verification": "not_confirmed",
        }

    if credential_mode == "include" and not session_available:
        return {
            "result_state": STATE_CREDENTIAL_PREREQUISITE_MISSING,
            "severity": "info",
            "confidence": "high",
            "verification": "confirmation_unavailable",
        }

    return {
        "result_state": STATE_INCONCLUSIVE,
        "severity": "info",
        "confidence": "low",
        "verification": "inconclusive",
    }


def lifecycle_outcome_for(state: str) -> str:
    if is_confirmed(state):
        return "terminal_confirmed"
    if state in (
        STATE_NEGATIVE,
        STATE_BROWSER_READ_BLOCKED,
        STATE_ORIGIN_NOT_ALLOWED,
        STATE_PREFLIGHT_BLOCKED,
        STATE_WILDCARD_WITH_CREDENTIALS_INVALID,
        STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
        STATE_UNCREDENTIALED_PUBLIC_READ,
    ):
        return "terminal_negative"
    if state in (
        STATE_CONFIRMATION_UNAVAILABLE,
        STATE_PROOF_ORIGIN_UNAVAILABLE,
        STATE_CONTROLLED_SESSION_UNAVAILABLE,
        STATE_CREDENTIAL_PREREQUISITE_MISSING,
        STATE_INCONCLUSIVE,
        STATE_PASSIVE_HEADER_OBSERVED,
    ):
        return "terminal_inconclusive"
    return "terminal_inconclusive"
