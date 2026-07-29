"""Canonical post-run lifecycle rows and published Phase-1 metrics.

All published live-recall / coverage metrics must be derived from these rows —
never from stale pre-run maturity annotations or the legacy mandatory subset alone.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from verifiers.contract import CONFIRMED_ACTIVE_STATES, is_actively_confirmed
from verifiers.maturity import (
    MATURITY_CONTRACT_ONLY,
    MATURITY_EXECUTABLE_UNVALIDATED,
    MATURITY_LIVE_VALIDATED,
    MATURITY_REGISTERED_ADAPTER,
)


# Terminal proof states that may promote a vulnerable candidate to live_validated.
TERMINAL_PROOF_STATES = frozenset(CONFIRMED_ACTIVE_STATES)

# Explicitly non-terminal (never live validation)
NON_TERMINAL_STATES = frozenset(
    {
        "",
        "discovered",
        "discovered_only",
        "visited",
        "scheduled",
        "probe_sent",
        "reflected_only",
        "differential_signal",  # not terminal unless elevated to execution_confirmed
        "confirmation_unavailable",
        "inconclusive",
        "negative",
        "passive_indicator",
        "html_injection_confirmed",
        "clobbered_value_consumed",
        "named_property_clobbered",
        "sink_context_candidate",
        "clobber_without_sink",
        "marker_output_signal",
        "probable",
        "attribute_breakout",
        "manual_validation_required",
    }
)


def confirmation_tier(result_state: str) -> str:
    st = (result_state or "").strip()
    if st in TERMINAL_PROOF_STATES:
        return "terminal_proof"
    if st in NON_TERMINAL_STATES or not st:
        return "non_terminal"
    return "intermediate"


def proof_type_for_state(result_state: str) -> str:
    st = (result_state or "").strip()
    mapping = {
        "browser_execution_confirmed": "browser_execution",
        "controlled_request_confirmed": "controlled_network_request",
        "oob_callback_confirmed": "oob_callback",
        "server_execution_confirmed": "server_side_execution",
        "execution_confirmed": "server_side_execution",
        "canary_file_confirmed": "canary_file_read",
        "state_change_confirmed": "state_changing_form",
        "authorization_bypass_confirmed": "authorization_bypass",
        "sensitive_resource_confirmed": "sensitive_resource",
    }
    return mapping.get(st, "none")


def empty_lifecycle_row(
    *,
    plan_item: Dict[str, Any],
    mode: str,
    discovered_url: str = "",
) -> Dict[str, Any]:
    return {
        "fixture_id": plan_item.get("candidate_id") or "",
        "path": plan_item.get("path") or "",
        "discovered_url": discovered_url,
        "family": plan_item.get("family") or "",
        "mode": mode,
        "capability_id": plan_item.get("capability_id") or "",
        "capability_maturity_before": plan_item.get("capability_maturity_before") or "",
        "discovery_evidence": "",
        "baseline_captured": False,
        "control_sent": False,
        "control_result": "",
        "probe_sent": False,
        "http_method": plan_item.get("method") or "GET",
        "parameter_or_form_fields": plan_item.get("parameter") or "",
        "browser_used": False,
        "callback_oob_state": "unknown",
        "replay_attempted": False,
        "terminal_result_state": "",
        "confirmation_tier": "non_terminal",
        "evidence_provenance": "",
        "finding_emitted": False,
        "capability_maturity_after": plan_item.get("capability_maturity_before")
        or MATURITY_EXECUTABLE_UNVALIDATED,
        "schedule_status": plan_item.get("schedule_status") or "",
        "failure_or_exclusion_reason": plan_item.get("exclusion_reason") or "",
        "classification": plan_item.get("classification") or "",
        "must_not_confirm": bool(plan_item.get("must_not_confirm")),
        "support_classification": plan_item.get("support_classification") or "",
        "deps_available_for_live_recall": True,
        "negative_control_passed": None,
    }


def finalize_maturity_after(row: Dict[str, Any]) -> str:
    """Post-run maturity from this run's evidence only — never stale annotations."""
    before = row.get("capability_maturity_before") or MATURITY_EXECUTABLE_UNVALIDATED
    if row.get("schedule_status") not in ("", "attempted"):
        # Unattempted executable stays executable_unvalidated (not live)
        if before == MATURITY_LIVE_VALIDATED:
            return MATURITY_EXECUTABLE_UNVALIDATED
        return before if before else MATURITY_EXECUTABLE_UNVALIDATED
    state = str(row.get("terminal_result_state") or "")
    if row.get("must_not_confirm") or row.get("classification") == "control":
        # Controls never become live_validated successes
        return MATURITY_EXECUTABLE_UNVALIDATED
    if (
        row.get("probe_sent")
        and is_actively_confirmed(state)
        and confirmation_tier(state) == "terminal_proof"
        and row.get("deps_available_for_live_recall", True)
    ):
        return MATURITY_LIVE_VALIDATED
    if before == MATURITY_LIVE_VALIDATED:
        return MATURITY_EXECUTABLE_UNVALIDATED
    return before or MATURITY_EXECUTABLE_UNVALIDATED


def apply_probe_outcome(
    row: Dict[str, Any],
    *,
    probe_sent: bool,
    result_state: str,
    finding_emitted: bool,
    evidence: Optional[Dict[str, Any]] = None,
    browser_used: bool = False,
    callback_used: bool = False,
    transport_failed: bool = False,
    verification_failed: bool = False,
) -> Dict[str, Any]:
    ev = evidence or {}
    row["probe_sent"] = bool(probe_sent)
    row["terminal_result_state"] = str(result_state or "")
    row["confirmation_tier"] = confirmation_tier(row["terminal_result_state"])
    row["finding_emitted"] = bool(finding_emitted)
    row["baseline_captured"] = bool(row.get("baseline_captured") or int(ev.get("baseline_count") or 0) > 0)
    row["control_sent"] = bool(row.get("control_sent") or int(ev.get("control_count") or 0) > 0)
    row["replay_attempted"] = bool(row.get("replay_attempted") or int(ev.get("replay_count") or 0) > 0)
    row["browser_used"] = bool(browser_used or ev.get("browser_used") or row.get("browser_used"))
    if callback_used or "oob" in str(result_state):
        row["callback_oob_state"] = "used"
    row["parameter_or_form_fields"] = (
        row.get("parameter_or_form_fields")
        or ",".join(str(k) for k in (ev.get("submitted_fields") or {}).keys())
        or row.get("parameter_or_form_fields")
        or ""
    )
    if transport_failed:
        row["schedule_status"] = "transport_failed"
        row["failure_or_exclusion_reason"] = row.get("failure_or_exclusion_reason") or "transport_failed"
    if verification_failed and not is_actively_confirmed(str(result_state or "")):
        if row.get("probe_sent") and confirmation_tier(str(result_state or "")) != "terminal_proof":
            row["failure_or_exclusion_reason"] = (
                row.get("failure_or_exclusion_reason")
                or f"verification_failed:{result_state or 'empty'}"
            )
    # Negative control outcome for controls
    if row.get("must_not_confirm") or row.get("classification") == "control":
        row["negative_control_passed"] = not is_actively_confirmed(str(result_state or ""))
    row["capability_maturity_after"] = finalize_maturity_after(row)
    row["evidence_provenance"] = (
        f"result_state={row['terminal_result_state']};"
        f"proof={proof_type_for_state(row['terminal_result_state'])};"
        f"probe_sent={row['probe_sent']}"
    )
    return row


def compute_published_metrics(
    lifecycle: Sequence[Dict[str, Any]],
    *,
    mode: str,
    catalog_support_counts: Optional[Dict[str, int]] = None,
    legacy_subset_recall: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generate all published metrics from completed lifecycle rows."""
    rows = list(lifecycle)
    applicable = [
        r
        for r in rows
        if r.get("support_classification") == "supported_active"
        and r.get("capability_maturity_before")
        in (MATURITY_EXECUTABLE_UNVALIDATED, MATURITY_LIVE_VALIDATED, "")
    ]
    # If before was blank, still count supported_active plan rows
    if not applicable:
        applicable = [r for r in rows if r.get("support_classification") == "supported_active"]

    attempted = [r for r in applicable if r.get("schedule_status") == "attempted"]
    unattempted = [r for r in applicable if r.get("schedule_status") != "attempted"]

    terminal = [
        r
        for r in attempted
        if confirmation_tier(str(r.get("terminal_result_state") or "")) == "terminal_proof"
        or str(r.get("terminal_result_state") or "") in NON_TERMINAL_STATES
        or bool(r.get("probe_sent"))
    ]
    # Verification coverage: reached a classified terminal OR explicit non-terminal after probe
    reached_verification = [
        r
        for r in attempted
        if r.get("probe_sent")
        and str(r.get("terminal_result_state") or "") not in ("",)
    ]

    # Live recall denominator: vulnerable, executable, deps available, not mode-excluded
    live_denom_rows = [
        r
        for r in applicable
        if r.get("classification") == "vulnerable"
        and not r.get("must_not_confirm")
        and r.get("schedule_status") != "mode_excluded"
        and r.get("deps_available_for_live_recall", True)
        and r.get("schedule_status")
        not in (
            "no_executable_adapter",
            "dependency_unavailable",
        )
    ]
    live_num_rows = [
        r
        for r in live_denom_rows
        if r.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED
        and is_actively_confirmed(str(r.get("terminal_result_state") or ""))
        and r.get("probe_sent")
    ]

    controls = [
        r
        for r in attempted
        if r.get("must_not_confirm") or r.get("classification") == "control"
    ]
    fp_rows = [
        r
        for r in controls
        if is_actively_confirmed(str(r.get("terminal_result_state") or ""))
    ]

    # Post-run maturity counts across ALL lifecycle rows (supported_active plan)
    # plus we need full 155 — caller merges inventory for non-planned fixtures
    mat_after = {
        MATURITY_CONTRACT_ONLY: 0,
        MATURITY_REGISTERED_ADAPTER: 0,
        MATURITY_EXECUTABLE_UNVALIDATED: 0,
        MATURITY_LIVE_VALIDATED: 0,
    }
    for r in rows:
        m = r.get("capability_maturity_after") or MATURITY_EXECUTABLE_UNVALIDATED
        if m in mat_after:
            mat_after[m] += 1

    live_entries = [
        {
            "family": r.get("family"),
            "candidate": r.get("path") or r.get("fixture_id"),
            "mode": mode,
            "terminal_result_state": r.get("terminal_result_state"),
            "proof_type": proof_type_for_state(str(r.get("terminal_result_state") or "")),
            "evidence_location": r.get("evidence_provenance"),
            "negative_control_result": r.get("negative_control_passed"),
            "discovered_url": r.get("discovered_url"),
        }
        for r in rows
        if r.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED
        and r.get("classification") == "vulnerable"
        and not r.get("must_not_confirm")
    ]

    dep_gaps = [
        {
            "path": r.get("path"),
            "family": r.get("family"),
            "reason": r.get("failure_or_exclusion_reason") or r.get("schedule_status"),
        }
        for r in unattempted
        if r.get("schedule_status") == "dependency_unavailable"
        or str(r.get("failure_or_exclusion_reason") or "").startswith("dependency_unavailable")
    ]

    exec_cov_den = len(applicable)
    exec_cov_num = len(attempted)
    ver_cov_den = max(len(attempted), 1) if attempted else 0
    ver_cov_num = len(reached_verification)

    return {
        "mode": mode,
        "execution_coverage": {
            "numerator": exec_cov_num,
            "denominator": exec_cov_den,
            "rate": round(exec_cov_num / exec_cov_den, 4) if exec_cov_den else None,
            "note": "applicable executable candidates attempted / applicable executable candidates",
        },
        "verification_coverage": {
            "numerator": ver_cov_num,
            "denominator": ver_cov_den if attempted else 0,
            "rate": round(ver_cov_num / ver_cov_den, 4) if attempted else None,
            "note": "candidates with probe_sent and non-empty result_state / attempted",
        },
        "evidence_backed_live_recall": {
            "numerator": len(live_num_rows),
            "denominator": len(live_denom_rows),
            "rate": round(len(live_num_rows) / len(live_denom_rows), 4) if live_denom_rows else None,
            "note": (
                "vulnerable candidates with terminal confirmation / "
                "in-scope vulnerable executable candidates with deps available"
            ),
            "live_validated_entries": live_entries,
        },
        "negative_control_fp_rate": {
            "numerator": len(fp_rows),
            "denominator": len(controls),
            "rate": round(len(fp_rows) / len(controls), 4) if controls else 0.0,
            "fp_rows": [
                {"path": r.get("path"), "result_state": r.get("terminal_result_state")}
                for r in fp_rows
            ],
        },
        "dependency_coverage_gaps": dep_gaps,
        "legacy_acceptance_subset_recall": legacy_subset_recall,
        "post_run_maturity_counts_plan_rows": mat_after,
        "live_validated_count": len(live_entries),
        "attempted_count": len(attempted),
        "unattempted": [
            {
                "path": r.get("path"),
                "family": r.get("family"),
                "schedule_status": r.get("schedule_status"),
                "reason": r.get("failure_or_exclusion_reason"),
            }
            for r in unattempted
        ],
        "catalog_support_counts": catalog_support_counts or {},
    }


def merge_catalog_maturity_counts(
    inventory_fixtures: Sequence[Dict[str, Any]],
    lifecycle: Sequence[Dict[str, Any]],
) -> Dict[str, int]:
    """Full 155 maturity after run: lifecycle overrides for planned fixtures."""
    by_path = {str(r.get("path")): r for r in lifecycle}
    counts = {
        MATURITY_CONTRACT_ONLY: 0,
        MATURITY_REGISTERED_ADAPTER: 0,
        MATURITY_EXECUTABLE_UNVALIDATED: 0,
        MATURITY_LIVE_VALIDATED: 0,
    }
    for fix in inventory_fixtures:
        path = str(fix.get("path") or "")
        if path in by_path:
            m = by_path[path].get("capability_maturity_after") or MATURITY_EXECUTABLE_UNVALIDATED
        else:
            m = fix.get("capability_maturity") or MATURITY_CONTRACT_ONLY
            # Never keep stale live_validated for fixtures not in this run's plan
            if m == MATURITY_LIVE_VALIDATED:
                m = MATURITY_EXECUTABLE_UNVALIDATED
        if m not in counts:
            m = MATURITY_CONTRACT_ONLY
        counts[m] += 1
    return counts
