"""Canonical post-run lifecycle rows and published Phase-1 metrics.

All published live-recall / coverage metrics must be derived from these rows —
never from stale pre-run maturity annotations or the legacy mandatory subset alone.

Lifecycle outcome classes (exactly one per attempted candidate):

  A. terminal_confirmed   — family-specific evidence proving vulnerable behavior
  B. terminal_negative    — probe (+ required control) completed; not vulnerable
  C. terminal_inconclusive — execution completed; evidence insufficient to classify
  D. nonterminal          — verification lifecycle did not finish

A non-empty result_state alone is never treated as terminal verification.
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

OUTCOME_TERMINAL_CONFIRMED = "terminal_confirmed"
OUTCOME_TERMINAL_NEGATIVE = "terminal_negative"
OUTCOME_TERMINAL_INCONCLUSIVE = "terminal_inconclusive"
OUTCOME_NONTERMINAL = "nonterminal"

LIFECYCLE_COMPLETE_OUTCOMES = frozenset(
    {
        OUTCOME_TERMINAL_CONFIRMED,
        OUTCOME_TERMINAL_NEGATIVE,
        OUTCOME_TERMINAL_INCONCLUSIVE,
    }
)

# States that mean the lifecycle finished without confirmation or a clean negative.
INCONCLUSIVE_COMPLETED_STATES = frozenset(
    {
        "reflected_only",
        "differential_signal",  # non-terminal by family contract unless elevated
        "html_injection_confirmed",
        "html_injection",
        "inconclusive",
        "confirmation_unavailable",
        "probable",
        "attribute_breakout",
        "passive_indicator",
        "clobbered_value_consumed",
        "named_property_clobbered",
        "sink_context_candidate",
        "clobber_without_sink",
        "marker_output_signal",
        "manual_validation_required",
        "behavior_changed",
        "input_identified",
        # Phase-2 CORS non-confirming completed states
        "passive_header_observed",
        "reflected_origin_without_sensitive_read",
        "uncredentialed_public_read",
        "proof_origin_unavailable",
        "controlled_session_unavailable",
        "credential_prerequisite_missing",
    }
)

# Explicit CORS negatives (completed probe, not vulnerable confirmation)
CORS_TERMINAL_NEGATIVE_STATES = frozenset(
    {
        "browser_read_blocked",
        "preflight_blocked",
        "origin_not_allowed",
        "wildcard_with_credentials_invalid",
    }
)

# States that mean the lifecycle did not finish.
NONTERMINAL_RAW_STATES = frozenset(
    {
        "",
        "discovered",
        "discovered_only",
        "visited",
        "scheduled",
        "probe_sent",
        "browser_started",
        "callback_pending",
        "replay_pending",
        "breaker_paused",
        "transport_failed",
        "dependency_unavailable",
        "unsupported",
        "blocked_by_waf",
        "blocked_by_csp",
        "rate_limited",
    }
)

# Explicitly non-terminal for live validation (never live_validated).
NON_TERMINAL_STATES = frozenset(
    NONTERMINAL_RAW_STATES
    | INCONCLUSIVE_COMPLETED_STATES
    | {"negative"}
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
        "cors_browser_read_confirmed": "cors_browser_read",
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


def classify_lifecycle_outcome(row: Dict[str, Any]) -> str:
    """Map one lifecycle row to exactly one outcome class A/B/C/D.

    Rules:
    - Confirmed-active states → terminal_confirmed (never for controls as success path;
      controls that reach confirmed-active are still class A for FP accounting, but
      maturity stays unvalidated).
    - Explicit ``negative`` after probe → terminal_negative.
    - Controls that completed a probe without active confirmation and reached a
      completed inconclusive signal (e.g. reflected_only) → terminal_negative
      (determined not vulnerable for that control input).
    - Completed non-confirming signals (reflected_only, differential_signal, …)
      on vulnerables → terminal_inconclusive.
    - probe_sent / empty / pending / interrupted / dependency gaps → nonterminal.
    - Unattempted / mode_excluded rows are not lifecycle-completion candidates;
      classify from raw state for bookkeeping (usually nonterminal).
    """
    state = str(row.get("terminal_result_state") or "").strip()
    schedule = str(row.get("schedule_status") or "")
    is_control = bool(row.get("must_not_confirm") or row.get("classification") == "control")
    probe_sent = bool(row.get("probe_sent"))

    if schedule in (
        "mode_excluded",
        "dependency_unavailable",
        "no_executable_adapter",
        "breaker_paused",
        "transport_failed",
        "discovery_missing",
    ):
        return OUTCOME_NONTERMINAL

    if state in TERMINAL_PROOF_STATES and is_actively_confirmed(state):
        return OUTCOME_TERMINAL_CONFIRMED

    if state == "negative" and probe_sent:
        return OUTCOME_TERMINAL_NEGATIVE

    if state in CORS_TERMINAL_NEGATIVE_STATES and probe_sent:
        return OUTCOME_TERMINAL_NEGATIVE

    if state in INCONCLUSIVE_COMPLETED_STATES and probe_sent:
        # Control completed without false confirmation → negative determination.
        if is_control:
            return OUTCOME_TERMINAL_NEGATIVE
        return OUTCOME_TERMINAL_INCONCLUSIVE

    # Intermediate unknown states: if probe finished with a named non-empty state
    # that is neither confirmed nor explicitly nonterminal-pending, treat as
    # inconclusive completion rather than inflating confirmation.
    if (
        probe_sent
        and state
        and state not in NONTERMINAL_RAW_STATES
        and state not in TERMINAL_PROOF_STATES
    ):
        if is_control:
            return OUTCOME_TERMINAL_NEGATIVE
        return OUTCOME_TERMINAL_INCONCLUSIVE

    return OUTCOME_NONTERMINAL


def unresolved_reason_for_row(row: Dict[str, Any]) -> str:
    outcome = str(row.get("lifecycle_outcome") or classify_lifecycle_outcome(row))
    state = str(row.get("terminal_result_state") or "").strip()
    if outcome == OUTCOME_TERMINAL_CONFIRMED:
        return ""
    if row.get("schedule_status") == "mode_excluded":
        return row.get("failure_or_exclusion_reason") or "mode_excluded"
    if row.get("schedule_status") == "dependency_unavailable":
        return row.get("failure_or_exclusion_reason") or "dependency_unavailable"
    if outcome == OUTCOME_NONTERMINAL:
        if state == "probe_sent":
            return "probe_sent_without_terminal_evaluation"
        if not state:
            return "empty_result_state"
        if not row.get("probe_sent"):
            return "probe_not_sent"
        return row.get("failure_or_exclusion_reason") or f"nonterminal:{state}"
    if outcome == OUTCOME_TERMINAL_INCONCLUSIVE:
        return f"inconclusive:{state or 'unknown'}"
    if outcome == OUTCOME_TERMINAL_NEGATIVE:
        return ""
    return row.get("failure_or_exclusion_reason") or ""


def empty_lifecycle_row(
    *,
    plan_item: Dict[str, Any],
    mode: str,
    discovered_url: str = "",
) -> Dict[str, Any]:
    row = {
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
        "lifecycle_outcome": OUTCOME_NONTERMINAL,
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
        "applicable_mode": mode,
        "unresolved_reason": "",
    }
    row["lifecycle_outcome"] = classify_lifecycle_outcome(row)
    row["unresolved_reason"] = unresolved_reason_for_row(row)
    return row


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
    row["lifecycle_outcome"] = classify_lifecycle_outcome(row)
    row["unresolved_reason"] = unresolved_reason_for_row(row)
    row["capability_maturity_after"] = finalize_maturity_after(row)
    row["evidence_provenance"] = (
        f"result_state={row['terminal_result_state']};"
        f"proof={proof_type_for_state(row['terminal_result_state'])};"
        f"outcome={row['lifecycle_outcome']};"
        f"probe_sent={row['probe_sent']}"
    )
    return row


def _rate(num: int, den: int) -> Optional[float]:
    if den <= 0:
        return None
    return round(num / den, 4)


def annotate_lifecycle_outcomes(lifecycle: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ensure every row carries lifecycle_outcome + unresolved_reason."""
    out: List[Dict[str, Any]] = []
    for raw in lifecycle:
        row = dict(raw)
        row["lifecycle_outcome"] = classify_lifecycle_outcome(row)
        row["unresolved_reason"] = unresolved_reason_for_row(row)
        out.append(row)
    return out


def build_reconciliation_entry(row: Dict[str, Any]) -> Dict[str, Any]:
    """One supported-active reconciliation row for audit tables."""
    outcome = str(row.get("lifecycle_outcome") or classify_lifecycle_outcome(row))
    state = str(row.get("terminal_result_state") or "")
    live = (
        row.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED
        and row.get("classification") == "vulnerable"
        and not row.get("must_not_confirm")
        and is_actively_confirmed(state)
        and outcome == OUTCOME_TERMINAL_CONFIRMED
    )
    return {
        "candidate_id": row.get("fixture_id") or row.get("path"),
        "path": row.get("path"),
        "family": row.get("family"),
        "discovered_url": row.get("discovered_url"),
        "capability_id": row.get("capability_id"),
        "applicable_mode": row.get("applicable_mode") or row.get("mode"),
        "scheduled": row.get("schedule_status")
        not in ("", "discovery_missing", "no_executable_adapter"),
        "attempted": row.get("schedule_status") == "attempted",
        "control_executed": bool(row.get("control_sent")),
        "probe_executed": bool(row.get("probe_sent")),
        "replay_executed": bool(row.get("replay_attempted")),
        "dependency_availability": (
            "available"
            if row.get("deps_available_for_live_recall", True)
            and row.get("schedule_status") != "dependency_unavailable"
            else "unavailable"
        ),
        "raw_result_state": state,
        "normalized_terminal_class": outcome,
        "terminal_proof_type": proof_type_for_state(state),
        "evidence_location": row.get("evidence_provenance"),
        "live_validated": bool(live),
        "finding_emitted": bool(row.get("finding_emitted")),
        "unresolved_reason": row.get("unresolved_reason") or unresolved_reason_for_row(row),
        "classification": row.get("classification"),
        "schedule_status": row.get("schedule_status"),
    }


def _is_legitimate_exclusion(row: Dict[str, Any]) -> bool:
    """discovery_missing is a coverage gap — never a legitimate exclusion."""
    status = str(row.get("schedule_status") or "")
    reason = str(row.get("failure_or_exclusion_reason") or "")
    if status == "discovery_missing":
        return False
    if status in ("mode_excluded", "dependency_unavailable", "unsupported"):
        return True
    if status == "no_executable_adapter":
        return True  # maps to unsupported surface
    if reason.startswith("mode_excluded") or reason.startswith("dependency_unavailable"):
        return True
    if reason in ("unsupported", "explicitly_non_applicable", "non_applicable_surface"):
        return True
    return False


def _inventory_identity_key(row: Dict[str, Any]) -> str:
    """Stable inventory identity — one path counts once across candidate variants."""
    path = str(row.get("path") or "").rstrip("/") or "/"
    return path


def _aggregate_inventory_rows(
    lifecycle: Sequence[Dict[str, Any]],
    inventory_identities: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Collapse candidate rows into inventory identities (path-level, count-once)."""
    by_path: Dict[str, Dict[str, Any]] = {}
    if inventory_identities:
        for ident in inventory_identities:
            path = str(ident.get("path") or "").rstrip("/") or "/"
            by_path[path] = {
                "path": path,
                "fixture_id": ident.get("fixture_id") or f"inv:{path}",
                "family": ident.get("family") or "",
                "classification": ident.get("classification") or "vulnerable",
                "must_not_confirm": bool(ident.get("must_not_confirm")),
                "support_classification": "supported_active",
                "schedule_status": "discovery_missing",
                "terminal_result_state": "",
                "lifecycle_outcome": OUTCOME_NONTERMINAL,
                "probe_sent": False,
                "control_sent": False,
                "capability_maturity_after": MATURITY_EXECUTABLE_UNVALIDATED,
                "deps_available_for_live_recall": True,
                "failure_or_exclusion_reason": "planned_but_not_executed_in_scan",
                "candidate_row_count": 0,
                "inventory_identity": path,
            }

    rank = {
        OUTCOME_TERMINAL_CONFIRMED: 4,
        OUTCOME_TERMINAL_NEGATIVE: 3,
        OUTCOME_TERMINAL_INCONCLUSIVE: 2,
        OUTCOME_NONTERMINAL: 1,
    }
    for raw in lifecycle:
        if raw.get("support_classification") and raw.get("support_classification") != "supported_active":
            continue
        path = _inventory_identity_key(raw)
        if inventory_identities is not None and path not in by_path:
            # Candidate outside ground-truth inventory — candidate metrics only.
            continue
        cur = by_path.get(path)
        if cur is None:
            cur = {
                "path": path,
                "fixture_id": raw.get("fixture_id") or f"inv:{path}",
                "family": raw.get("family") or "",
                "classification": raw.get("classification") or "vulnerable",
                "must_not_confirm": bool(raw.get("must_not_confirm")),
                "support_classification": "supported_active",
                "schedule_status": raw.get("schedule_status") or "",
                "terminal_result_state": raw.get("terminal_result_state") or "",
                "lifecycle_outcome": raw.get("lifecycle_outcome") or OUTCOME_NONTERMINAL,
                "probe_sent": bool(raw.get("probe_sent")),
                "control_sent": bool(raw.get("control_sent")),
                "capability_maturity_after": raw.get("capability_maturity_after")
                or MATURITY_EXECUTABLE_UNVALIDATED,
                "deps_available_for_live_recall": raw.get("deps_available_for_live_recall", True),
                "failure_or_exclusion_reason": raw.get("failure_or_exclusion_reason") or "",
                "candidate_row_count": 0,
                "inventory_identity": path,
            }
            by_path[path] = cur
        cur["candidate_row_count"] = int(cur.get("candidate_row_count") or 0) + 1
        # Prefer control classification if any candidate is a control
        if raw.get("must_not_confirm") or raw.get("classification") == "control":
            cur["must_not_confirm"] = True
            cur["classification"] = "control"
        # Prefer attempted over discovery_missing
        rs = str(raw.get("schedule_status") or "")
        cs = str(cur.get("schedule_status") or "")
        if rs == "attempted" or (rs and cs in ("", "discovery_missing") and rs != "discovery_missing"):
            cur["schedule_status"] = rs
        if raw.get("probe_sent"):
            cur["probe_sent"] = True
        if raw.get("control_sent"):
            cur["control_sent"] = True
        # Strongest terminal outcome / proof wins within the identity
        out = str(raw.get("lifecycle_outcome") or classify_lifecycle_outcome(raw))
        if rank.get(out, 0) > rank.get(str(cur.get("lifecycle_outcome") or ""), 0):
            cur["lifecycle_outcome"] = out
            cur["terminal_result_state"] = raw.get("terminal_result_state") or cur.get(
                "terminal_result_state"
            )
        if raw.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED:
            cur["capability_maturity_after"] = MATURITY_LIVE_VALIDATED
        if raw.get("family") and not cur.get("family"):
            cur["family"] = raw.get("family")
        # Clear discovery gap reason once executed
        if cur.get("schedule_status") == "attempted" and cur.get("probe_sent"):
            if str(cur.get("failure_or_exclusion_reason") or "") == "planned_but_not_executed_in_scan":
                cur["failure_or_exclusion_reason"] = ""
    return list(by_path.values())


def _metric_block_from_rows(
    applicable: Sequence[Dict[str, Any]],
    *,
    mode: str,
    catalog_supported: int = 0,
    universe: str = "candidate",
) -> Dict[str, Any]:
    """Shared coverage/FP/recall math for candidate or inventory rows."""
    # Planned: all applicable identities/rows considered
    planned = list(applicable)
    scheduled = [
        r
        for r in planned
        if r.get("schedule_status")
        not in ("", "discovery_missing", "no_executable_adapter")
    ]
    mode_excluded = [r for r in planned if r.get("schedule_status") == "mode_excluded"]
    legitimate_exclusions = [r for r in planned if _is_legitimate_exclusion(r)]
    discovery_gaps = [
        r
        for r in planned
        if r.get("schedule_status") == "discovery_missing" or (
            not r.get("probe_sent")
            and r.get("schedule_status") not in (
                "mode_excluded",
                "dependency_unavailable",
                "unsupported",
                "no_executable_adapter",
            )
            and not _is_legitimate_exclusion(r)
            and r.get("schedule_status") != "attempted"
        )
    ]
    # Tighten discovery_gaps to explicit discovery_missing / not-executed without exclusion
    discovery_gaps = [
        r
        for r in planned
        if (
            r.get("schedule_status") == "discovery_missing"
            or (
                r.get("schedule_status") != "attempted"
                and not _is_legitimate_exclusion(r)
                and not bool(r.get("probe_sent"))
            )
        )
    ]
    applicable_executable = [
        r for r in planned if r.get("schedule_status") != "mode_excluded"
    ]
    attempted = [r for r in applicable_executable if r.get("schedule_status") == "attempted"]
    # not-executed cannot count in execution coverage
    executed = [r for r in attempted if bool(r.get("probe_sent")) or r.get("schedule_status") == "attempted"]

    completed = [
        r for r in attempted if r.get("lifecycle_outcome") in LIFECYCLE_COMPLETE_OUTCOMES
    ]
    nonterminal_attempted = [
        r for r in attempted if r.get("lifecycle_outcome") == OUTCOME_NONTERMINAL
    ]
    terminal_confirmed = [
        r for r in attempted if r.get("lifecycle_outcome") == OUTCOME_TERMINAL_CONFIRMED
    ]
    terminal_negative = [
        r for r in attempted if r.get("lifecycle_outcome") == OUTCOME_TERMINAL_NEGATIVE
    ]
    terminal_inconclusive = [
        r for r in attempted if r.get("lifecycle_outcome") == OUTCOME_TERMINAL_INCONCLUSIVE
    ]

    confirm_eligible = [
        r
        for r in applicable_executable
        if r.get("classification") == "vulnerable"
        and not r.get("must_not_confirm")
        and r.get("deps_available_for_live_recall", True)
        and r.get("schedule_status")
        not in (
            "no_executable_adapter",
            "dependency_unavailable",
            "discovery_missing",
        )
    ]
    live_num_rows = [
        r
        for r in confirm_eligible
        if r.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED
        and is_actively_confirmed(str(r.get("terminal_result_state") or ""))
        and r.get("probe_sent")
        and r.get("lifecycle_outcome") == OUTCOME_TERMINAL_CONFIRMED
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
        or r.get("lifecycle_outcome") == OUTCOME_TERMINAL_CONFIRMED
    ]

    vul_attempted = [
        r
        for r in attempted
        if r.get("classification") != "control" and not r.get("must_not_confirm")
    ]
    ctrl_attempted = list(controls)

    def _count(rows: Sequence[Dict[str, Any]], outcome: str) -> int:
        return sum(1 for r in rows if r.get("lifecycle_outcome") == outcome)

    reconciliation = {
        "terminal_confirmed_vulnerable": _count(vul_attempted, OUTCOME_TERMINAL_CONFIRMED),
        "terminal_negative_vulnerable": _count(vul_attempted, OUTCOME_TERMINAL_NEGATIVE),
        "terminal_inconclusive_vulnerable": _count(vul_attempted, OUTCOME_TERMINAL_INCONCLUSIVE),
        "nonterminal_vulnerable": _count(vul_attempted, OUTCOME_NONTERMINAL)
        + sum(
            1
            for r in planned
            if r.get("classification") != "control"
            and not r.get("must_not_confirm")
            and r.get("schedule_status") != "attempted"
            and not _is_legitimate_exclusion(r)
        ),
        "terminal_confirmed_controls": _count(ctrl_attempted, OUTCOME_TERMINAL_CONFIRMED),
        "terminal_negative_controls": _count(ctrl_attempted, OUTCOME_TERMINAL_NEGATIVE),
        "terminal_inconclusive_controls": _count(ctrl_attempted, OUTCOME_TERMINAL_INCONCLUSIVE),
        "nonterminal_controls": _count(ctrl_attempted, OUTCOME_NONTERMINAL)
        + sum(
            1
            for r in planned
            if (r.get("classification") == "control" or r.get("must_not_confirm"))
            and r.get("schedule_status") != "attempted"
            and not _is_legitimate_exclusion(r)
        ),
        "legitimate_explicit_exclusions": len(legitimate_exclusions),
        "true_discovery_gaps": len(
            [
                r
                for r in discovery_gaps
                if not _is_legitimate_exclusion(r)
            ]
        ),
    }
    # Avoid double-counting discovery gaps already in nonterminal buckets:
    # nonterminal_* above already includes not-attempted non-excluded rows.
    recon_sum = (
        reconciliation["terminal_confirmed_vulnerable"]
        + reconciliation["terminal_negative_vulnerable"]
        + reconciliation["terminal_inconclusive_vulnerable"]
        + reconciliation["nonterminal_vulnerable"]
        + reconciliation["terminal_confirmed_controls"]
        + reconciliation["terminal_negative_controls"]
        + reconciliation["terminal_inconclusive_controls"]
        + reconciliation["nonterminal_controls"]
        + reconciliation["legitimate_explicit_exclusions"]
    )
    # true_discovery_gaps are the not-attempted non-excluded already inside nonterminal_*;
    # expose the count separately but do not add again to the =N check.
    reconciliation["sum_excluding_gap_double_count"] = recon_sum
    reconciliation["equals_universe"] = recon_sum == len(planned)
    reconciliation["universe_size"] = len(planned)

    planning_den = catalog_supported or len(planned)
    return {
        "universe": universe,
        "mode": mode,
        "universe_size": len(planned),
        "planning_coverage": {
            "numerator": len(planned),
            "denominator": planning_den,
            "rate": _rate(len(planned), planning_den),
            "note": f"{universe} rows represented / ground-truth or planned denominator",
        },
        "scheduling_coverage": {
            "numerator": len(scheduled),
            "denominator": len(planned),
            "rate": _rate(len(scheduled), len(planned)),
            "note": (
                "scheduled (not discovery_missing) / planned. "
                "planned≠scheduled; discovery_missing cannot be scheduled=true"
            ),
            "mode_excluded_count": len(mode_excluded),
        },
        "execution_coverage": {
            "numerator": len(attempted),
            "denominator": len(
                [r for r in applicable_executable if r.get("schedule_status") != "discovery_missing"]
            ),
            "rate": _rate(
                len(attempted),
                len(
                    [
                        r
                        for r in applicable_executable
                        if r.get("schedule_status") != "discovery_missing"
                    ]
                ),
            ),
            "note": (
                "attempted / applicable non-discovery_missing. "
                "scheduled≠attempted; not-executed excluded from execution coverage"
            ),
            "mode_excluded_removed": [
                {"path": r.get("path"), "reason": r.get("failure_or_exclusion_reason")}
                for r in mode_excluded
            ],
        },
        "lifecycle_completion": {
            "numerator": len(completed),
            "denominator": len(attempted),
            "rate": _rate(len(completed), len(attempted)) if attempted else None,
            "note": "terminal outcomes / attempted (attempted≠terminal)",
            "by_class": {
                OUTCOME_TERMINAL_CONFIRMED: len(terminal_confirmed),
                OUTCOME_TERMINAL_NEGATIVE: len(terminal_negative),
                OUTCOME_TERMINAL_INCONCLUSIVE: len(terminal_inconclusive),
                OUTCOME_NONTERMINAL: len(nonterminal_attempted),
            },
        },
        "terminal_confirmation_rate": {
            "numerator": len(
                [
                    r
                    for r in terminal_confirmed
                    if r.get("classification") == "vulnerable" and not r.get("must_not_confirm")
                ]
            ),
            "denominator": len(confirm_eligible),
            "rate": _rate(
                len(
                    [
                        r
                        for r in terminal_confirmed
                        if r.get("classification") == "vulnerable" and not r.get("must_not_confirm")
                    ]
                ),
                len(confirm_eligible),
            ),
            "note": "terminal_confirmed vulnerable / confirm-eligible (reflected≠confirmed)",
        },
        "live_recall": {
            "numerator": len(live_num_rows),
            "denominator": len(confirm_eligible),
            "rate": _rate(len(live_num_rows), len(confirm_eligible)),
            "note": "live_validated confirmed vulnerable / confirm-eligible",
        },
        "negative_control_fp_rate": {
            "numerator": len(fp_rows),
            "denominator": len(controls),
            "rate": _rate(len(fp_rows), len(controls)) if controls else 0.0,
            "fp_rows": [
                {"path": r.get("path"), "result_state": r.get("terminal_result_state")}
                for r in fp_rows
            ],
            "note": "controls incorrectly reaching terminal_confirmed / controls executed",
        },
        "missing_not_executed_count": len(discovery_gaps),
        "legitimate_exclusions": [
            {
                "path": r.get("path"),
                "schedule_status": r.get("schedule_status"),
                "reason": r.get("failure_or_exclusion_reason"),
            }
            for r in legitimate_exclusions
        ],
        "discovery_gaps": [
            {
                "path": r.get("path"),
                "schedule_status": r.get("schedule_status"),
                "reason": r.get("failure_or_exclusion_reason") or "discovery_missing",
                "legitimate_exclusion": False,
            }
            for r in discovery_gaps
        ],
        "reconciliation": reconciliation,
        "attempted_count": len(attempted),
        "outcome_class_counts_attempted": {
            OUTCOME_TERMINAL_CONFIRMED: len(terminal_confirmed),
            OUTCOME_TERMINAL_NEGATIVE: len(terminal_negative),
            OUTCOME_TERMINAL_INCONCLUSIVE: len(terminal_inconclusive),
            OUTCOME_NONTERMINAL: len(nonterminal_attempted),
        },
    }


def compute_published_metrics(
    lifecycle: Sequence[Dict[str, Any]],
    *,
    mode: str,
    catalog_support_counts: Optional[Dict[str, int]] = None,
    legacy_subset_recall: Optional[Dict[str, Any]] = None,
    inventory_identities: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate candidate-level and inventory-level Phase-1 metrics.

    Candidate universe: dynamic production rows (may be 58+).
    Inventory universe: ground-truth supported-active identities (e.g. 39 for
    Horizon Lab) — each identity aggregates multiple candidate rows but counts once.
    """
    rows = annotate_lifecycle_outcomes(lifecycle)
    catalog = catalog_support_counts or {}
    catalog_supported = int(catalog.get("supported_active") or 0)

    applicable = [
        r
        for r in rows
        if r.get("support_classification") == "supported_active"
        and r.get("capability_maturity_before")
        in (MATURITY_EXECUTABLE_UNVALIDATED, MATURITY_LIVE_VALIDATED, "")
    ]
    if not applicable:
        applicable = [r for r in rows if r.get("support_classification") == "supported_active"]

    candidate_metrics = _metric_block_from_rows(
        applicable,
        mode=mode,
        catalog_supported=0,  # candidate denom = candidate count
        universe="candidate",
    )
    # Alias candidate fields to the names requested in the release gate.
    candidate_metrics["candidate_planning_coverage"] = candidate_metrics["planning_coverage"]
    candidate_metrics["candidate_scheduling_coverage"] = candidate_metrics["scheduling_coverage"]
    candidate_metrics["candidate_execution_coverage"] = candidate_metrics["execution_coverage"]
    candidate_metrics["candidate_lifecycle_completion"] = candidate_metrics["lifecycle_completion"]
    candidate_metrics["candidate_terminal_confirmation_rate"] = candidate_metrics[
        "terminal_confirmation_rate"
    ]
    candidate_metrics["candidate_negative_control_fp_rate"] = candidate_metrics[
        "negative_control_fp_rate"
    ]

    inv_rows = _aggregate_inventory_rows(applicable, inventory_identities=inventory_identities)
    inv_den = (
        len(inventory_identities)
        if inventory_identities is not None
        else (catalog_supported or len(inv_rows))
    )
    inventory_metrics = _metric_block_from_rows(
        inv_rows,
        mode=mode,
        catalog_supported=inv_den,
        universe="inventory",
    )
    inventory_metrics["inventory_visibility"] = {
        "numerator": len(inv_rows),
        "denominator": inv_den,
        "rate": _rate(len(inv_rows), inv_den),
        "note": "represented inventory identities / ground-truth supported-active (e.g. 39)",
    }
    inventory_metrics["inventory_execution_coverage"] = inventory_metrics["execution_coverage"]
    inventory_metrics["inventory_terminal_completion"] = inventory_metrics["lifecycle_completion"]
    inventory_metrics["inventory_live_recall"] = inventory_metrics["live_recall"]
    inventory_metrics["inventory_negative_control_fp_rate"] = inventory_metrics[
        "negative_control_fp_rate"
    ]
    inventory_metrics["inventory_missing_not_executed_count"] = inventory_metrics[
        "missing_not_executed_count"
    ]

    # Backward-compatible top-level keys — prefer candidate for dynamic ops,
    # but never claim inventory_size == candidate_size.
    scheduling_coverage = dict(candidate_metrics["scheduling_coverage"])
    applicable_execution_coverage = dict(candidate_metrics["execution_coverage"])
    lifecycle_completion_coverage = dict(candidate_metrics["lifecycle_completion"])
    terminal_confirmation_rate = dict(candidate_metrics["terminal_confirmation_rate"])
    negative_control_fp_rate = dict(candidate_metrics["negative_control_fp_rate"])

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
            "control_executed": bool(r.get("control_sent")),
            "replay_executed": bool(r.get("replay_attempted")),
            "lifecycle_outcome": r.get("lifecycle_outcome"),
            "why_terminal_confirmation": (
                f"state={r.get('terminal_result_state')} in CONFIRMED_ACTIVE_STATES; "
                f"proof={proof_type_for_state(str(r.get('terminal_result_state') or ''))}"
            ),
        }
        for r in applicable
        if r.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED
        and r.get("classification") == "vulnerable"
        and not r.get("must_not_confirm")
        and r.get("lifecycle_outcome") == OUTCOME_TERMINAL_CONFIRMED
    ]

    reconciliation = [build_reconciliation_entry(r) for r in applicable]
    # Mark discovery_missing rows as gaps, never legitimate exclusions
    for e, r in zip(reconciliation, applicable):
        if r.get("schedule_status") == "discovery_missing":
            e["legitimate_exclusion"] = False
            e["discovery_gap"] = True
        else:
            e["legitimate_exclusion"] = _is_legitimate_exclusion(r)
            e["discovery_gap"] = bool(
                r.get("schedule_status") == "discovery_missing"
                or (
                    not r.get("probe_sent")
                    and r.get("schedule_status") != "attempted"
                    and not _is_legitimate_exclusion(r)
                )
            )

    inv_recon = [build_reconciliation_entry(r) for r in inv_rows]
    for e, r in zip(inv_recon, inv_rows):
        e["inventory_identity"] = r.get("inventory_identity") or r.get("path")
        e["candidate_row_count"] = r.get("candidate_row_count")
        if r.get("schedule_status") == "discovery_missing":
            e["legitimate_exclusion"] = False
            e["discovery_gap"] = True
        else:
            e["legitimate_exclusion"] = _is_legitimate_exclusion(r)
            e["discovery_gap"] = e.get("discovery_gap", False)

    return {
        "mode": mode,
        "candidate_metrics": candidate_metrics,
        "inventory_metrics": inventory_metrics,
        "metric_universes": {
            "candidate_count": len(applicable),
            "inventory_count": len(inv_rows),
            "inventory_denominator": inv_den,
            "note": (
                "Never use candidate_count and inventory_count interchangeably. "
                "Candidate rows are dynamic; inventory identities are ground-truth."
            ),
        },
        "scheduling_coverage": scheduling_coverage,
        "applicable_execution_coverage": applicable_execution_coverage,
        "catalog_scheduling_execution_visibility": {
            "numerator": candidate_metrics["attempted_count"],
            "denominator": len(applicable),
            "rate": _rate(candidate_metrics["attempted_count"], len(applicable)),
            "note": (
                "attempted / all supported-active candidate rows including gaps "
                "(visibility only; not inventory execution coverage)"
            ),
        },
        "execution_coverage": applicable_execution_coverage,
        "lifecycle_completion_coverage": lifecycle_completion_coverage,
        "verification_coverage": {
            **lifecycle_completion_coverage,
            "replaced_by": "lifecycle_completion_coverage",
            "note": (
                "DEPRECATED alias of lifecycle_completion_coverage. "
                "Former definition (probe_sent + non-empty result_state) removed "
                "because it treated nonterminal states as verification."
            ),
        },
        "terminal_confirmation_rate": terminal_confirmation_rate,
        "evidence_backed_live_recall": {
            **inventory_metrics["live_recall"],
            "live_validated_entries": live_entries,
            "note": (
                "Prefer inventory_metrics.inventory_live_recall for ground-truth recall. "
                + str(inventory_metrics["live_recall"].get("note") or "")
            ),
        },
        "negative_control_fp_rate": negative_control_fp_rate,
        "nonterminal_rate": {
            "numerator": candidate_metrics["outcome_class_counts_attempted"].get(
                OUTCOME_NONTERMINAL, 0
            ),
            "denominator": candidate_metrics["attempted_count"],
            "rate": _rate(
                candidate_metrics["outcome_class_counts_attempted"].get(OUTCOME_NONTERMINAL, 0),
                candidate_metrics["attempted_count"],
            )
            if candidate_metrics["attempted_count"]
            else None,
            "note": "attempted candidates still ending in nonterminal / attempted",
            "rows": [
                {
                    "path": r.get("path"),
                    "family": r.get("family"),
                    "raw_result_state": r.get("terminal_result_state"),
                    "reason": r.get("unresolved_reason") or unresolved_reason_for_row(r),
                }
                for r in applicable
                if r.get("schedule_status") == "attempted"
                and r.get("lifecycle_outcome") == OUTCOME_NONTERMINAL
            ],
        },
        "dependency_coverage_gaps": [
            {
                "path": r.get("path"),
                "family": r.get("family"),
                "reason": r.get("failure_or_exclusion_reason") or r.get("schedule_status"),
            }
            for r in applicable
            if r.get("schedule_status") == "dependency_unavailable"
            or str(r.get("failure_or_exclusion_reason") or "").startswith("dependency_unavailable")
        ],
        "legacy_acceptance_subset_recall": legacy_subset_recall,
        "post_run_maturity_counts_plan_rows": {
            MATURITY_CONTRACT_ONLY: 0,
            MATURITY_REGISTERED_ADAPTER: 0,
            MATURITY_EXECUTABLE_UNVALIDATED: 0,
            MATURITY_LIVE_VALIDATED: 0,
        },
        "live_validated_count": len(live_entries),
        "attempted_count": candidate_metrics["attempted_count"],
        "outcome_class_counts_attempted": candidate_metrics["outcome_class_counts_attempted"],
        "reconciliation": reconciliation,
        "inventory_reconciliation": inv_recon,
        "reconciliation_totals": {
            "supported_active_candidates": len(reconciliation),
            "supported_active_inventory": len(inv_recon),
            "live_validated": len(live_entries),
            "vulnerable_without_terminal_proof": sum(
                1
                for e in reconciliation
                if e.get("classification") == "vulnerable" and not e.get("live_validated")
            ),
            "controls": sum(1 for e in reconciliation if e.get("classification") == "control"),
            "explained_remainder": (
                f"candidates={len(reconciliation)}; inventory={len(inv_recon)}; "
                f"do not equate these universes"
            ),
        },
        "unattempted": [
            {
                "path": r.get("path"),
                "family": r.get("family"),
                "schedule_status": r.get("schedule_status"),
                "reason": r.get("failure_or_exclusion_reason"),
                "legitimate_exclusion": _is_legitimate_exclusion(r),
                "discovery_gap": r.get("schedule_status") == "discovery_missing",
            }
            for r in applicable
            if r.get("schedule_status") != "attempted"
        ],
        "catalog_support_counts": catalog,
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
