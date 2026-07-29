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


def compute_published_metrics(
    lifecycle: Sequence[Dict[str, Any]],
    *,
    mode: str,
    catalog_support_counts: Optional[Dict[str, int]] = None,
    legacy_subset_recall: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generate all published metrics from completed lifecycle rows."""
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
    # If before was blank, still count supported_active plan rows
    if not applicable:
        applicable = [r for r in rows if r.get("support_classification") == "supported_active"]

    # Catalog scheduling: all supported-active entries considered for the mode
    # (including mode_excluded, so exclusions remain visible against the catalog).
    catalog_considered = list(applicable)
    if catalog_supported and catalog_supported > len(catalog_considered):
        # Prefer explicit catalog count when inventory says more fixtures exist
        # than were planned (should not happen for Phase-1 supported_active).
        pass
    scheduled_into_plan = [
        r
        for r in catalog_considered
        if r.get("schedule_status")
        not in ("", "discovery_missing", "no_executable_adapter")
    ]
    # "Entered into the execution plan" includes attempted + mode_excluded + dep gaps
    entered_plan = [
        r
        for r in catalog_considered
        if r.get("schedule_status")
        in (
            "attempted",
            "mode_excluded",
            "dependency_unavailable",
            "breaker_paused",
            "transport_failed",
            "verification_failed",
        )
        or bool(r.get("schedule_status"))
    ]

    mode_excluded = [r for r in applicable if r.get("schedule_status") == "mode_excluded"]
    # Applicable execution denominator: exclude explicit mode_excluded only.
    applicable_executable = [
        r for r in applicable if r.get("schedule_status") != "mode_excluded"
    ]
    attempted = [r for r in applicable_executable if r.get("schedule_status") == "attempted"]
    unattempted = [r for r in applicable if r.get("schedule_status") != "attempted"]

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

    # Eligible for active terminal confirmation: vulnerable, not mode-excluded,
    # deps available, executable adapter present.
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
        )
    ]

    # Live recall denominator: vulnerable, executable, deps available, not mode-excluded
    live_denom_rows = list(confirm_eligible)
    live_num_rows = [
        r
        for r in live_denom_rows
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
            "control_executed": bool(r.get("control_sent")),
            "replay_executed": bool(r.get("replay_attempted")),
            "lifecycle_outcome": r.get("lifecycle_outcome"),
            "why_terminal_confirmation": (
                f"state={r.get('terminal_result_state')} in CONFIRMED_ACTIVE_STATES; "
                f"proof={proof_type_for_state(str(r.get('terminal_result_state') or ''))}"
            ),
        }
        for r in rows
        if r.get("capability_maturity_after") == MATURITY_LIVE_VALIDATED
        and r.get("classification") == "vulnerable"
        and not r.get("must_not_confirm")
        and r.get("lifecycle_outcome") == OUTCOME_TERMINAL_CONFIRMED
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

    reconciliation = [build_reconciliation_entry(r) for r in applicable]
    vulnerable_without_terminal_proof = [
        e
        for e in reconciliation
        if e.get("classification") == "vulnerable"
        and not e.get("live_validated")
    ]
    control_entries = [e for e in reconciliation if e.get("classification") == "control"]

    sched_num = len(entered_plan)
    sched_den = catalog_supported or len(catalog_considered)
    applicable_exec_num = len(attempted)
    applicable_exec_den = len(applicable_executable)
    lifecycle_num = len(completed)
    lifecycle_den = len(attempted)
    confirm_num = len(
        [
            r
            for r in terminal_confirmed
            if r.get("classification") == "vulnerable" and not r.get("must_not_confirm")
        ]
    )
    confirm_den = len(confirm_eligible)
    nonterm_num = len(nonterminal_attempted)
    nonterm_den = len(attempted)

    # Catalog scheduling coverage keeps mode exclusions visible against all
    # supported-active entries (e.g. Safe 36 attempted of 39 catalog → scheduling
    # may still show 39/39 entered, while applicable execution is 36/36).
    scheduling_coverage = {
        "numerator": sched_num,
        "denominator": sched_den,
        "rate": _rate(sched_num, sched_den),
        "note": (
            "candidates entered into the execution plan / "
            "catalog supported-active candidates considered for the mode"
        ),
        "mode_excluded_count": len(mode_excluded),
    }
    applicable_execution_coverage = {
        "numerator": applicable_exec_num,
        "denominator": applicable_exec_den,
        "rate": _rate(applicable_exec_num, applicable_exec_den),
        "note": (
            "applicable candidates for which execution was attempted / "
            "applicable executable candidates (mode_excluded removed from denominator)"
        ),
        "mode_excluded_removed": [
            {"path": r.get("path"), "reason": r.get("failure_or_exclusion_reason")}
            for r in mode_excluded
        ],
    }
    # Backward-compatible alias: old "execution_coverage" was catalog-style 36/39.
    # Publish both; keep catalog_scheduling_execution_visibility separate.
    catalog_scheduling_execution_visibility = {
        "numerator": len(attempted),
        "denominator": len(applicable),
        "rate": _rate(len(attempted), len(applicable)),
        "note": (
            "attempted / all supported-active plan rows including mode_excluded "
            "(visibility only; not applicable execution coverage)"
        ),
    }
    lifecycle_completion_coverage = {
        "numerator": lifecycle_num,
        "denominator": lifecycle_den,
        "rate": _rate(lifecycle_num, lifecycle_den) if attempted else None,
        "note": (
            "candidates ending in terminal_confirmed, terminal_negative, or "
            "terminal_inconclusive / attempted candidates"
        ),
        "by_class": {
            OUTCOME_TERMINAL_CONFIRMED: len(terminal_confirmed),
            OUTCOME_TERMINAL_NEGATIVE: len(terminal_negative),
            OUTCOME_TERMINAL_INCONCLUSIVE: len(terminal_inconclusive),
            OUTCOME_NONTERMINAL: len(nonterminal_attempted),
        },
    }
    terminal_confirmation_rate = {
        "numerator": confirm_num,
        "denominator": confirm_den,
        "rate": _rate(confirm_num, confirm_den),
        "note": (
            "terminal_confirmed candidates / "
            "candidates eligible for active terminal confirmation"
        ),
    }
    nonterminal_rate = {
        "numerator": nonterm_num,
        "denominator": nonterm_den,
        "rate": _rate(nonterm_num, nonterm_den) if attempted else None,
        "note": (
            "attempted candidates still ending in nonterminal states / "
            "attempted candidates"
        ),
        "rows": [
            {
                "path": r.get("path"),
                "family": r.get("family"),
                "raw_result_state": r.get("terminal_result_state"),
                "reason": r.get("unresolved_reason") or unresolved_reason_for_row(r),
            }
            for r in nonterminal_attempted
        ],
    }

    return {
        "mode": mode,
        "scheduling_coverage": scheduling_coverage,
        "applicable_execution_coverage": applicable_execution_coverage,
        "catalog_scheduling_execution_visibility": catalog_scheduling_execution_visibility,
        # Replaced: old execution_coverage mixed mode_excluded into the denominator.
        "execution_coverage": applicable_execution_coverage,
        "lifecycle_completion_coverage": lifecycle_completion_coverage,
        # Replaced: old verification_coverage counted probe_sent + non-empty state.
        # Must never again report 39/39 while candidates remain at probe_sent.
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
            "numerator": len(live_num_rows),
            "denominator": len(live_denom_rows),
            "rate": _rate(len(live_num_rows), len(live_denom_rows)),
            "note": (
                "vulnerable candidates with exact terminal confirmation / "
                "in-scope vulnerable candidates whose verifier is executable "
                "and whose required dependencies were available"
            ),
            "live_validated_entries": live_entries,
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
        "nonterminal_rate": nonterminal_rate,
        "dependency_coverage_gaps": dep_gaps,
        "legacy_acceptance_subset_recall": legacy_subset_recall,
        "post_run_maturity_counts_plan_rows": mat_after,
        "live_validated_count": len(live_entries),
        "attempted_count": len(attempted),
        "outcome_class_counts_attempted": {
            OUTCOME_TERMINAL_CONFIRMED: len(terminal_confirmed),
            OUTCOME_TERMINAL_NEGATIVE: len(terminal_negative),
            OUTCOME_TERMINAL_INCONCLUSIVE: len(terminal_inconclusive),
            OUTCOME_NONTERMINAL: len(nonterminal_attempted),
        },
        "reconciliation": reconciliation,
        "reconciliation_totals": {
            "supported_active": len(reconciliation),
            "live_validated": len(live_entries),
            "vulnerable_without_terminal_proof": len(vulnerable_without_terminal_proof),
            "controls": len(control_entries),
            "explained_remainder": (
                f"{len(live_entries)} live-validated + "
                f"{len(vulnerable_without_terminal_proof)} vulnerable without terminal proof + "
                f"{len(control_entries)} controls = {len(reconciliation)}"
            ),
        },
        "unattempted": [
            {
                "path": r.get("path"),
                "family": r.get("family"),
                "schedule_status": r.get("schedule_status"),
                "reason": r.get("failure_or_exclusion_reason"),
            }
            for r in unattempted
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
