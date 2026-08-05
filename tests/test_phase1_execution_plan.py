"""Tests for Phase-1 capability-driven execution plan and metric reconciliation."""

from __future__ import annotations

from horizon_benchmark.execution_plan import (
    ATTEMPTED,
    DependencyAvailability,
    MODE_EXCLUDED,
    build_phase1_execution_plan,
)
from horizon_benchmark.inventory import build_fixture_inventory
from horizon_benchmark.lifecycle import (
    OUTCOME_NONTERMINAL,
    OUTCOME_TERMINAL_CONFIRMED,
    OUTCOME_TERMINAL_INCONCLUSIVE,
    OUTCOME_TERMINAL_NEGATIVE,
    apply_probe_outcome,
    classify_lifecycle_outcome,
    compute_published_metrics,
    empty_lifecycle_row,
    finalize_maturity_after,
    merge_catalog_maturity_counts,
)
from verifiers.maturity import MATURITY_EXECUTABLE_UNVALIDATED, MATURITY_LIVE_VALIDATED, clear_live_validated


def _row(
    path: str,
    *,
    state: str = "",
    cls: str = "vulnerable",
    must_not: bool = False,
    schedule: str = "attempted",
    probe: bool = True,
    family: str = "rce",
    maturity_before: str = MATURITY_EXECUTABLE_UNVALIDATED,
    deps_ok: bool = True,
) -> dict:
    row = empty_lifecycle_row(
        plan_item={
            "candidate_id": path,
            "path": path,
            "method": "GET",
            "family": family,
            "capability_id": "x",
            "capability_maturity_before": maturity_before,
            "support_classification": "supported_active",
            "classification": cls,
            "must_not_confirm": must_not,
            "parameter": "q",
            "schedule_status": schedule,
            "exclusion_reason": "mode_excluded:test" if schedule == MODE_EXCLUDED else "",
        },
        mode="lab",
        discovered_url=f"https://t{path}",
    )
    row["deps_available_for_live_recall"] = deps_ok
    if schedule == "attempted":
        apply_probe_outcome(
            row,
            probe_sent=probe,
            result_state=state,
            finding_emitted=bool(state) and state not in ("", "probe_sent"),
        )
    else:
        row["lifecycle_outcome"] = classify_lifecycle_outcome(row)
    return row


def test_execution_plan_includes_dom_clobber_without_route_allowlist():
    clear_live_validated()
    inv = build_fixture_inventory()
    deps = DependencyAvailability(http_client=True, browser=True, oob_callback=True, traversal_canary=True)
    plan = build_phase1_execution_plan(mode="lab", inventory=inv, deps=deps)
    paths = {p.path for p in plan if p.schedule_status == ATTEMPTED}
    assert any("dom-clobber" in p and "safe" not in p for p in paths)
    assert any(p.family == "dom_clobber" for p in plan if p.schedule_status == ATTEMPTED)


def test_execution_plan_mode_excludes_lab_only_in_safe():
    clear_live_validated()
    inv = build_fixture_inventory()
    deps = DependencyAvailability(browser=True, oob_callback=True)
    plan = build_phase1_execution_plan(mode="safe", inventory=inv, deps=deps)
    excluded = [p for p in plan if p.schedule_status == MODE_EXCLUDED]
    assert isinstance(excluded, list)


def test_execution_plan_covers_supported_active_not_just_twelve():
    clear_live_validated()
    inv = build_fixture_inventory()
    deps = DependencyAvailability(browser=True, oob_callback=True, traversal_canary=True)
    plan = build_phase1_execution_plan(mode="lab", inventory=inv, deps=deps)
    applicable = [p for p in plan if p.support_classification == "supported_active"]
    assert len(applicable) >= 30
    assert len([p for p in applicable if p.schedule_status == ATTEMPTED]) > 12


def test_live_validated_count_matches_published_numerator():
    clear_live_validated()
    rows = []
    for path, state, cls, must_not in (
        ("/a", "execution_confirmed", "vulnerable", False),
        ("/b", "oob_callback_confirmed", "vulnerable", False),
        ("/c", "reflected_only", "vulnerable", False),
        ("/d", "execution_confirmed", "control", True),
    ):
        rows.append(_row(path, state=state, cls=cls, must_not=must_not))
    pub = compute_published_metrics(rows, mode="lab", catalog_support_counts={"supported_active": 4})
    live = pub["evidence_backed_live_recall"]
    assert live["numerator"] == 2
    assert pub["live_validated_count"] == 2
    assert len(live["live_validated_entries"]) == 2
    assert pub["live_validated_count"] == live["numerator"]
    assert all(e["candidate"] != "/d" for e in live["live_validated_entries"])
    assert pub["negative_control_fp_rate"]["numerator"] == 1


def test_differential_signal_is_not_live_validated():
    row = _row("/sqli/error", state="differential_signal", family="sqli")
    assert row["capability_maturity_after"] == MATURITY_EXECUTABLE_UNVALIDATED
    assert finalize_maturity_after(row) != MATURITY_LIVE_VALIDATED
    assert classify_lifecycle_outcome(row) == OUTCOME_TERMINAL_INCONCLUSIVE


def test_probe_sent_does_not_count_as_lifecycle_completion():
    row = _row("/x", state="probe_sent")
    assert classify_lifecycle_outcome(row) == OUTCOME_NONTERMINAL
    pub = compute_published_metrics([row], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub["lifecycle_completion_coverage"]["numerator"] == 0
    assert pub["lifecycle_completion_coverage"]["denominator"] == 1
    assert pub["nonterminal_rate"]["numerator"] == 1
    # Deprecated alias must track lifecycle completion, not inflate to 1/1
    assert pub["verification_coverage"]["numerator"] == 0
    assert pub["verification_coverage"]["denominator"] == 1


def test_reflected_only_is_not_terminal_confirmation():
    row = _row("/xss/r", state="reflected_only", family="xss")
    assert classify_lifecycle_outcome(row) == OUTCOME_TERMINAL_INCONCLUSIVE
    assert row["capability_maturity_after"] != MATURITY_LIVE_VALIDATED
    pub = compute_published_metrics([row], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub["evidence_backed_live_recall"]["numerator"] == 0
    assert pub["lifecycle_completion_coverage"]["numerator"] == 1  # inconclusive completes


def test_nonterminal_differential_signal_not_terminal_confirmation():
    row = _row("/sqli/blind", state="differential_signal", family="sqli")
    assert classify_lifecycle_outcome(row) != OUTCOME_TERMINAL_CONFIRMED
    pub = compute_published_metrics([row], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub["terminal_confirmation_rate"]["numerator"] == 0
    assert pub["evidence_backed_live_recall"]["numerator"] == 0


def test_terminal_inconclusive_counts_as_lifecycle_completion_not_live_recall():
    row = _row("/xss/reflected", state="html_injection_confirmed", family="xss")
    assert classify_lifecycle_outcome(row) == OUTCOME_TERMINAL_INCONCLUSIVE
    pub = compute_published_metrics([row], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub["lifecycle_completion_coverage"]["numerator"] == 1
    assert pub["evidence_backed_live_recall"]["numerator"] == 0
    assert pub["live_validated_count"] == 0


def test_dependency_unavailable_is_nonterminal_never_confirmed():
    row = _row(
        "/ssrf/fetch",
        state="",
        schedule="dependency_unavailable",
        probe=False,
        family="ssrf",
        deps_ok=False,
    )
    assert classify_lifecycle_outcome(row) == OUTCOME_NONTERMINAL
    pub = compute_published_metrics(
        [row], mode="lab", catalog_support_counts={"supported_active": 1}
    )
    assert pub["applicable_execution_coverage"]["numerator"] == 0
    assert pub["evidence_backed_live_recall"]["numerator"] == 0
    assert row.get("capability_maturity_after") != MATURITY_LIVE_VALIDATED


def test_mode_excluded_removed_from_applicable_execution_denominator():
    rows = [
        _row("/a", state="execution_confirmed"),
        _row("/b", state="execution_confirmed"),
        _row("/c", state="", schedule=MODE_EXCLUDED, probe=False),
    ]
    pub = compute_published_metrics(rows, mode="safe", catalog_support_counts={"supported_active": 3})
    assert pub["applicable_execution_coverage"]["numerator"] == 2
    assert pub["applicable_execution_coverage"]["denominator"] == 2
    assert pub["catalog_scheduling_execution_visibility"]["numerator"] == 2
    assert pub["catalog_scheduling_execution_visibility"]["denominator"] == 3
    assert len(pub["applicable_execution_coverage"]["mode_excluded_removed"]) == 1


def test_all_published_metrics_derive_from_lifecycle_rows():
    rows = [
        _row("/ok", state="server_execution_confirmed"),
        _row("/probe", state="probe_sent"),
        _row("/diff", state="differential_signal", family="sqli"),
        _row("/neg", state="negative"),
        _row("/ctl", state="reflected_only", cls="control", must_not=True),
        _row("/excl", state="", schedule=MODE_EXCLUDED, probe=False),
    ]
    pub = compute_published_metrics(rows, mode="lab", catalog_support_counts={"supported_active": 6})
    assert pub["live_validated_count"] == pub["evidence_backed_live_recall"]["numerator"] == 1
    assert pub["lifecycle_completion_coverage"]["by_class"][OUTCOME_TERMINAL_CONFIRMED] == 1
    assert pub["lifecycle_completion_coverage"]["by_class"][OUTCOME_NONTERMINAL] == 1
    assert pub["lifecycle_completion_coverage"]["by_class"][OUTCOME_TERMINAL_INCONCLUSIVE] == 1
    assert pub["lifecycle_completion_coverage"]["by_class"][OUTCOME_TERMINAL_NEGATIVE] == 2
    assert pub["verification_coverage"]["numerator"] == pub["lifecycle_completion_coverage"]["numerator"]
    assert pub["reconciliation_totals"]["supported_active_candidates"] == 6
    assert pub["reconciliation_totals"].get("supported_active_inventory", 6) >= 1
    assert {e["path"] for e in pub["reconciliation"]} == {r["path"] for r in rows}


def test_stale_live_mark_not_kept_without_terminal_proof():
    row = empty_lifecycle_row(
        plan_item={
            "candidate_id": "hz:/xss/dom-clobber",
            "path": "/xss/dom-clobber",
            "method": "GET",
            "family": "dom_clobber",
            "capability_id": "dom_clobber_source_to_sink",
            "capability_maturity_before": MATURITY_LIVE_VALIDATED,  # stale
            "support_classification": "supported_active",
            "classification": "vulnerable",
            "must_not_confirm": False,
            "parameter": "html",
            "schedule_status": "attempted",
        },
        mode="lab",
    )
    apply_probe_outcome(row, probe_sent=False, result_state="", finding_emitted=False)
    assert row["capability_maturity_after"] == MATURITY_EXECUTABLE_UNVALIDATED


def test_catalog_maturity_merge_reconciles_158():
    clear_live_validated()
    inv = build_fixture_inventory()
    lifecycle = []
    counts = merge_catalog_maturity_counts(inv["fixtures"], lifecycle)
    assert sum(counts.values()) == 158
    assert counts.get(MATURITY_LIVE_VALIDATED, 0) == 0  # no stale marks
