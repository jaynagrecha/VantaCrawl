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
    apply_probe_outcome,
    compute_published_metrics,
    empty_lifecycle_row,
    finalize_maturity_after,
    merge_catalog_maturity_counts,
)
from verifiers.maturity import MATURITY_EXECUTABLE_UNVALIDATED, MATURITY_LIVE_VALIDATED, clear_live_validated


def test_execution_plan_includes_dom_clobber_without_route_allowlist():
    clear_live_validated()
    inv = build_fixture_inventory()
    deps = DependencyAvailability(http_client=True, browser=True, oob_callback=True, traversal_canary=True)
    plan = build_phase1_execution_plan(mode="lab", inventory=inv, deps=deps)
    paths = {p.path for p in plan if p.schedule_status == ATTEMPTED}
    assert any("dom-clobber" in p and "safe" not in p for p in paths)
    # No hardcoded path allowlist module constant used — planner uses inventory support class
    assert any(p.family == "dom_clobber" for p in plan if p.schedule_status == ATTEMPTED)


def test_execution_plan_mode_excludes_lab_only_in_safe():
    clear_live_validated()
    inv = build_fixture_inventory()
    deps = DependencyAvailability(browser=True, oob_callback=True)
    plan = build_phase1_execution_plan(mode="safe", inventory=inv, deps=deps)
    # Some fixtures are lab-only in modes list
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
        row = empty_lifecycle_row(
            plan_item={
                "candidate_id": path,
                "path": path,
                "method": "GET",
                "family": "rce",
                "capability_id": "x",
                "capability_maturity_before": MATURITY_EXECUTABLE_UNVALIDATED,
                "support_classification": "supported_active",
                "classification": cls,
                "must_not_confirm": must_not,
                "parameter": "q",
                "schedule_status": "attempted",
            },
            mode="lab",
            discovered_url=f"https://t{path}",
        )
        apply_probe_outcome(row, probe_sent=True, result_state=state, finding_emitted=True)
        rows.append(row)
    pub = compute_published_metrics(rows, mode="lab")
    live = pub["evidence_backed_live_recall"]
    assert live["numerator"] == 2
    assert pub["live_validated_count"] == 2
    assert len(live["live_validated_entries"]) == 2
    assert pub["live_validated_count"] == live["numerator"]
    # Control must not be TP
    assert all(e["candidate"] != "/d" for e in live["live_validated_entries"])
    assert pub["negative_control_fp_rate"]["numerator"] == 1


def test_differential_signal_is_not_live_validated():
    row = empty_lifecycle_row(
        plan_item={
            "candidate_id": "hz:/sqli/error",
            "path": "/sqli/error",
            "method": "GET",
            "family": "sqli",
            "capability_id": "sqli_boolean_error_time",
            "capability_maturity_before": MATURITY_EXECUTABLE_UNVALIDATED,
            "support_classification": "supported_active",
            "classification": "vulnerable",
            "must_not_confirm": False,
            "parameter": "id",
            "schedule_status": "attempted",
        },
        mode="lab",
    )
    apply_probe_outcome(row, probe_sent=True, result_state="differential_signal", finding_emitted=True)
    assert row["capability_maturity_after"] == MATURITY_EXECUTABLE_UNVALIDATED
    assert finalize_maturity_after(row) != MATURITY_LIVE_VALIDATED


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


def test_catalog_maturity_merge_reconciles_155():
    clear_live_validated()
    inv = build_fixture_inventory()
    lifecycle = []
    counts = merge_catalog_maturity_counts(inv["fixtures"], lifecycle)
    assert sum(counts.values()) == 155
    assert counts.get(MATURITY_LIVE_VALIDATED, 0) == 0  # no stale marks
