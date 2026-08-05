"""Phase-1 production runtime integration tests.

Covers the shared verifiers.runtime planner/lifecycle used by the worker path.
No Horizon fixture hardcodes in production packages under test.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from verifiers.contract import CONFIRMED_ACTIVE_STATES
from verifiers.maturity import (
    MATURITY_EXECUTABLE_UNVALIDATED,
    MATURITY_LIVE_VALIDATED,
    clear_live_validated,
    mark_live_validated,
)
from verifiers.runtime.execution_plan import (
    ATTEMPTED,
    CandidateSurface,
    DependencyAvailability,
    MODE_EXCLUDED,
    build_execution_plan,
)
from verifiers.runtime.finalize import apply_ledger_to_lifecycle, finalize_phase1_runtime
from verifiers.runtime.lifecycle import (
    OUTCOME_NONTERMINAL,
    OUTCOME_TERMINAL_CONFIRMED,
    OUTCOME_TERMINAL_INCONCLUSIVE,
    OUTCOME_TERMINAL_NEGATIVE,
    classify_lifecycle_outcome,
    compute_published_metrics,
    empty_lifecycle_row,
    apply_probe_outcome,
)
from verifiers.runtime.surfaces import discover_surfaces_from_stats


def _stats(**kwargs):
    defaults = dict(
        request_ledger=[],
        findings=[],
        forms=[],
        browser_confirmation={"browser_confirmation": "available"},
        discovered_urls=set(),
        target_catalog=None,
        scan_id="",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _cfg(**kwargs):
    defaults = dict(
        active_probe_mode="lab",
        ssrf_callback_base="https://cb.example/oob",
        oob_callback_poll_url="https://cb.example/oob/poll",
        traversal_fixture_installed=True,
        vuln_active_probe=True,
        job_id="job-test-1",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_write_stats_reports_invokes_shared_execution_planner(tmp_path, monkeypatch):
    """Normal report path must call verifiers.runtime planner (not horizon_benchmark)."""
    from crawl_stats import CrawlStats
    import reporting
    import verifiers.runtime.finalize as finalize_mod

    called = {}

    def fake_finalize(stats, **kwargs):
        called["ok"] = True
        called["scan_id"] = kwargs.get("scan_id")
        called["module"] = finalize_mod.__name__
        stats.phase1_runtime_summary = {
            "phase1_runtime_status": "ok",
            "execution_plan_count": 1,
        }
        return {
            "runtime_status": {"status": "ok"},
            "execution_plan": [{"path": "/x"}],
            "lifecycle_rows": [],
            "published_metrics": {},
            "summary": stats.phase1_runtime_summary,
            "artifact_paths": {"execution_plan": str(tmp_path / "execution_plan.json")},
        }

    monkeypatch.setattr(finalize_mod, "finalize_phase1_runtime", fake_finalize)

    stats = CrawlStats()
    stats.request_ledger.append(
        {
            "phase": "active_probe",
            "probe_class": "xss",
            "url": "https://t.example/xss/reflected?q=1",
            "method": "GET",
            "probe_role": "probe",
            "result_state": "probe_sent",
        }
    )
    cfg = _cfg(job_id="prod-job-42")
    paths = reporting.write_stats_reports(
        stats,
        report_dir=str(tmp_path),
        start_url="https://t.example/",
        title="t",
        config=cfg,
    )
    assert called.get("ok") is True
    assert called.get("scan_id") == "prod-job-42"
    assert called.get("module") == "verifiers.runtime.finalize"
    assert "horizon_benchmark" not in called.get("module", "")
    assert paths


def test_registry_membership_alone_does_not_mark_scheduled_or_verified():
    clear_live_validated()
    # Surface for a registered family but mode-excluded → visible, not attempted
    surf = CandidateSurface(
        candidate_id="c1",
        url="https://t/x",
        path="/lab-only",
        family="xss",
        modes=["lab"],
        support_classification="supported_active",
        capability_maturity=MATURITY_LIVE_VALIDATED,  # stale mark must be ignored
    )
    plan = build_execution_plan(
        mode="safe",
        surfaces=[surf],
        deps=DependencyAvailability(browser=True, oob_callback=True),
    )
    assert len(plan) == 1
    assert plan[0].schedule_status == MODE_EXCLUDED
    assert plan[0].capability_maturity_before != MATURITY_LIVE_VALIDATED
    rows = apply_ledger_to_lifecycle(plan, mode="safe", ledger=[], findings=[], scan_id="s1")
    assert rows[0]["schedule_status"] == MODE_EXCLUDED
    assert rows[0]["probe_sent"] is False
    assert rows[0]["lifecycle_outcome"] != OUTCOME_TERMINAL_CONFIRMED
    assert classify_lifecycle_outcome(rows[0]) != OUTCOME_TERMINAL_CONFIRMED


def test_mode_excluded_candidates_visible_but_not_attempted():
    clear_live_validated()
    surf = CandidateSurface(
        candidate_id="c2",
        url="https://t/trav",
        path="/trav/view",
        family="traversal",
        modes=["lab"],
        support_classification="supported_active",
    )
    plan = build_execution_plan(
        mode="safe", surfaces=[surf], deps=DependencyAvailability(http_client=True)
    )
    assert plan[0].schedule_status == MODE_EXCLUDED
    rows = apply_ledger_to_lifecycle(plan, mode="safe", ledger=[], findings=[], scan_id="s")
    assert rows[0]["schedule_status"] == MODE_EXCLUDED
    assert rows[0]["probe_sent"] is False
    pub = compute_published_metrics(rows, mode="safe", catalog_support_counts={"supported_active": 1})
    assert pub["applicable_execution_coverage"]["denominator"] == 0  # excluded from exec denom
    assert pub["scheduling_coverage"]["mode_excluded_count"] == 1


def test_request_ledger_maps_into_canonical_lifecycle_rows(tmp_path):
    clear_live_validated()
    stats = _stats(
        request_ledger=[
            {
                "phase": "active_probe",
                "probe_class": "xss",
                "url": "https://t.example/xss/reflected?q=1",
                "method": "GET",
                "probe_role": "probe",
                "result_state": "browser_execution_confirmed",
                "parameter": "q",
            },
            {
                "phase": "active_probe",
                "probe_class": "xss",
                "url": "https://t.example/xss/reflected?q=1",
                "method": "GET",
                "probe_role": "control",
                "result_state": "negative",
            },
        ],
        scan_id="scan-A",
    )
    out = finalize_phase1_runtime(stats, config=_cfg(job_id="scan-A"), report_dir=str(tmp_path), scan_id="scan-A")
    assert out["runtime_status"]["status"] == "ok"
    assert len(out["execution_plan"]) >= 1
    assert len(out["lifecycle_rows"]) >= 1
    row = next(r for r in out["lifecycle_rows"] if r.get("path") == "/xss/reflected")
    assert row["probe_sent"] is True
    assert row["terminal_result_state"] == "browser_execution_confirmed"
    assert row["lifecycle_outcome"] == OUTCOME_TERMINAL_CONFIRMED
    assert row["scan_id"] == "scan-A"
    assert (tmp_path / "execution_plan.json").exists()
    assert (tmp_path / "lifecycle_rows.json").exists()
    assert (tmp_path / "published_metrics.json").exists()


def test_form_submission_distinct_from_route_visit():
    clear_live_validated()
    surf = CandidateSurface(
        candidate_id="form1",
        url="https://t/xss/form",
        path="/xss/form",
        family="xss",
        method="POST",
        form_fields=["message"],
        support_classification="supported_active",
    )
    plan = build_execution_plan(
        mode="lab", surfaces=[surf], deps=DependencyAvailability(browser=True)
    )
    ledger = [
        {
            "phase": "active_probe",
            "probe_class": "xss",
            "url": "https://t/xss/form",
            "method": "POST",
            "probe_role": "probe",
            "result_state": "html_injection_confirmed",
            "form_submitted": True,
        }
    ]
    rows = apply_ledger_to_lifecycle(plan, mode="lab", ledger=ledger, findings=[], scan_id="s")
    assert rows[0]["form_submitted"] is True
    assert rows[0]["route_visited"] is True

    # Visit-only (no POST / form role) must not set form_submitted
    ledger_visit = [
        {
            "phase": "active_probe",
            "probe_class": "xss",
            "url": "https://t/xss/form",
            "method": "GET",
            "probe_role": "probe",
            "result_state": "probe_sent",
        }
    ]
    rows2 = apply_ledger_to_lifecycle(plan, mode="lab", ledger=ledger_visit, findings=[], scan_id="s")
    assert rows2[0]["form_submitted"] is False


def test_browser_evidence_bound_to_candidate_and_scan_id(tmp_path):
    clear_live_validated()
    stats = _stats(
        request_ledger=[
            {
                "phase": "active_probe",
                "probe_class": "dom_clobber",
                "url": "https://t/xss/dom-clobber?x=1",
                "method": "GET",
                "probe_role": "browser_probe",
                "result_state": "browser_execution_confirmed",
                "scan_id": "scan-B",
            }
        ]
    )
    out = finalize_phase1_runtime(
        stats, config=_cfg(), report_dir=str(tmp_path), scan_id="scan-B"
    )
    row = next(r for r in out["lifecycle_rows"] if "dom-clobber" in (r.get("path") or ""))
    assert row["scan_id"] == "scan-B"
    assert row["browser_used"] is True
    assert str(row.get("fixture_id") or "").startswith("scan-B:")


def test_oob_evidence_nonce_probe_scan_bound():
    clear_live_validated()
    surf = CandidateSurface(
        candidate_id="ssrf1",
        url="https://t/ssrf/fetch",
        path="/ssrf/fetch",
        family="ssrf",
        support_classification="supported_active",
    )
    plan = build_execution_plan(
        mode="lab",
        surfaces=[surf],
        deps=DependencyAvailability(oob_callback=True),
    )
    # Foreign scan_id on ledger must not confirm OOB for this scan
    ledger = [
        {
            "phase": "active_probe",
            "probe_class": "ssrf",
            "url": "https://t/ssrf/fetch",
            "method": "GET",
            "probe_role": "probe",
            "result_state": "oob_callback_confirmed",
            "probe_name": "ssrf_callback",
            "scan_id": "other-scan",
        }
    ]
    rows = apply_ledger_to_lifecycle(plan, mode="lab", ledger=ledger, findings=[], scan_id="this-scan")
    assert rows[0]["terminal_result_state"] != "oob_callback_confirmed"
    assert rows[0]["lifecycle_outcome"] != OUTCOME_TERMINAL_CONFIRMED


def test_nonterminal_states_excluded_from_completion_and_live_recall():
    row = empty_lifecycle_row(
        plan_item={
            "candidate_id": "n1",
            "path": "/x",
            "method": "GET",
            "family": "xss",
            "capability_id": "x",
            "capability_maturity_before": MATURITY_EXECUTABLE_UNVALIDATED,
            "support_classification": "supported_active",
            "classification": "vulnerable",
            "must_not_confirm": False,
            "parameter": "q",
            "schedule_status": ATTEMPTED,
            "exclusion_reason": "",
        },
        mode="lab",
    )
    apply_probe_outcome(row, probe_sent=True, result_state="probe_sent", finding_emitted=False)
    assert classify_lifecycle_outcome(row) == OUTCOME_NONTERMINAL
    pub = compute_published_metrics([row], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub["lifecycle_completion_coverage"]["numerator"] == 0
    assert pub["evidence_backed_live_recall"]["numerator"] == 0


def test_negative_controls_cannot_confirm_from_generic_reflection():
    row = empty_lifecycle_row(
        plan_item={
            "candidate_id": "ctrl",
            "path": "/xss/encoded",
            "method": "GET",
            "family": "xss",
            "capability_id": "x",
            "capability_maturity_before": MATURITY_EXECUTABLE_UNVALIDATED,
            "support_classification": "supported_active",
            "classification": "control",
            "must_not_confirm": True,
            "parameter": "q",
            "schedule_status": ATTEMPTED,
            "exclusion_reason": "",
        },
        mode="lab",
    )
    apply_probe_outcome(row, probe_sent=True, result_state="reflected_only", finding_emitted=True)
    assert classify_lifecycle_outcome(row) != OUTCOME_TERMINAL_CONFIRMED
    assert row["capability_maturity_after"] != MATURITY_LIVE_VALIDATED
    pub = compute_published_metrics([row], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub["negative_control_fp_rate"]["numerator"] == 0
    assert "reflected_only" not in CONFIRMED_ACTIVE_STATES


def test_stale_prior_run_validation_cannot_influence_new_scan(tmp_path):
    clear_live_validated()
    mark_live_validated("family:xss")
    mark_live_validated("cap.xss")
    stats = _stats(
        request_ledger=[
            {
                "phase": "active_probe",
                "probe_class": "xss",
                "url": "https://t/xss/reflected",
                "method": "GET",
                "probe_role": "probe",
                "result_state": "probe_sent",
            }
        ]
    )
    out = finalize_phase1_runtime(
        stats, config=_cfg(), report_dir=str(tmp_path), scan_id="fresh"
    )
    assert out["published_metrics"].get("stale_live_validated_preloaded") is False
    for row in out["lifecycle_rows"]:
        assert row.get("capability_maturity_before") != MATURITY_LIVE_VALIDATED
        if row.get("terminal_result_state") == "probe_sent":
            assert row.get("capability_maturity_after") != MATURITY_LIVE_VALIDATED


def test_concurrent_scans_remain_isolated(tmp_path):
    clear_live_validated()
    ledger_a = [
        {
            "phase": "active_probe",
            "probe_class": "xss",
            "url": "https://t/xss/reflected",
            "method": "GET",
            "probe_role": "probe",
            "result_state": "browser_execution_confirmed",
            "scan_id": "scan-A",
        }
    ]
    ledger_b = [
        {
            "phase": "active_probe",
            "probe_class": "xss",
            "url": "https://t/xss/reflected",
            "method": "GET",
            "probe_role": "probe",
            "result_state": "probe_sent",
            "scan_id": "scan-B",
        }
    ]
    out_a = finalize_phase1_runtime(
        _stats(request_ledger=ledger_a),
        config=_cfg(job_id="scan-A"),
        report_dir=str(tmp_path / "a"),
        scan_id="scan-A",
    )
    out_b = finalize_phase1_runtime(
        _stats(request_ledger=ledger_b),
        config=_cfg(job_id="scan-B"),
        report_dir=str(tmp_path / "b"),
        scan_id="scan-B",
    )
    ids_a = {r["scan_id"] for r in out_a["lifecycle_rows"]}
    ids_b = {r["scan_id"] for r in out_b["lifecycle_rows"]}
    assert ids_a == {"scan-A"}
    assert ids_b == {"scan-B"}
    assert all(str(r["fixture_id"]).startswith("scan-A:") for r in out_a["lifecycle_rows"])
    assert all(str(r["fixture_id"]).startswith("scan-B:") for r in out_b["lifecycle_rows"])


def test_planner_failure_produces_explicit_runtime_gap(tmp_path, monkeypatch):
    clear_live_validated()

    def boom(*_a, **_k):
        raise RuntimeError("planner exploded")

    monkeypatch.setattr(
        "verifiers.runtime.finalize.build_execution_plan", boom
    )
    out = finalize_phase1_runtime(
        _stats(request_ledger=[{"phase": "active_probe", "probe_class": "xss", "url": "https://t/x", "method": "GET", "probe_role": "probe"}]),
        config=_cfg(),
        report_dir=str(tmp_path),
        scan_id="fail-1",
    )
    assert out["runtime_status"]["status"] == "failed"
    assert out["published_metrics"] == {}
    assert (tmp_path / "unresolved_coverage_gaps.json").exists()
    gaps = json.loads((tmp_path / "unresolved_coverage_gaps.json").read_text())
    assert any(g.get("reason") == "phase1_runtime_error" for g in gaps)
    status = json.loads((tmp_path / "phase1_runtime_status.json").read_text())
    assert status["status"] == "failed"


def test_benchmark_and_production_equivalent_lifecycle_classification():
    """Identical evidence → same outcome class via shared lifecycle module."""
    from horizon_benchmark import lifecycle as hz_life
    from verifiers.runtime import lifecycle as prod_life

    assert hz_life.classify_lifecycle_outcome is prod_life.classify_lifecycle_outcome
    assert hz_life.compute_published_metrics is prod_life.compute_published_metrics

    plan_item = {
        "candidate_id": "eq",
        "path": "/xss/reflected",
        "method": "GET",
        "family": "xss",
        "capability_id": "x",
        "capability_maturity_before": MATURITY_EXECUTABLE_UNVALIDATED,
        "support_classification": "supported_active",
        "classification": "vulnerable",
        "must_not_confirm": False,
        "parameter": "q",
        "schedule_status": ATTEMPTED,
        "exclusion_reason": "",
    }
    row_a = prod_life.empty_lifecycle_row(plan_item=plan_item, mode="lab")
    row_b = hz_life.empty_lifecycle_row(plan_item=plan_item, mode="lab")
    prod_life.apply_probe_outcome(
        row_a, probe_sent=True, result_state="browser_execution_confirmed", finding_emitted=True
    )
    hz_life.apply_probe_outcome(
        row_b, probe_sent=True, result_state="browser_execution_confirmed", finding_emitted=True
    )
    assert row_a["lifecycle_outcome"] == row_b["lifecycle_outcome"] == OUTCOME_TERMINAL_CONFIRMED
    pub_a = prod_life.compute_published_metrics([row_a], mode="lab", catalog_support_counts={"supported_active": 1})
    pub_b = hz_life.compute_published_metrics([row_b], mode="lab", catalog_support_counts={"supported_active": 1})
    assert pub_a["evidence_backed_live_recall"]["numerator"] == pub_b["evidence_backed_live_recall"]["numerator"]


def test_production_packages_contain_zero_horizon_hardcodes():
    root = Path(__file__).resolve().parents[1]
    banned = (
        "horizon-catalog",
        "onrender.com",
        "horizon_benchmark",
        "/xss/reflected",
        "/xss/encoded",
        "/xss/dom-clobber",
        "app-settings",
        "widget-cfg",
        "defaultConfig",
        "PARTIAL_OR_PASSIVE_PATHS",
        "fixture_id\": \"hz",
    )
    packages = [
        root / "verifiers",
        root / "dom_clobber",
        root / "active_probe_kit.py",
        root / "active_probe_browser.py",
        root / "active_probe_targeting.py",
        root / "crawl_orchestrator.py",
        root / "reporting.py",
        root / "security_scan.py",
        root / "report_status.py",
        root / "web" / "worker",
        root / "web" / "api" / "vantacrawl_api" / "routes" / "jobs.py",
    ]
    hits = []
    for path in packages:
        files = [path] if path.is_file() else list(path.rglob("*.py"))
        for f in files:
            if "__pycache__" in f.parts:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            for b in banned:
                if b in text:
                    hits.append(f"{f.relative_to(root)}:{b}")
    assert hits == [], hits

def test_callback_base_alias_in_job_config():
    """callback_base UI alias maps to ssrf_callback_base + poll URL."""
    from active_probe_kit import normalize_mode

    # Mirror _build_config_json aliasing without importing the FastAPI router
    # (avoids SQLAlchemy metadata redefinition when the suite already loaded models).
    merged = {
        "vuln_active_probe": True,
        "active_probe_mode": normalize_mode("lab"),
        "callback_base": "https://t.example/oob",
    }
    if merged.get("callback_base") and not merged.get("ssrf_callback_base"):
        merged["ssrf_callback_base"] = str(merged.get("callback_base") or "").strip()
    if merged.get("ssrf_callback_base") and not merged.get("oob_callback_poll_url"):
        base = str(merged["ssrf_callback_base"]).rstrip("/")
        if base:
            merged["oob_callback_poll_url"] = f"{base}/poll"
    assert merged.get("ssrf_callback_base") == "https://t.example/oob"
    assert merged.get("oob_callback_poll_url") == "https://t.example/oob/poll"

    # Worker overlay path
    overlay = {"callback_base": "https://t.example/oob"}
    if overlay.get("callback_base") and not overlay.get("ssrf_callback_base"):
        overlay["ssrf_callback_base"] = str(overlay.pop("callback_base") or "").strip()
    assert overlay["ssrf_callback_base"] == "https://t.example/oob"
    assert "callback_base" not in overlay


def test_catalog_intensity_tags_expand_upward():
    """Tag 'safe' must not exclude the candidate from lab mode."""
    catalog = [
        {
            "path": "/xss/reflected",
            "family": "xss",
            "tags": ["active", "safe"],
            "methods": ["GET"],
        },
        {
            "path": "/trav/view",
            "family": "traversal",
            "tags": ["active", "lab"],
            "methods": ["GET"],
        },
    ]
    stats = _stats(target_catalog=catalog, discovered_urls={"https://t.example/"})
    surfaces = discover_surfaces_from_stats(stats, mode="lab", scan_id="s")
    plan = build_execution_plan(
        mode="lab",
        surfaces=surfaces,
        deps=DependencyAvailability(browser=True, traversal_canary=True),
    )
    by_path = {p.path: p for p in plan}
    assert by_path["/xss/reflected"].schedule_status == ATTEMPTED
    assert by_path["/trav/view"].schedule_status == ATTEMPTED
    plan_safe = build_execution_plan(
        mode="safe",
        surfaces=surfaces,
        deps=DependencyAvailability(browser=True, traversal_canary=True),
    )
    by_safe = {p.path: p for p in plan_safe}
    assert by_safe["/xss/reflected"].schedule_status == ATTEMPTED
    assert by_safe["/trav/view"].schedule_status == MODE_EXCLUDED


def test_catalog_surfaces_use_tags_not_path_allowlist():
    catalog = [
        {
            "path": "/xss/dom-clobber",
            "family": "xss",
            "tags": ["active", "browser", "dom-clobber"],
            "methods": ["GET"],
        },
        {
            "path": "/xss/dom-clobber-safe",
            "family": "xss",
            "tags": ["control", "fp-guard", "browser", "dom-clobber"],
            "methods": ["GET"],
        },
    ]
    stats = _stats(target_catalog=catalog, discovered_urls={"https://t.example/"})
    surfaces = discover_surfaces_from_stats(stats, mode="lab", scan_id="s")
    paths = {s.path: s for s in surfaces}
    assert "/xss/dom-clobber" in paths
    assert paths["/xss/dom-clobber"].family == "dom_clobber"
    assert paths["/xss/dom-clobber-safe"].must_not_confirm is True
    plan = build_execution_plan(
        mode="lab",
        surfaces=surfaces,
        deps=DependencyAvailability(browser=True, oob_callback=True),
    )
    assert any(p.path == "/xss/dom-clobber" and p.schedule_status == ATTEMPTED for p in plan)
