"""Anti-inflation tests for stacked-PR integrity audit (PART D)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from crawl_stats import CrawlStats
from horizon_benchmark.evaluate import evaluate_entire_catalog
from horizon_benchmark.inventory import build_fixture_inventory, support_classification_lists
from verifiers.base import Candidate, Evidence, SurfaceContext, VulnerabilityVerifier
from verifiers.contract import (
    PRODUCT_CLAIM,
    STATUS_ACTIVELY_VERIFIED,
    STATUS_MISSED,
    is_actively_confirmed,
    map_fixture_status,
)
from verifiers.maturity import (
    MATURITY_CONTRACT_ONLY,
    MATURITY_EXECUTABLE_UNVALIDATED,
    MATURITY_LIVE_VALIDATED,
    MATURITY_REGISTERED_ADAPTER,
    assess_capability_maturity,
    classify_support_from_maturity,
    clear_live_validated,
    mark_live_validated,
)
from verifiers.phase1 import DomClobberVerifier, SqliVerifier, SsrfVerifier
from verifiers.registry import register


class _ContractOnlyFamily(VulnerabilityVerifier):
    """Intentionally incomplete — contract surface only."""

    family = "audit_contract_only_family"
    capability_id = "audit_contract_only"
    phase = 99

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {}

    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        return []

    def build_probes(self, candidate: Candidate, mode: str) -> List:
        return []

    async def execute(self, candidate, probe, runtime):
        return None

    def collect_evidence(self, candidate, probe, response, runtime, *, baseline=None, controls=None):
        return Evidence(result_state="inconclusive")

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        return evidence


class _RegisteredStubVerifier(VulnerabilityVerifier):
    family = "audit_registered_stub"
    capability_id = "audit_registered_stub"
    phase = 99

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        return {"http_client": True}

    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        return [Candidate(self.family, "q", "query", context.url)]

    def build_probes(self, candidate: Candidate, mode: str) -> List:
        return []

    async def execute(self, candidate, probe, runtime):
        return None

    def collect_evidence(self, candidate, probe, response, runtime, *, baseline=None, controls=None):
        return Evidence(result_state="probe_sent")

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        evidence.result_state = "probe_sent"
        return evidence


def test_product_claim_mentions_maturity_not_full_phase1():
    assert "live-validation maturity" in PRODUCT_CLAIM or "live_validated" in PRODUCT_CLAIM
    assert "entire Phase-1" not in PRODUCT_CLAIM


def test_contract_only_family_not_supported_active():
    matured = classify_support_from_maturity(
        bucket="supported_required",
        family="audit_contract_only_family",
        path="/audit/contract-only",
    )
    assert matured["capability_maturity"] in (MATURITY_CONTRACT_ONLY, MATURITY_REGISTERED_ADAPTER)
    assert matured["support_classification"] != "supported_active"


def test_registered_verifier_without_executable_methods_not_supported_active():
    register(_RegisteredStubVerifier())
    mat = assess_capability_maturity("audit_registered_stub")
    assert mat["execute_is_stub"] is True
    # Not in FAMILY_IMPL → not executable via kit map
    assert mat["supported_active_eligible"] is False
    matured = classify_support_from_maturity(
        bucket="supported_required",
        family="audit_registered_stub",
        path="/audit/stub",
    )
    assert matured["support_classification"] != "supported_active"


def test_routed_probe_is_not_verified():
    status = map_fixture_status(
        bucket="supported_required",
        classification="vulnerable",
        discovered=True,
        probe_sent=False,
        result_state="",
        expected_result_state="server_execution_confirmed",
        must_not_confirm=False,
        match=False,
    )
    assert status == STATUS_MISSED
    assert status != STATUS_ACTIVELY_VERIFIED


def test_sent_probe_is_not_verified():
    assert not is_actively_confirmed("probe_sent")
    status = map_fixture_status(
        bucket="supported_required",
        classification="vulnerable",
        discovered=True,
        probe_sent=True,
        result_state="probe_sent",
        expected_result_state="server_execution_confirmed",
        must_not_confirm=False,
        match=False,
    )
    assert status != STATUS_ACTIVELY_VERIFIED


def test_benchmark_expected_state_cannot_change_scanner_evidence():
    stats = CrawlStats()
    stats._scan_status = "final"
    stats.discovered_urls.add("https://example.test/sqli/error")
    entire = evaluate_entire_catalog(stats=stats, mode="lab")
    for row in entire["matrix"]:
        assert row.get("scanner_result_state_preserved") is True
        # Evaluator must not invent confirmation from expected_result_state alone
        if not row.get("probe_sent") and not row.get("result_state"):
            assert row.get("result_state") in ("", None, "discovered_only", "negative", "inconclusive") or not is_actively_confirmed(
                row.get("result_state") or ""
            )


def test_route_visitation_cannot_produce_recall():
    stats = CrawlStats()
    stats._scan_status = "final"
    # Visit many routes without probes
    for path in ("/sqli/error", "/xss/reflected", "/ssrf/fetch", "/rce/arith"):
        stats.discovered_urls.add(f"https://example.test{path}")
    entire = evaluate_entire_catalog(stats=stats, mode="lab")
    tp = entire["headline"].get("supported_active_tp_recall") or {}
    # No actively confirmed findings → recall numerator must be 0
    assert int(tp.get("numerator") or 0) == 0
    live = entire["headline"].get("live_validated_tp_recall") or {}
    assert int(live.get("numerator") or 0) == 0


def test_evaluator_cannot_manufacture_baseline_control_replay_flags():
    stats = CrawlStats()
    stats._scan_status = "final"
    entire = evaluate_entire_catalog(stats=stats, mode="lab")
    for row in entire["matrix"]:
        # Flags must come from scanner ledger, not evaluator defaults claiming success
        for flag in ("baseline_captured", "control_captured", "replay_captured", "negative_control_passed"):
            if flag in row and row[flag] is True:
                # Only acceptable if scanner evidence exists for that fixture
                assert row.get("probe_sent") or row.get("result_state"), flag


def test_live_recall_excludes_non_live_maturity(monkeypatch):
    import verifiers.maturity as maturity

    monkeypatch.setattr(maturity, "_LIVE_VALIDATED", set())
    inv = build_fixture_inventory()
    # Without live marks, live_recall_denominator must be 0
    assert inv["summary"]["live_recall_denominator"] == 0
    for row in inv["fixtures"]:
        if row.get("capability_maturity") in (
            MATURITY_CONTRACT_ONLY,
            MATURITY_REGISTERED_ADAPTER,
            MATURITY_EXECUTABLE_UNVALIDATED,
        ):
            # Cannot contribute to published live recall
            assert row.get("capability_maturity") != MATURITY_LIVE_VALIDATED

    mark_live_validated("dom_clobber_source_to_sink")
    mark_live_validated("family:dom_clobber")
    inv2 = build_fixture_inventory()
    live_rows = [r for r in inv2["fixtures"] if r.get("capability_maturity") == MATURITY_LIVE_VALIDATED]
    assert live_rows
    assert all("dom-clobber" in (r.get("path") or "") or r.get("probe_family") == "dom_clobber" for r in live_rows)
    # Non-live maturity still excluded from live denominator
    assert inv2["summary"]["live_recall_denominator"] == len(live_rows)
    clear_live_validated()
    maturity.reload_live_validated()


def test_unsupported_and_passive_outside_active_recall_denominator():
    inv = build_fixture_inventory()
    lists = support_classification_lists(inv)
    active = set(lists["supported_active"])
    assert not (set(lists["unsupported"]) & active)
    assert not (set(lists["passive_manual"]) & active)
    # Catalog partition
    assert (
        inv["summary"]["supported_active"]
        + inv["summary"]["passive_manual"]
        + inv["summary"]["unsupported"]
        == inv["summary"]["catalog_fixtures"]
        == 158
    )


def test_negative_control_failure_prevents_confirmation():
    from verifiers.phase1 import CsrfVerifier

    ev = CsrfVerifier().classify(
        Candidate("csrf", "email", "form", "https://t/x", method="POST"),
        None,
        [],
        Evidence(
            result_state="state_change_confirmed",
            structured={
                "kit_result_state": "state_change_confirmed",
                "negative_control_changed": True,
            },
        ),
    )
    assert ev.result_state == "inconclusive"
    assert not is_actively_confirmed(ev.result_state)


def test_replay_failure_prevents_high_confidence_confirmation():
    ev = SqliVerifier().classify(
        Candidate("sqli", "id", "query", "https://t/x"),
        None,
        [],
        Evidence(
            result_state="execution_confirmed",
            structured={"kit_result_state": "execution_confirmed", "replay_ok": False},
        ),
    )
    assert ev.result_state == "inconclusive"
    assert not is_actively_confirmed(ev.result_state)


def test_callback_unavailability_cannot_count_as_ssrf_success():
    ev = SsrfVerifier().classify(
        Candidate("ssrf", "url", "query", "https://t/x"),
        None,
        [],
        Evidence(
            result_state="confirmation_unavailable",
            structured={"kit_result_state": "confirmation_unavailable", "oob_configured": False},
        ),
    )
    assert ev.result_state == "confirmation_unavailable"
    assert not is_actively_confirmed(ev.result_state)


def test_fixture_markers_cannot_confirm_production_findings():
    # Dom-clobber package must not treat Horizon fixture marker strings as proof
    from pathlib import Path
    import re

    text = Path("dom_clobber").joinpath("proof.py").read_text(encoding="utf-8")
    for banned in ("domClobberExecuted", "defaultConfig", "PLAYGROUND_", "horizon-catalog"):
        assert banned not in text
    # Marker key is nonce-derived
    assert "vcDc_" in text


def test_inventory_supported_active_not_inflated_by_registry_alone():
    """Previously 48 came from cap_id presence; maturity may demote incomplete rows."""
    inv = build_fixture_inventory()
    s = inv["summary"]
    assert s["catalog_fixtures"] == 158
    # Every supported_active row must be executable_* maturity
    for row in inv["fixtures"]:
        if row["support_classification"] == "supported_active":
            assert row["capability_maturity"] in (
                MATURITY_EXECUTABLE_UNVALIDATED,
                MATURITY_LIVE_VALIDATED,
            ), row["path"]
    # Partial XSS subtypes demoted
    by_path = {r["path"]: r for r in inv["fixtures"]}
    for p in ("/xss/angular", "/xss/postmessage", "/xss/stored"):
        if p in by_path:
            assert by_path[p]["support_classification"] != "supported_active"
    # CSRF incomplete replay → not supported_active
    csrf = [r for r in inv["fixtures"] if r["family"] == "csrf"]
    for r in csrf:
        assert r["support_classification"] != "supported_active" or r["capability_maturity"] == MATURITY_LIVE_VALIDATED


def test_dom_clobber_adapter_execute_stub_does_not_alone_grant_active():
    """Registry DomClobberVerifier.execute is a stub; eligibility comes from dom_clobber package map."""
    import textwrap
    import ast
    import inspect

    v = DomClobberVerifier()
    src = textwrap.dedent(inspect.getsource(v.execute))
    tree = ast.parse(src)
    fn_node = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    body = fn_node.body
    if body and isinstance(body[0], ast.Expr):
        body = body[1:]
    assert len(body) == 1 and isinstance(body[0], ast.Return)
    val = body[0].value
    assert val is None or (isinstance(val, ast.Constant) and val.value is None)
    mat = assess_capability_maturity("dom_clobber", path="/xss/dom-clobber")
    assert mat["implementation_module"] == "dom_clobber.verify"
    assert mat["executable_methods"] is True


# remove old helper if present — kept for import safety
def inspect_returns_none(fn) -> bool:
    import inspect
    import ast
    import textwrap

    src = textwrap.dedent(inspect.getsource(fn))
    tree = ast.parse(src)
    fn_node = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    body = fn_node.body
    if body and isinstance(body[0], ast.Expr):
        body = body[1:]
    return len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value is None
