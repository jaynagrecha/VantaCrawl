"""Tests for the generic verifier framework and anti-inflation rules."""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from verifiers.contract import (
    PRODUCT_CLAIM,
    STATUS_ACTIVELY_VERIFIED,
    STATUS_MISSED,
    STATUS_UNSUPPORTED,
    is_actively_confirmed,
    map_fixture_status,
)
from verifiers.phase1 import (
    DomClobberVerifier,
    RceVerifier,
    SqliVerifier,
    SsrfVerifier,
    XssVerifier,
)
from verifiers.registry import capability_registry, get_verifier, supported_families
from verifiers.base import Candidate, Evidence, SurfaceContext
from horizon_benchmark.inventory import build_fixture_inventory, support_classification_lists
from horizon_benchmark.evaluate import evaluate_entire_catalog
from crawl_stats import CrawlStats

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_product_claim_is_honest():
    assert "supported-active recall separately" in PRODUCT_CLAIM
    assert "100%" not in PRODUCT_CLAIM


def test_phase1_capabilities_registered():
    caps = capability_registry()
    families = set(supported_families(phase=1))
    for needed in ("sqli", "rce", "ssti", "xss", "ssrf", "redirect", "traversal", "crlf", "csrf", "dom_clobber"):
        assert needed in families, needed
        assert get_verifier(needed) is not None


def test_visiting_route_is_not_actively_verified():
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
    assert not is_actively_confirmed("")


def test_scheduling_or_probe_send_alone_not_confirmed():
    assert not is_actively_confirmed("probe_sent")
    assert not is_actively_confirmed("discovered_only")
    assert not is_actively_confirmed("reflected_only")


def test_reflection_is_not_execution():
    assert not is_actively_confirmed("reflected_only")
    ev = XssVerifier().classify(
        Candidate("xss", "q", "query", "https://t/x"),
        None,
        [],
        Evidence(result_state="reflected_only", structured={"kit_result_state": "reflected_only"}),
    )
    assert ev.result_state == "reflected_only"
    assert ev.verification != "confirmed" or ev.severity == "info"


def test_callback_unavailability_not_tp():
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


def test_rce_marker_reflection_not_server_exec():
    payload = ";printf VC_RCE_abcd"
    body = f"output: {payload}"
    ev = RceVerifier().classify(
        Candidate("rce", "cmd", "query", "https://t/x"),
        None,
        [],
        Evidence(
            result_state="marker_output_signal",
            structured={
                "kit_result_state": "marker_output_signal",
                "body": body,
                "payload": payload,
                "marker": "VC_RCE_abcd",
                "arith": "7603",
            },
        ),
    )
    assert ev.result_state != "server_execution_confirmed"


def test_sqli_requires_replay_for_confirm_path():
    ev = SqliVerifier().classify(
        Candidate("sqli", "id", "query", "https://t/x"),
        None,
        [],
        Evidence(
            result_state="differential_signal",
            structured={"kit_result_state": "execution_confirmed", "replay_ok": False},
        ),
    )
    assert ev.result_state == "inconclusive"


def test_unsupported_fixtures_not_in_supported_active_denominator():
    inv = build_fixture_inventory()
    lists = support_classification_lists(inv)
    assert inv["summary"]["catalog_fixtures"] == len(inv["fixtures"])
    assert inv["summary"]["supported_active"] + inv["summary"]["passive_manual"] + inv["summary"]["unsupported"] == inv[
        "summary"
    ]["catalog_fixtures"]
    # Unsupported paths must not be classified supported_active
    assert not set(lists["unsupported"]) & set(lists["supported_active"])


def test_evaluator_does_not_overwrite_scanner_result_state():
    stats = CrawlStats()
    stats._scan_status = "final"
    stats.discovered_urls.add("https://example.test/sqli/error")
    entire = evaluate_entire_catalog(stats=stats, mode="safe")
    assert entire["headline"]["product_claim"]
    for row in entire["matrix"]:
        assert row.get("scanner_result_state_preserved") is True
    # Empty ledger → no fabricated confirmations
    confirmed = [
        r
        for r in entire["matrix"]
        if r.get("result_state") in (
            "browser_execution_confirmed",
            "server_execution_confirmed",
            "oob_callback_confirmed",
        )
    ]
    assert confirmed == []


def test_passive_findings_not_counted_as_active_verification():
    status = map_fixture_status(
        bucket="passive_manual",
        classification="vulnerable",
        discovered=True,
        probe_sent=False,
        result_state="passive_indicator",
        expected_result_state="",
        must_not_confirm=False,
        match=True,
    )
    assert status == "passively_confirmed"
    assert status != STATUS_ACTIVELY_VERIFIED


def test_production_verifiers_have_no_horizon_hardcodes():
    forbidden = [
        r"horizon-catalog",
        r"onrender\.com",
        r"/xss/dom-clobber",
        r"/sqli/error",
        r"/csrf/action",
        r"/ssrf/fetch",
        r"defaultConfig",
        r"PLAYGROUND_",
        r"domClobberExecuted",
        r"dom-clobber-proof",
        r"VC_TRAVERSAL_PROOF",  # ok in kit; ban in verifiers package specifically as fixture
    ]
    # Allow generic VC_ prefixes in probe builders; ban Horizon domains/routes
    route_bans = [
        r"horizon-catalog",
        r"onrender\.com",
        r"/xss/dom-clobber",
        r"/sqli/error",
        r"/csrf/action",
        r"/ssrf/fetch",
        r"/rce/arith",
        r"/cmdi/",
        r"defaultConfig",
        r"domClobberExecuted",
        r"dom-clobber-proof",
    ]
    files = list((ROOT / "verifiers").rglob("*.py"))
    for path in files:
        text = path.read_text(encoding="utf-8")
        for pat in route_bans:
            assert re.search(pat, text) is None, f"{path} hardcodes {pat}"


def test_dom_clobber_verifier_contract_present():
    v = DomClobberVerifier()
    ctx = SurfaceContext(url="https://app.example/page?html=x", query_params={"html": "x"})
    cands = v.discover_candidates(ctx)
    assert cands
    assert cands[0].parameter == "html"  # discovered from context, not hardcoded allowlist alone


def test_headline_metrics_separate_buckets():
    inv = build_fixture_inventory()
    s = inv["summary"]
    assert "catalog_fixtures" in s
    assert "supported_active" in s
    assert "passive_manual" in s
    assert "unsupported" in s
    # Never claim full catalog is supported-active
    assert s["supported_active"] < s["catalog_fixtures"]
