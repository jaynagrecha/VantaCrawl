"""Unit tests for dynamic DOM-clobber discovery and verification contract."""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from dom_clobber.contract import (
    CONFIRMED_VULN_STATES,
    STATE_BROWSER_EXECUTION_CONFIRMED,
    STATE_CLOBBER_WITHOUT_SINK,
    STATE_CONTROLLED_REQUEST_CONFIRMED,
    STATE_HTML_INJECTION_CONFIRMED,
    STATE_NAMED_PROPERTY_CLOBBERED,
    STATE_NEGATIVE,
    STATE_REFLECTED_ONLY,
    STATE_SINK_CONTEXT_CANDIDATE,
    clamp_state_for_mode,
    is_confirmed_vuln,
)
from dom_clobber.discovery import (
    classify_marker_reflection,
    discover_candidates_from_html,
    inert_html_marker,
    new_marker,
    random_noncolliding_id,
)
from dom_clobber.payloads import build_clobber_payloads, build_negative_payloads
from dom_clobber.proof import DomClobberProofService
from dom_clobber.verify import decide_state
from dom_clobber.discovery import ClobberCandidate


ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_unknown_parameter_marker_classification_live_dom():
    mid, nonce = new_marker()
    marker = inert_html_marker(mid, nonce)
    # Simulate app reflecting arbitrary param name "markup" as live HTML
    body = f"<html><body><div>{marker}</div></body></html>"
    ctx = classify_marker_reflection(body, mid, nonce)
    assert ctx.classification == "live_dom"
    assert ctx.allows_element_creation is True


def test_encoded_marker_is_not_live_dom():
    mid, nonce = new_marker()
    body = f"<html><body>&lt;span id=&quot;{mid}&quot;&gt;</body></html>"
    ctx = classify_marker_reflection(body, mid, nonce)
    assert ctx.classification == "encoded"
    assert ctx.allows_element_creation is False


def test_unknown_clobber_property_discovered_from_script():
    html = """
    <html><body>
    <script>
      var cfg = window.totallyUnknownCfg || { href: '/safe' };
      var s = document.createElement('script');
      s.src = cfg.href;
      document.body.appendChild(s);
    </script>
    </body></html>
    """
    cands = discover_candidates_from_html(html)
    names = {c.root_name for c in cands}
    assert "totallyUnknownCfg" in names
    # Must not require defaultConfig
    assert any(c.score >= 80 for c in cands if c.root_name == "totallyUnknownCfg")


def test_random_noncolliding_ids_do_not_match_target():
    existing = {"defaultConfig", "appSettings"}
    rid = random_noncolliding_id(existing)
    assert rid not in existing
    assert not rid.startswith("default")


def test_clobber_without_sink_is_not_confirmed_vuln():
    state = decide_state(
        mode="lab",
        injection_class="live_dom",
        named_clobber=True,
        consumed=False,
        proof_in_sink=False,
        app_network_proof=False,
        execution_marker=False,
        csp_blocked=False,
        browser_available=True,
        proof_available=True,
        negative_cleared=True,
        replay_ok=True,
    )
    assert state == STATE_CLOBBER_WITHOUT_SINK
    assert not is_confirmed_vuln(state)


def test_sink_without_attacker_control_not_confirmed():
    state = decide_state(
        mode="lab",
        injection_class="live_dom",
        named_clobber=False,
        consumed=False,
        proof_in_sink=True,
        app_network_proof=True,
        execution_marker=True,
        csp_blocked=False,
        browser_available=True,
        proof_available=True,
        negative_cleared=True,
        replay_ok=True,
    )
    # Without named clobber, live HTML alone is not E-tier
    assert state == STATE_HTML_INJECTION_CONFIRMED
    assert not is_confirmed_vuln(state)


def test_scanner_generated_requests_cannot_self_confirm():
    svc = DomClobberProofService(callback_base="https://cb.example/oob", scan_id="s1")
    binding = svc.mint(
        endpoint="https://t/x",
        parameter="html",
        candidate_property="cfg",
        browser_session_id="bs1",
    )
    hit = svc.correlate_network_hit(
        nonce=binding.nonce,
        request_url=binding.proof_url,
        initiator="script",
        requester_fingerprint="scanner_http_client",
        browser_session_id="bs1",
    )
    assert hit is None


def test_callback_cannot_leak_across_browser_sessions():
    svc = DomClobberProofService(callback_base="https://cb.example/oob", scan_id="s1")
    binding = svc.mint(
        endpoint="https://t/x",
        parameter="html",
        candidate_property="cfg",
        browser_session_id="bs_session_a",
    )
    hit = svc.correlate_network_hit(
        nonce=binding.nonce,
        request_url=binding.proof_url,
        initiator="script",
        requester_fingerprint="browser_page",
        browser_session_id="bs_session_b",
    )
    assert hit is None


def test_negative_control_invalidates_confirmed_state():
    state = decide_state(
        mode="lab",
        injection_class="live_dom",
        named_clobber=True,
        consumed=True,
        proof_in_sink=True,
        app_network_proof=True,
        execution_marker=True,
        csp_blocked=False,
        browser_available=True,
        proof_available=True,
        negative_cleared=False,
        replay_ok=True,
    )
    assert state == STATE_SINK_CONTEXT_CANDIDATE
    assert not is_confirmed_vuln(state)


def test_csp_blocked_represented_accurately():
    state = decide_state(
        mode="lab",
        injection_class="live_dom",
        named_clobber=True,
        consumed=True,
        proof_in_sink=True,
        app_network_proof=False,
        execution_marker=False,
        csp_blocked=True,
        browser_available=True,
        proof_available=True,
        negative_cleared=True,
        replay_ok=True,
    )
    assert state == "blocked_by_csp"


def test_safe_mode_never_executes_proof_confirmation():
    raw = decide_state(
        mode="lab",
        injection_class="live_dom",
        named_clobber=True,
        consumed=True,
        proof_in_sink=True,
        app_network_proof=False,
        execution_marker=True,
        csp_blocked=False,
        browser_available=True,
        proof_available=True,
        negative_cleared=True,
        replay_ok=True,
    )
    assert raw == STATE_BROWSER_EXECUTION_CONFIRMED
    clamped = clamp_state_for_mode(raw, "safe")
    assert clamped == STATE_SINK_CONTEXT_CANDIDATE
    assert clamped not in CONFIRMED_VULN_STATES


def test_payloads_use_discovered_property_not_hardcoded():
    cand = ClobberCandidate(property_path="weirdProp99", root_name="weirdProp99", source="test", score=90)
    payloads = build_clobber_payloads(cand, proof_url="https://cb.example/n/proof.js")
    assert payloads
    assert all("weirdProp99" in p.html for p in payloads)
    assert all("defaultConfig" not in p.html for p in payloads)


def test_negative_payloads_include_required_variants():
    cand = ClobberCandidate(property_path="cfg", root_name="cfg", source="test", score=90)
    negs = build_negative_payloads(cand, proof_url="https://cb.example/n/proof.js")
    variants = {n.variant for n in negs}
    assert "baseline_empty" in variants
    assert "noncolliding_id" in variants
    assert "random_unused_property" in variants
    assert "clobber_without_url" in variants


def test_production_scanner_has_no_horizon_hardcodes():
    """Evidence: production scanner modules must not hardcode Horizon fixture specifics."""
    forbidden = [
        r"/xss/dom-clobber",
        r"defaultConfig",
        r"domClobberExecuted",
        r"dom-clobber-proof\.js",
        r"appSettings",
        r"widgetCfg",
        r"mediaTarget",
        r"horizon-catalog",
    ]
    scan_files = [
        ROOT / "dom_clobber" / "contract.py",
        ROOT / "dom_clobber" / "discovery.py",
        ROOT / "dom_clobber" / "payloads.py",
        ROOT / "dom_clobber" / "proof.py",
        ROOT / "dom_clobber" / "browser.py",
        ROOT / "dom_clobber" / "verify.py",
        ROOT / "dom_clobber" / "__init__.py",
    ]
    # active_probe_kit wiring may mention dom_clobber family but not Horizon paths/props
    kit = (ROOT / "active_probe_kit.py").read_text(encoding="utf-8")
    for pat in forbidden:
        assert re.search(pat, kit) is None, f"active_probe_kit hardcodes {pat}"
    for path in scan_files:
        text = path.read_text(encoding="utf-8")
        for pat in forbidden:
            assert re.search(pat, text) is None, f"{path.name} hardcodes {pat}"


def test_no_fixture_param_aliases_in_horizon_dom_clobber():
    """Horizon must not ship scanner-matching q/content aliases for DOM clobber."""
    src = (ROOT / "vuln_playground" / "vulns" / "browser_extra.py").read_text(encoding="utf-8")
    assert "_dom_clobber_inject_raw" not in src
    # Only html= (realistic) — not a multi-name alias helper
    assert 'for key in ("html", "q"' not in src
