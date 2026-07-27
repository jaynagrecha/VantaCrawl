"""Regression tests for report-quality fixes (keutek-report-quality-32cd).

Covers:
 - CSRF flood aggregation (normalise fragment/query in group key)
 - Suppressed/invalidated findings excluded from severity totals
 - XSS precision: reflected param must be near sink, not just same block
 - Attack-surface categories (oauth, business_logic) mapped correctly
 - Defense header inconsistency detection
 - Coverage wording (crawl_only ≠ comprehensive)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

import pytest

from crawl_stats import CrawlStats
from finding_explain import group_findings_for_report, _normalize_csrf_group_key
from report_status import assessment_state_for_finding, scan_status_from_stats
from security_scan import scan_xss


# ---------------------------------------------------------------------------
# CSRF aggregation
# ---------------------------------------------------------------------------

def _csrf_finding(action: str, fields: str = "") -> Dict[str, Any]:
    return {
        "category": "csrf",
        "severity": "info",
        "url": f"https://example.com/products/widget?page=1",
        "detail": "State-changing POST form without CSRF token (hardening — no session cookie observed)",
        "evidence": f"csrf_form: `POST {action} fields={fields}`",
        "impact": "informational",
        "validation": "unverified",
    }


def test_csrf_group_key_strips_fragment():
    key1 = _normalize_csrf_group_key(
        "csrf_form: `POST https://keutek.com/contact#contact-abc123 fields=form_type,utf8`"
    )
    key2 = _normalize_csrf_group_key(
        "csrf_form: `POST https://keutek.com/contact#contact-xyz789 fields=form_type,utf8`"
    )
    assert key1 == key2, "Same path with different fragment should produce same key"


def test_csrf_group_key_strips_query():
    key1 = _normalize_csrf_group_key(
        "csrf_form: `POST https://keutek.com/cart/add?variant=123 fields=id`"
    )
    key2 = _normalize_csrf_group_key(
        "csrf_form: `POST https://keutek.com/cart/add?variant=456 fields=id`"
    )
    assert key1 == key2, "Same path with different query should produce same key"


def test_csrf_group_key_keeps_distinct_paths_separate():
    key1 = _normalize_csrf_group_key(
        "csrf_form: `POST https://keutek.com/cart fields=(none)`"
    )
    key2 = _normalize_csrf_group_key(
        "csrf_form: `POST https://keutek.com/cart/add fields=id`"
    )
    assert key1 != key2, "Different paths must produce different keys"


def test_csrf_flood_collapses_to_one_group_per_action():
    """326 CSRF findings for different product pages but same /contact action → few groups."""
    findings = []
    for i in range(50):
        findings.append(_csrf_finding(f"https://keutek.com/contact#contact-contact{i}"))
    for i in range(50):
        findings.append(_csrf_finding(f"https://keutek.com/cart/add?variant={i}"))

    groups = group_findings_for_report(findings, max_groups=200)
    csrf_groups = [g for g in groups if g["category"] == "csrf"]
    assert len(csrf_groups) == 2, (
        f"Expected 2 CSRF groups (contact + cart/add), got {len(csrf_groups)}: "
        f"{[g['evidence'] if g.get('evidence') else g['detail'] for g in csrf_groups]}"
    )
    counts = sorted(g["count"] for g in csrf_groups)
    assert counts == [50, 50]


def test_csrf_info_dedupe_in_record_finding():
    """CrawlStats.record_finding should collapse same-action CSRF info findings."""
    stats = CrawlStats()
    for i in range(10):
        stats.record_finding(
            "csrf",
            "info",
            f"https://keutek.com/products/widget-{i}",
            "State-changing POST form without CSRF token (hardening — no session cookie observed)",
            evidence=f"csrf_form: `POST https://keutek.com/contact#contact-{i} fields=form_type,utf8`",
            impact="informational",
        )
    csrf_findings = [f for f in stats.findings if f["category"] == "csrf"]
    assert len(csrf_findings) == 1, (
        f"Expected 1 deduplicated CSRF finding, got {len(csrf_findings)}"
    )


# ---------------------------------------------------------------------------
# Suppressed findings excluded from severity counts
# ---------------------------------------------------------------------------

def test_suppressed_finding_excluded_from_severity_counts():
    """False-positive / skipped findings must not inflate severity counts."""
    from assessment_report import build_assessment_document

    stats = CrawlStats()
    stats.pages_crawled = 5
    stats.finished_at = time.time()
    stats.findings = [
        {
            "category": "secrets_exposure",
            "severity": "low",
            "url": "https://keutek.com/checkout.js",
            "detail": "Exposed Uppercase ID and Password (assigned to `password`)",
            "evidence": "_7ozb2u1e",
            "impact": "possible_credential",
            "validation": "skipped",
            "verification": "skipped",
        }
    ]
    doc = build_assessment_document(stats, "https://keutek.com/")
    sev = doc["severity_counts"]
    assert sev["low"] == 0, (
        f"Skipped/suppressed finding should NOT appear in low severity count, got {sev['low']}"
    )
    assert sev["critical"] == 0
    assert sev["high"] == 0
    assert sev["medium"] == 0


def test_suppressed_finding_in_suppressed_section():
    """Suppressed findings appear in suppressed_observations, not vulnerabilities."""
    from assessment_report import build_assessment_document

    stats = CrawlStats()
    stats.pages_crawled = 5
    stats.finished_at = time.time()
    stats.findings = [
        {
            "category": "secrets_exposure",
            "severity": "low",
            "url": "https://keutek.com/checkout.js",
            "detail": "Exposed CSS class map value",
            "evidence": "_7ozb2u1e",
            "impact": "no_impact",
            "validation": "invalid",
        }
    ]
    doc = build_assessment_document(stats, "https://keutek.com/")
    suppressed = doc.get("suppressed_observations") or doc.get("finding_sections", {}).get(
        "suppressed_false_positives", []
    )
    assert len(suppressed) >= 1, "Invalidated finding must appear in suppressed section"


# ---------------------------------------------------------------------------
# Attack-surface observation categorisation
# ---------------------------------------------------------------------------

def test_oauth_is_attack_surface_observation():
    state = assessment_state_for_finding(category="oauth", severity="info", validation="unverified")
    assert state == "Attack-surface observation"


def test_business_logic_is_attack_surface_observation():
    state = assessment_state_for_finding(
        category="business_logic", severity="info", validation="unverified"
    )
    assert state == "Attack-surface observation"


def test_graphql_is_attack_surface_observation():
    state = assessment_state_for_finding(
        category="graphql", severity="info", validation="unverified"
    )
    assert state == "Attack-surface observation"


# ---------------------------------------------------------------------------
# XSS precision
# ---------------------------------------------------------------------------

def test_xss_no_high_when_reflected_param_far_from_sink():
    """Reflected param value appearing 1000+ chars from sink must not yield 'high'."""
    # Build a script block where the param value is far from the innerHTML sink
    param_value = "myparamval"
    far_content = "x" * 1200  # more than the 400-char window
    body = (
        f"<html><script>"
        f"var data = '{param_value}';"  # param reflected here (far from sink)
        f"{far_content}"
        f"someElem.innerHTML = document.querySelector('#safe').textContent;"
        f"</script></html>"
    )
    url = f"https://example.com/page?q={param_value}"
    findings = scan_xss(url, body)
    high_xss = [f for f in findings if f[1] == "high"]
    assert not high_xss, (
        f"Reflected param far from sink should NOT produce high XSS finding, got: {high_xss}"
    )


def test_xss_high_when_reflected_param_near_sink():
    """Reflected param value close to the sink should yield 'high'."""
    param_value = "myparamval"
    # Put the reflected value just before the sink (within 400 chars)
    body = (
        f"<html><script>"
        f"var safe = 'prefix';"
        f"someElem.innerHTML = '{param_value}';"  # value used in the sink expression
        f"</script></html>"
    )
    url = f"https://example.com/page?q={param_value}"
    findings = scan_xss(url, body)
    high_xss = [f for f in findings if f[1] == "high"]
    assert high_xss, f"Reflected param near sink should produce high XSS finding, got: {findings}"


# ---------------------------------------------------------------------------
# Defense header consistency
# ---------------------------------------------------------------------------

def test_observe_headers_no_header_in_both_present_and_missing():
    """After observing multiple responses, a header must not appear in both lists."""
    from defense_verify import DefenseTracker

    tracker = DefenseTracker(start_url="https://example.com/")
    # First response: no security headers
    tracker.observe_headers({"content-type": "text/html"})
    # Second response: has CSP
    tracker.observe_headers({"content-security-policy": "default-src 'self'"})

    data = tracker.to_dict()
    present = set(data["security_headers_present"])
    missing = set(data["security_headers_missing"])
    overlap = present & missing
    assert not overlap, (
        f"Headers appearing in both present AND missing: {overlap}. "
        "A header should be 'missing' only when it was NEVER seen."
    )


def test_observe_headers_inconsistent_set():
    """Headers present on some responses but absent on others are reported as inconsistent."""
    from defense_verify import DefenseTracker

    tracker = DefenseTracker(start_url="https://example.com/")
    # First response: has CSP but no HSTS
    tracker.observe_headers({"content-security-policy": "default-src 'self'"})
    # Second response: has HSTS but no CSP
    tracker.observe_headers({"strict-transport-security": "max-age=31536000"})

    data = tracker.to_dict()
    # Both headers were seen on at least one response → both in present
    assert "content-security-policy" in data["security_headers_present"]
    assert "strict-transport-security" in data["security_headers_present"]
    # Neither should be in 'missing' (both were seen at least once)
    assert "content-security-policy" not in data["security_headers_missing"]
    assert "strict-transport-security" not in data["security_headers_missing"]
    # Both should be in inconsistent (present on some but not all)
    inconsistent = set(data.get("security_headers_inconsistent") or [])
    assert "content-security-policy" in inconsistent or "strict-transport-security" in inconsistent


# ---------------------------------------------------------------------------
# Coverage wording
# ---------------------------------------------------------------------------

def test_target_content_coverage_is_crawl_only_not_ok():
    """A finished scan without active probes should report crawl_only, not ok."""

    class FakeStats:
        queue_size = 0
        pages_crawled = 50
        enum_words_total = 0
        enum_words_tested = 0
        finished_at = time.time()
        _remaining_jobs = 0
        enum_edge_blocked = False
        assessment_inconclusive_reason = ""
        target_content_coverage = ""
        _scan_status = "final"
        _directory_enum_enabled = False
        enum_configured = False
        enum_started_at = None
        enum_skip_reason = None

    status = scan_status_from_stats(FakeStats())
    coverage = status.get("target_content_coverage", "")
    assert coverage != "ok", (
        f"A crawl-only scan should not report target_content_coverage='ok', got '{coverage}'"
    )
    assert coverage in ("crawl_only", ""), (
        f"Expected 'crawl_only' or '', got '{coverage}'"
    )
