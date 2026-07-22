"""Hardening vs vulnerability severity model."""

from __future__ import annotations

import asyncio

from assessment_report import build_assessment_document
from crawl_stats import CrawlStats
from finding_impact import assess_finding
from finding_kind import apply_hardening_context, classify_finding_kind
from finding_explain import group_findings_for_report


def test_headers_are_info_hardening():
    for detail in ("missing HSTS", "missing CSP", "missing X-Frame-Options (clickjacking)"):
        result = asyncio.run(
            assess_finding(category="header_audit", severity="medium", detail=detail)
        )
        assert result.role == "hardening"
        assert result.severity == "info"
        assert result.impact == "informational"


def test_csp_elevates_when_xss_on_same_host():
    groups = apply_hardening_context(
        [
            {
                "severity": "info",
                "category": "header_audit",
                "detail": "missing CSP",
                "title": "Missing CSP",
                "count": 1,
                "urls": ["https://app.example/"],
                "hosts": ["app.example"],
                "role": "hardening",
                "impact": "informational",
            },
            {
                "severity": "high",
                "category": "xss",
                "detail": "Active xss probe confirmed",
                "title": "XSS",
                "count": 1,
                "urls": ["https://app.example/search?q=1"],
                "hosts": ["app.example"],
                "role": "finding",
                "impact": "confirmed",
            },
        ]
    )
    csp = next(g for g in groups if "csp" in g["detail"].lower())
    assert csp["severity"] == "medium"
    assert csp["finding_kind"] == "hardening"


def test_classify_google_key_restricted_is_hardening():
    assert (
        classify_finding_kind(
            category="secrets_exposure",
            role="client_public_key",
            impact="limited_impact",
            severity="info",
            detail="Exposed Firebase API Key",
        )
        == "hardening"
    )


def test_assessment_risk_ignores_hardening_medium_noise():
    import time

    stats = CrawlStats()
    stats.pages_crawled = 5
    stats.finished_at = time.time()
    stats.record_finding(
        "header_audit",
        "info",
        "https://restaurant.example/",
        "missing HSTS",
        role="hardening",
        impact="informational",
    )
    stats.record_finding(
        "header_audit",
        "info",
        "https://restaurant.example/",
        "missing CSP",
        role="hardening",
        impact="informational",
    )
    stats.record_finding(
        "secrets_exposure",
        "info",
        "https://restaurant.example/assets/app.js",
        "Exposed Firebase API Key in response body",
        evidence="AIzaSyAQmcbet1FYuca30mB23_Z_z91Sdt1PsCE",
        role="client_public_key",
        impact="limited_impact",
        validation="unverified",
    )
    doc = build_assessment_document(stats, "https://restaurant.example/")
    assert doc["risk_level"] in ("Low", "Clear")
    assert doc["hardening_issues"]
    assert doc["vulnerabilities"] == []
    assert all(str(f["id"]).startswith("H-") for f in doc["hardening_issues"])


def test_group_findings_sets_finding_kind():
    groups = group_findings_for_report(
        [
            {
                "category": "header_audit",
                "severity": "info",
                "url": "https://a/",
                "detail": "missing HSTS",
                "role": "hardening",
                "impact": "informational",
            }
        ]
    )
    assert groups
    assert groups[0]["finding_kind"] == "hardening"
    assert groups[0]["severity"] == "info"
