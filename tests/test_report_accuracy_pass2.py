"""Report accuracy pass 2 — CORS proof, remediation filter, JS URL policy, XSS/CSP."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from assessment_report import build_assessment_document
from cookie_impact import classify_cookie
from crawl_stats import CrawlStats
from crawl_url_policy import (
    classify_js_candidate,
    js_candidate_enqueue_url,
    path_has_route_placeholder,
)
from discovery_extra import extract_js_route_templates, extract_js_routes
from finding_impact import assess_cors
from finding_kind import apply_hardening_context
from finding_proof import downgrade_unproven_confirmation, proof_has_http_exchange
from report_status import include_in_remediation, is_suppressed_or_invalidated
from security_scan import check_cors, scan_xss


def test_cors_check_returns_proof():
    class Resp:
        status_code = 200
        headers = {
            "access-control-allow-origin": "https://evil.example",
            "access-control-allow-credentials": "true",
            "vary": "Origin",
        }
        request = type("R", (), {"headers": {}})()

    client = AsyncMock()
    client.get = AsyncMock(return_value=Resp())
    result = asyncio.run(check_cors(client, "https://lab.example/"))
    assert result is not None
    detail, proof = result
    assert "credentials" in detail.lower()
    assert proof_has_http_exchange(proof)
    assert "Access-Control-Allow-Origin" in proof["response"]
    assert "Origin:" in proof["request"]


def test_cors_assess_requires_proof():
    bare = assess_cors(
        "CORS reflects arbitrary Origin with credentials",
        "high",
        url="https://lab.example/",
    )
    assert bare.validation == "unverified"
    assert bare.severity == "info"

    proof = {
        "request": "GET / HTTP/1.1\nHost: lab.example\nOrigin: https://evil.example",
        "response": (
            "HTTP/1.1 200\nAccess-Control-Allow-Origin: https://evil.example\n"
            "Access-Control-Allow-Credentials: true"
        ),
    }
    ok = assess_cors(
        "CORS reflects arbitrary Origin with credentials",
        "high",
        url="https://lab.example/account",
        cookies=[{"name": "session", "host": "lab.example", "role": "auth_session"}],
        proof=proof,
    )
    assert ok.validation == "confirmed"
    assert ok.severity == "high"


def test_downgrade_unproven_confirmation():
    val, ver = downgrade_unproven_confirmation(
        validation="confirmed", verification="confirmed", proof={"request": "", "response": ""}
    )
    assert val == "unverified"
    assert ver == "detected"


def test_remediation_excludes_invalidated_secrets():
    finding = {
        "validation": "invalid",
        "verification": "detected",
        "assessment_state": "False positive / invalidated",
        "title": "Exposed Reset Password",
        "detail": "R3ResetPass localization label",
        "fix": "Revoke and rotate the exposed secret immediately.",
    }
    assert include_in_remediation(finding) is False
    assert is_suppressed_or_invalidated(finding) is True

    confirmed = {
        "validation": "confirmed",
        "verification": "confirmed",
        "assessment_state": "Confirmed vulnerability",
        "finding_kind": "vulnerability",
        "severity": "medium",
        "title": "XSS",
        "fix": "Encode output",
    }
    assert include_in_remediation(confirmed) is True


def test_roadmap_skips_invalidated(tmp_path=None):
    stats = CrawlStats()
    stats.pages_crawled = 10
    stats.finished_at = stats.started_at
    stats.findings = [
        {
            "severity": "high",
            "category": "secrets_exposure",
            "detail": "Exposed Reset Password",
            "url": "https://lab.example/a.js",
            "validation": "invalid",
            "impact": "no_impact",
            "finding_kind": "vulnerability",
            "verification": "detected",
        },
        {
            "severity": "medium",
            "category": "xss",
            "detail": "Confirmed reflected XSS",
            "url": "https://lab.example/x",
            "validation": "confirmed",
            "impact": "confirmed",
            "finding_kind": "vulnerability",
            "verification": "confirmed",
            "proof": {"request": "GET /x", "response": "HTTP 200 <script>"},
        },
    ]
    doc = build_assessment_document(stats, "https://lab.example/")
    roadmap_text = " ".join(r.get("item", "") for r in doc.get("roadmap") or [])
    assert "Reset Password" not in roadmap_text
    assert any("XSS" in (r.get("item") or "") or "xss" in (r.get("item") or "").lower() for r in doc.get("roadmap") or []) or doc.get("roadmap")
    assert doc.get("suppressed_observations")


def test_js_placeholder_not_enqueued():
    assert path_has_route_placeholder("/[countryCode]/[langCode]/find-locations")
    templates = extract_js_route_templates(
        'const r = "/[countryCode]/[langCode]/[partnerName]/find-locations";'
    )
    assert any("{countryCode}" in t for t in templates)
    routes = extract_js_routes(
        'const r = "/[countryCode]/[langCode]/find-locations"; const ok="/rewards/dashboard";',
        "https://lab.example/_next/static/chunks/pages/app.js",
    )
    assert not any("[countryCode]" in u for u in routes)
    assert any("rewards/dashboard" in u for u in routes)


def test_js_relative_not_resolved_against_chunk_dir():
    script = "https://lab.example/_next/static/chunks/pages/app.js"
    kind, _ = classify_js_candidate("rewards/dashboard", script, "https://lab.example")
    assert kind == "unverified_string"
    assert js_candidate_enqueue_url("rewards/dashboard", script) is None
    enq = js_candidate_enqueue_url("/rewards/dashboard", script, "https://lab.example")
    assert enq == "https://lab.example/rewards/dashboard"
    assert "/_next/static/" not in enq


def test_xss_cookie_assignment_not_sink():
    body = "<html><script>document.cookie = cookie;</script></html>"
    assert scan_xss("https://lab.example/", body) == []


def test_csp_not_elevated_by_cookie_heuristic():
    groups = apply_hardening_context(
        [
            {
                "severity": "info",
                "category": "header_audit",
                "detail": "missing CSP",
                "urls": ["https://app.example/"],
                "hosts": ["app.example"],
            },
            {
                "severity": "low",
                "category": "xss",
                "detail": "Inline script with cookie/eval sink",
                "urls": ["https://app.example/"],
                "hosts": ["app.example"],
                "verification": "detected",
                "validation": "unverified",
            },
        ]
    )
    csp = next(g for g in groups if "csp" in g["detail"].lower())
    assert csp["severity"] == "info"


def test_bm_cookies_are_edge_protection():
    for name in ("_abck", "bm_sz", "bm_sv", "ak_bmsc"):
        assert classify_cookie(name, "x") == "edge_protection"


def test_cookie_inventory_dedupes_rotations():
    stats = CrawlStats()
    stats.record_cookie_inventory(
        [{"name": "bm_sz", "domain": ".lab.example", "path": "/", "flags": "Secure"}]
    )
    stats.record_cookie_inventory(
        [{"name": "bm_sz", "domain": ".lab.example", "path": "/", "flags": "Secure,HttpOnly"}]
    )
    rows = [c for c in stats.cookie_inventory if c["name"] == "bm_sz"]
    assert len(rows) == 1
    assert rows[0]["observed_rotations"] == 2
