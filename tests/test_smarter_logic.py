"""Smarter multi-signal logic — tune severity/context without blind elimination."""

from __future__ import annotations

from finding_impact import assess_api_leak, assess_secrets_static
from secret_classify import is_client_public_key, severity_for_kind
from security_scan import (
    extract_forms,
    scan_file_upload,
    scan_open_redirect,
    scan_sql_injection,
    scan_ssrf,
    scan_xss,
)


def test_sqli_tiers_payload_vs_name_only():
    high = scan_sql_injection(
        "https://x.com/item?id=1'",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert high and high[0][1] == "high"

    med = scan_sql_injection(
        "https://x.com/item?id=1",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert med and med[0][1] == "medium"


def test_xss_analytics_inline_cookie_skipped():
    body = (
        "<html><script>"
        "window.ga=window.ga||function(){(ga.q=ga.q||[]).push(arguments)};"
        "document.cookie='_ga=1';"
        "google-analytics.com/analytics.js"
        "</script></html>"
    )
    findings = scan_xss("https://x.com/", body)
    assert not any("Inline script with cookie/eval" in f[2] for f in findings)


def test_xss_inline_with_reflected_param_high():
    body = (
        "<html><script>"
        "eval('markerXYZ');"
        "document.cookie='x=1';"
        "</script></html>"
    )
    findings = scan_xss("https://x.com/p?q=markerXYZ", body)
    assert any(f[0] == "xss" and f[1] == "high" for f in findings)


def test_xss_document_cookie_alone_not_xss():
    body = "<html><script>document.cookie='session=1';</script></html>"
    findings = scan_xss("https://x.com/", body)
    assert not any(f[0] == "xss" for f in findings)


def test_ssrf_rfc1918_is_low():
    findings = scan_ssrf("https://app.example/fetch?url=http://10.0.0.5/admin")
    assert findings and findings[0][1] == "low"


def test_ssrf_metadata_stays_high():
    findings = scan_ssrf(
        "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/"
    )
    assert findings and findings[0][1] == "high"


def test_open_redirect_partner_is_info():
    findings = scan_open_redirect(
        "https://app.example/out?next=https://www.facebook.com/sharer"
    )
    assert findings and findings[0][1] == "info"


def test_open_redirect_unknown_stays_low():
    findings = scan_open_redirect(
        "https://app.example/login?next=https://evil-phish.example/x"
    )
    assert findings and findings[0][1] == "low"


def test_client_public_key_severity():
    assert is_client_public_key("Stripe Live Publishable Key", "pk_live_" + "a" * 24)
    assert severity_for_kind("Google Cloud / Maps API Key", "high", "AIza" + "x" * 35) == "info"
    static = assess_secrets_static(
        "Exposed Google Cloud / Maps API Key in response body",
        "high",
        "AIzaSyD-RealKeyValue0123456789AbCdEfGhI",
    )
    assert static.role == "client_public_key"
    assert static.suppress is True
    assert static.severity == "info"


def test_graphql_schema_vs_playground_impact():
    schema = assess_api_leak(
        "GraphQL schema JSON disclosed (__schema/queryType) on GraphQL path",
        "high",
    )
    assert schema.impact == "confirmed"
    playground = assess_api_leak(
        "GraphQL playground/UI indicators on GraphQL path (unverified introspection)",
        "medium",
    )
    assert playground.impact == "possible"
    assert playground.validation == "unverified"


def test_file_upload_profile_vs_risky():
    profile = extract_forms(
        '<form action="/account/avatar" method="post">'
        '<input type="file" name="photo" accept="image/*">'
        "</form>",
        "https://x.com/account",
        "text/html",
    )
    findings = scan_file_upload(profile, "https://x.com/account")
    assert findings and findings[0][1] == "info"

    risky = extract_forms(
        '<form action="/admin/import" method="post">'
        '<input type="file" name="blob" accept="*/*">'
        "</form>",
        "https://x.com/admin",
        "text/html",
    )
    findings = scan_file_upload(risky, "https://x.com/admin")
    # Attack-surface observation — not a confirmed Medium vulnerability
    assert findings and findings[0][1] == "info"
    assert "server-side validation not assessed" in findings[0][2].lower()
    assert "risky accept" in findings[0][2].lower() or "admin" in findings[0][2].lower()
