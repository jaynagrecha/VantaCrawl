"""Cookie capture + stealable-credential impact analysis."""

from __future__ import annotations

from cookie_impact import (
    analyze_response_cookies,
    analyze_set_cookie_headers,
    assess_cookie_impact,
    classify_cookie,
    parse_set_cookie,
)
from finding_explain import explain_finding
from recon_extract import inventory_cookies


def test_parse_and_classify_session_cookie():
    parsed = parse_set_cookie(
        "sessionid=abc123def456ghi789jkl012; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
    assert parsed["name"] == "sessionid"
    assert parsed["httponly"] is True
    assert parsed["secure"] is True
    assert classify_cookie(parsed["name"], parsed["value"]) == "auth_session"
    assessment = assess_cookie_impact(parsed, page_url="https://example.com/")
    assert assessment["impact"] == "mitigated_credential"
    assert assessment["stealable"] is False


def test_stealable_session_missing_httponly():
    parsed = parse_set_cookie("sessionid=abc123def456ghi789jkl012; Path=/; Secure; SameSite=Lax")
    assessment = assess_cookie_impact(parsed, page_url="https://example.com/")
    assert assessment["impact"] == "stealable_credential"
    assert assessment["stealable"] is True
    assert assessment["severity"] == "high"


def test_analytics_cookie_no_credential_impact():
    parsed = parse_set_cookie("_ga=GA1.2.123456789.1234567890; Path=/; SameSite=Lax")
    assessment = assess_cookie_impact(parsed, page_url="https://example.com/")
    assert assessment["role"] == "analytics"
    assert assessment["impact"] == "no_credential_impact"
    assert assessment["stealable"] is False


def test_csrf_limited_impact():
    parsed = parse_set_cookie("csrf_token=abcdefghijklmnopqrstuv; Path=/")
    assessment = assess_cookie_impact(parsed, page_url="https://example.com/")
    assert assessment["role"] == "csrf"
    assert assessment["impact"] == "limited_impact"


def test_analyze_emits_finding_only_for_stealable():
    headers = {
        "Set-Cookie": (
            "sessionid=abc123def456ghi789jkl012; Path=/; Secure, "
            "_ga=GA1.2.111.222; Path=/, "
            "prefs=dark; Path=/"
        )
    }
    inv, findings = analyze_set_cookie_headers(headers, page_url="https://wu.example/")
    names = {r["name"] for r in inv}
    assert "sessionid" in names and "_ga" in names
    # Stealable session finding present; analytics should not produce a steal finding
    assert any("sessionid" in f[2] and "stealable" in f[2].lower() for f in findings)
    assert not any("_ga" in f[2] and f[1] in ("high", "medium") for f in findings)


def test_jwt_cookie_flagged():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "signaturepad1234567890abcd"
    )
    inv, findings = analyze_set_cookie_headers(
        {"Set-Cookie": f"access_token={jwt}; Path=/"},
        page_url="https://example.com/",
    )
    assert inv and inv[0]["role"] == "jwt"
    assert inv[0]["impact"] == "stealable_credential"
    assert findings and findings[0][3] == jwt


def test_inventory_cookies_includes_impact_fields():
    rows = inventory_cookies(
        {"Set-Cookie": "sessionid=abc123def456ghi789jkl012; HttpOnly; Secure; SameSite=Strict"}
    )
    assert rows
    assert rows[0]["name"] == "sessionid"
    assert "HttpOnly" in rows[0]["flags"]
    assert rows[0].get("impact") == "mitigated_credential"


def test_request_cookie_header_captured():
    inv, findings = analyze_response_cookies(
        {"Cookie": "sessionid=abc123def456ghi789jkl012; _ga=GA1.2.1.2"},
        page_url="https://example.com/",
        include_request_cookie=True,
    )
    assert any(r["name"] == "sessionid" for r in inv)
    assert any(r["name"] == "_ga" for r in inv)


def test_explain_stealable_cookie():
    expl = explain_finding(
        "authentication",
        "Cookie `sessionid` — appears to be a session/auth credential. Impact: stealable_credential. "
        "Issues: Missing HttpOnly — XSS or injected script can read this cookie.",
    )
    assert "steal" in expl["title"].lower() or "cookie" in expl["title"].lower()
    assert "HttpOnly" in expl["fix"] or "cookie" in expl["fix"].lower()
