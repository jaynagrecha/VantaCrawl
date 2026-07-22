"""Regression tests for high-noise false-positive sources in security scanning."""

from __future__ import annotations

from content_validate import needs_content_gate, validate_sensitive_content
from cookie_impact import classify_cookie, analyze_set_cookie_headers
from recon_extract import extract_mixed_content, find_jwt_candidates, jwt_header_looks_valid
from security_scan import (
    extract_forms,
    scan_file_upload,
    scan_open_redirect,
    scan_secrets,
    scan_sensitive_path,
    scan_ssrf,
)


def test_ssrf_public_absolute_url_not_passive_fp():
    findings = scan_ssrf("https://app.example/login?next=https://cdn.example/logo.png")
    assert findings == []


def test_open_redirect_oauth_redirect_uri_suppressed():
    findings = scan_open_redirect(
        "https://auth.example/oauth/authorize?client_id=x&redirect_uri=https://app.example/callback"
    )
    assert findings == []


def test_open_redirect_passive_is_low():
    findings = scan_open_redirect("https://app.example/login?next=https://evil.example/phish")
    assert findings
    assert all(f[1] == "low" for f in findings if f[0] == "open_redirect")


def test_mailgun_webpack_chunk_not_fp():
    body = "chunk-key-abcdef0123456789abcdef0123456789.js"
    assert scan_secrets(body, "https://cdn.example/app.js") == []


def _fake_twilio_sk() -> str:
    # Runtime-only; diverse hex so entropy filters accept it, never a commit literal.
    return "SK" + "".join(f"{i:02x}" for i in range(16))


def test_twilio_sk_without_context_not_fp():
    body = f'const id = "{_fake_twilio_sk()}";'
    assert scan_secrets(body, "https://cdn.example/app.js") == []


def test_twilio_sk_with_context_detected():
    body = f'twilio.accountSid = "{_fake_twilio_sk()}";'
    hits = scan_secrets(body, "https://cdn.example/config.js")
    assert any("Twilio" in h[0] for h in hits)


def test_bare_backup_path_not_sensitive():
    assert scan_sensitive_path("https://x.com/backup") is None
    assert scan_sensitive_path("https://x.com/dump") is None
    assert scan_sensitive_path("https://x.com/backup.zip") is not None


def test_phpinfo_requires_body_proof():
    url = "https://x.com/phpinfo.php"
    assert needs_content_gate(url)
    assert (
        validate_sensitive_content(
            url,
            status=200,
            body="<html><title>Not found</title></html>",
            content_type="text/html",
        )
        is None
    )
    assert validate_sensitive_content(
        url,
        status=200,
        body="<html><h1>PHP Version 8.2.0</h1><p>phpinfo()</p></html>",
        content_type="text/html",
    )


def test_file_upload_name_only_not_fp():
    forms = [
        {
            "action": "https://x.com/upload",
            "method": "POST",
            "fields": ["file", "title"],
            "has_file_input": False,
            "file_fields": [],
        }
    ]
    assert scan_file_upload(forms, "https://x.com/") == []


def test_file_upload_type_file_detected():
    html = (
        '<form action="/upload" method="post">'
        '<input type="file" name="attachment">'
        '<input type="submit">'
        "</form>"
    )
    forms = extract_forms(html, "https://x.com/page", "text/html")
    assert forms and forms[0]["has_file_input"]
    findings = scan_file_upload(forms, "https://x.com/page")
    assert any(f[0] == "file_upload" for f in findings)


def test_mixed_content_anchor_href_not_fp():
    hits = extract_mixed_content(
        "https://secure.example/",
        '<a href="http://legacy.example/docs">docs</a>'
        '<img src="http://cdn.example/a.png">',
    )
    assert hits == []


def test_mixed_content_script_still_detected():
    hits = extract_mixed_content(
        "https://secure.example/",
        '<script src="http://cdn.example/a.js"></script>',
    )
    assert hits and hits[0].startswith("http://")


def test_jwt_body_noise_skipped_by_default():
    # Valid-looking JWT shape embedded in JS without auth context
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "signaturepad1234567890abcd"
    )
    assert jwt_header_looks_valid(token)
    assert find_jwt_candidates(f"const x = '{token}';", {}, include_body=False) == []
    auth_hits = find_jwt_candidates(
        "",
        {"Authorization": f"Bearer {token}"},
        include_body=False,
    )
    assert auth_hits and auth_hits[0][0] == "authorization"


def test_intercom_session_cookie_is_analytics_not_auth():
    assert classify_cookie("intercom-session-abc123", "xyz") == "analytics"
    inv, findings = analyze_set_cookie_headers(
        {"Set-Cookie": "intercom-session-abc123=opaquevalue1234567890; Path=/"},
        page_url="https://example.com/",
    )
    assert inv and inv[0]["role"] == "analytics"
    assert findings == []


def test_mitigated_session_cookie_no_finding():
    inv, findings = analyze_set_cookie_headers(
        {
            "Set-Cookie": (
                "sessionid=abc123def456ghi789jkl012; Path=/; HttpOnly; Secure; SameSite=Strict"
            )
        },
        page_url="https://example.com/",
    )
    assert inv and inv[0]["impact"] == "mitigated_credential"
    assert findings == []
