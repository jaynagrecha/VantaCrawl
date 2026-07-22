"""Regression tests for high-noise false-positive sources in security scanning."""

from __future__ import annotations

from content_validate import needs_content_gate, validate_sensitive_content
from cookie_impact import (
    analyze_response_cookies,
    analyze_set_cookie_headers,
    classify_cookie,
)
from file_metadata import metadata_findings
from recon_extract import (
    extract_mixed_content,
    find_jwt_candidates,
    jwt_alg_is_none,
    jwt_header_looks_valid,
)
from security_scan import (
    extract_forms,
    scan_api_leaks,
    scan_authentication_flaws,
    scan_directory_traversal,
    scan_file_upload,
    scan_open_redirect,
    scan_secrets,
    scan_sensitive_path,
    scan_sql_injection,
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


def test_open_redirect_passive_is_precise_low():
    findings = scan_open_redirect("https://app.example/login?next=https://evil.example/phish")
    assert findings and all(f[1] == "low" for f in findings)


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


def test_file_upload_type_file_info_finding():
    html = (
        '<form action="/upload" method="post">'
        '<input type="file" name="attachment">'
        '<input type="submit">'
        "</form>"
    )
    forms = extract_forms(html, "https://x.com/page", "text/html")
    assert forms and forms[0]["has_file_input"]
    findings = scan_file_upload(forms, "https://x.com/page")
    assert any(f[0] == "file_upload" and f[1] == "info" for f in findings)


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


# --- Round 2 ---------------------------------------------------------------


def test_path_only_dotdot_not_traversal_fp():
    assert scan_directory_traversal("https://x.com/static/../assets/app.js") == []
    assert scan_directory_traversal("https://x.com/page?next=../home") == []


def test_traversal_etc_passwd_param_precise_tp():
    findings = scan_directory_traversal("https://x.com/file?path=../../../etc/passwd")
    assert any(f[0] == "directory_traversal" for f in findings)


def test_api_leak_phpinfo_404_not_fp():
    findings = scan_api_leaks(
        "https://x.com/phpinfo.php",
        "<html><title>Not Found</title></html>",
        {},
        "text/html",
    )
    assert findings == []


def test_api_leak_phpinfo_with_body_proof():
    findings = scan_api_leaks(
        "https://x.com/phpinfo.php",
        "<h1>PHP Version 8.2.12</h1><p>phpinfo()</p>",
        {},
        "text/html",
    )
    assert any(f[0] == "api_leak" for f in findings)


def test_bare_api_key_param_not_critical_fp():
    findings = scan_authentication_flaws(
        "https://x.com/search?api_key=&q=test",
        {},
        "",
    )
    assert findings == []


def test_credential_like_url_value_still_flagged():
    findings = scan_authentication_flaws(
        "https://x.com/callback?api_key=a1b2c3d4e5f60718293a4b5c6d7e8f90",
        {},
        "",
    )
    assert any(f[0] == "authentication" for f in findings)


def test_sql_special_chars_without_error_not_fp():
    findings = scan_sql_injection(
        "https://shop.example/item?id=1'",
        "Welcome to our shop",
    )
    assert findings == []


def test_cart_token_cookie_not_auth():
    assert classify_cookie("cart_token", "abc123def456ghi789") == "unknown"
    assert classify_cookie("device_sid", "abc123def456ghi789") == "unknown"
    assert classify_cookie("ab_test_session", "variant_a") == "unknown"


def test_request_cookie_inventory_only_no_finding():
    inv, findings = analyze_response_cookies(
        {"Cookie": "sessionid=abc123def456ghi789jkl012"},
        page_url="https://example.com/",
        include_request_cookie=True,
    )
    assert any(r["name"] == "sessionid" for r in inv)
    assert findings == []


def test_git_forbidden_plaintext_not_confirmed():
    assert (
        validate_sensitive_content(
            "https://x.com/.git/config",
            status=403,
            body="Forbidden\n",
            content_type="text/plain",
        )
        is None
    )


def test_git_config_body_still_confirmed():
    proof = validate_sensitive_content(
        "https://x.com/.git/config",
        status=200,
        body='[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n',
        content_type="text/plain",
    )
    assert proof and "Confirmed" in proof


def test_plain_author_metadata_not_finding():
    findings = metadata_findings(
        {
            "url": "https://x.com/a.pdf",
            "fields": {"author": "Ada Lovelace", "title": "Notes"},
            "interesting": {"author": "Ada Lovelace"},
        }
    )
    assert findings == []


def test_email_author_metadata_still_finding():
    findings = metadata_findings(
        {
            "url": "https://x.com/a.pdf",
            "fields": {"author": "jsmith@corp.local"},
            "interesting": {"author": "jsmith@corp.local"},
        }
    )
    assert any(f[0] == "file_metadata" and f[1] == "medium" for f in findings)


def test_jwt_alg_none_helper():
    # header {"alg":"none","typ":"JWT"}
    import base64
    import json

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
    token = f"{header}.{payload}."
    assert jwt_header_looks_valid(token)
    assert jwt_alg_is_none(token)


# --- Round 3 ---------------------------------------------------------------


def test_http_auth_path_alone_not_finding():
    findings = scan_authentication_flaws(
        "http://x.com/author/posts",
        {},
        "<html><body>Blog author page</body></html>",
    )
    assert findings == []


def test_http_password_form_still_finding():
    findings = scan_authentication_flaws(
        "http://x.com/login",
        {},
        '<form><input type="password" name="password"></form>',
    )
    assert any(f[0] == "authentication" for f in findings)


def test_possible_credential_cookie_low_finding():
    inv, findings = analyze_set_cookie_headers(
        {"Set-Cookie": "device_id=abcdef0123456789abcdef0123456789; Path=/"},
        page_url="https://example.com/",
    )
    assert inv
    # Precise low TP: opaque high-entropy cookie without HttpOnly
    assert any(f[0] == "authentication" and f[1] == "low" for f in findings)


def test_passive_precise_signals_still_fire():
    from security_scan import scan_rce

    assert scan_ssrf("https://x.com/fetch?url=http://169.254.169.254/")
    assert scan_sql_injection("https://x.com/?id=1", "mysql_fetch SQL syntax error")
    assert scan_rce("https://x.com/?cmd=id", "sh: command not found")
    assert scan_open_redirect("https://x.com/out?next=https://evil.test/")
