"""Second-pass FP/FN hardening: content gates, cloud classify, redirects, recon."""

from content_validate import classify_bucket_response, validate_sensitive_content
from recon_extract import (
    detect_login_surface,
    extract_mixed_content,
    extract_sourcemap_urls,
    extract_websocket_urls,
    find_jwt_candidates,
    inventory_cookies,
)
from security_scan import (
    run_passive_vuln_scan,
    scan_api_leaks,
    scan_open_redirect,
    scan_sensitive_path,
    scan_secrets,
)


def test_git_html_soft404_rejected():
    assert (
        validate_sensitive_content(
            "https://x.com/.git/HEAD",
            status=200,
            body="<!DOCTYPE html><html><head><title>404</title></head></html>",
            content_type="text/html",
        )
        is None
    )


def test_git_head_confirmed():
    proof = validate_sensitive_content(
        "https://x.com/.git/HEAD",
        status=200,
        body="ref: refs/heads/main\n",
        content_type="text/plain",
    )
    assert proof and "Confirmed" in proof


def test_env_key_lines_confirmed():
    body = "DB_HOST=localhost\nDB_PASSWORD=supersecret\nAPP_KEY=base64:abc\n"
    proof = validate_sensitive_content(
        "https://x.com/.env", status=200, body=body, content_type="text/plain"
    )
    assert proof and "Confirmed" in proof


def test_env_html_rejected():
    assert (
        validate_sensitive_content(
            "https://x.com/.env",
            status=200,
            body="<html><body>Not found</body></html>",
            content_type="text/html",
        )
        is None
    )


def test_s3_nosuchbucket_filtered():
    ok, note = classify_bucket_response(
        403,
        b'<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>',
        provider="s3",
    )
    assert ok is False
    assert "NoSuchBucket" in note


def test_s3_access_denied_kept():
    ok, note = classify_bucket_response(
        403,
        b'<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>',
        provider="s3",
    )
    assert ok is True
    assert "AccessDenied" in note


def test_secrets_not_double_fired_in_passive():
    body = 'const key = "AIzaSyD-RealKeyValue0123456789AbCdEfGhI";'
    direct = scan_secrets(body, "https://x.com/a.js")
    assert direct
    passive = run_passive_vuln_scan("https://x.com/a.js", body, [], {}, "application/javascript")
    assert not any(f[0] == "secrets_exposure" for f in passive)


def test_sensitive_path_backup_guide_still_clean():
    assert scan_sensitive_path("https://x.com/backup-restore-policy") is None
    assert scan_sensitive_path("https://x.com/backup.zip") is not None
    assert scan_sensitive_path("https://x.com/.git/config") is not None


def test_open_redirect_passive_offsite():
    findings = scan_open_redirect("https://app.example/login?next=https://evil.example/phish")
    assert any(f[0] == "open_redirect" for f in findings)


def test_open_redirect_same_host_not_flagged():
    findings = scan_open_redirect("https://app.example/login?next=https://app.example/home")
    assert findings == []


def test_api_debug_substring_not_fp():
    findings = scan_api_leaks(
        "https://docs.example/debugging-guide",
        "How to debug your app",
        {},
        "text/html",
    )
    assert not any(f[0] == "api_leak" for f in findings)


def test_sourcemap_and_websocket_extract():
    js = "//# sourceMappingURL=app.js.map\nconst s = new WebSocket('wss://x.com/ws');\n"
    maps = extract_sourcemap_urls(js, "https://cdn.example/static/app.js")
    assert any(u.endswith("app.js.map") for u in maps)
    sockets = extract_websocket_urls(js, "https://cdn.example/static/app.js")
    assert any("wss://x.com/ws" in u for u in sockets)


def test_mixed_content_on_https():
    hits = extract_mixed_content(
        "https://secure.example/",
        '<script src="http://cdn.example/a.js"></script>',
    )
    assert hits and hits[0].startswith("http://")


def test_login_surface_and_jwt_cookie():
    why = detect_login_surface(
        "https://x.com/login",
        '<form><input type="password" name="password"></form>',
        [{"action": "/login", "method": "POST", "fields": ["user", "password"]}],
    )
    assert why
    cookies = inventory_cookies(
        {"Set-Cookie": "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"}
    )
    assert cookies and cookies[0]["name"] == "sessionid"
    assert "HttpOnly" in cookies[0]["flags"]
    jwts = find_jwt_candidates(
        "",
        {
            "Authorization": (
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepad1234567890"
            )
        },
    )
    assert jwts
