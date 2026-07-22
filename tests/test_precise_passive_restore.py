"""Precise passive matchers — restored after over-suppression in FP round 3."""

from __future__ import annotations

from security_scan import (
    extract_forms,
    scan_directory_traversal,
    scan_file_upload,
    scan_open_redirect,
    scan_rce,
    scan_sql_injection,
    scan_ssrf,
    scan_xss,
)


def test_sqli_error_alone_not_enough():
    assert (
        scan_sql_injection(
            "https://x.com/",
            "Warning: mysql_fetch_array(): SQL syntax error near",
        )
        == []
    )


def test_sqli_error_plus_injectable_param_is_tp():
    findings = scan_sql_injection(
        "https://x.com/item?id=1'",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert any(f[0] == "sql_injection" and "precise" in f[2] for f in findings)


def test_xss_quote_only_not_tp():
    assert (
        scan_xss(
            'https://x.com/search?q="hi"',
            '<html><body>query: "hi"</body></html>',
        )
        == []
    )


def test_xss_script_payload_unreflected_escaped_not_tp():
    assert (
        scan_xss(
            "https://x.com/search?q=<script>",
            "<html><body>query: &lt;script&gt;</body></html>",
        )
        == []
    )


def test_xss_script_payload_unescaped_is_tp():
    findings = scan_xss(
        "https://x.com/search?q=<script>alert(1)</script>",
        "<html><body>query: <script>alert(1)</script></body></html>",
    )
    assert any(f[0] == "xss" and "precise" in f[2] for f in findings)


def test_ssrf_redirect_param_internal_not_ssrf():
    # next=/internal is open-redirect territory
    assert scan_ssrf("https://app.example/login?next=http://127.0.0.1/admin") == []


def test_ssrf_fetch_metadata_is_tp():
    findings = scan_ssrf(
        "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/"
    )
    assert any(f[0] == "ssrf" and f[1] == "high" and "precise" in f[2] for f in findings)


def test_ssrf_fetch_loopback_is_tp():
    findings = scan_ssrf("https://app.example/proxy?uri=http://127.0.0.1:8080/")
    assert any(f[0] == "ssrf" and "precise" in f[2] for f in findings)


def test_traversal_path_dotdot_still_clean():
    assert scan_directory_traversal("https://x.com/static/../assets/app.js") == []


def test_traversal_file_passwd_is_tp():
    findings = scan_directory_traversal("https://x.com/file?path=../../../etc/passwd")
    assert any(f[0] == "directory_traversal" and "precise" in f[2] for f in findings)


def test_rce_docs_still_clean():
    body = "```python\nos.system('ls')\n```\nThis tutorial explains eval()."
    assert scan_rce("https://docs.example/?cmd=id", body) == []


def test_rce_cmd_plus_shell_error_is_tp():
    findings = scan_rce(
        "https://x.com/run?cmd=id",
        "sh: id: command not found\n",
    )
    assert any(f[0] == "rce" and "precise" in f[2] for f in findings)


def test_open_redirect_oauth_still_suppressed():
    assert (
        scan_open_redirect(
            "https://auth.example/oauth/authorize?client_id=x&redirect_uri=https://app.example/cb"
        )
        == []
    )


def test_open_redirect_offsite_is_precise_low():
    findings = scan_open_redirect(
        "https://app.example/login?next=https://evil.example/phish"
    )
    assert findings and findings[0][1] == "low" and "precise" in findings[0][2]


def test_file_upload_type_file_info_finding():
    html = (
        '<form action="/upload" method="post">'
        '<input type="file" name="attachment">'
        "</form>"
    )
    forms = extract_forms(html, "https://x.com/page", "text/html")
    findings = scan_file_upload(forms, "https://x.com/page")
    assert any(f[0] == "file_upload" and f[1] == "info" for f in findings)
