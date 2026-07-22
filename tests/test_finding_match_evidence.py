"""Exact matched-pattern evidence must be stored on pattern-based findings."""

from __future__ import annotations

from finding_explain import group_findings_for_report
from security_scan import (
    scan_api_leaks,
    scan_directory_traversal,
    scan_open_redirect,
    scan_rce,
    scan_sql_injection,
    scan_ssrf,
    scan_xss,
)


def test_static_js_bundle_never_flags_rce_from_eval():
    """Screenshot FP: webpack bundles with eval( must not emit body-only RCE."""
    body = "function n(e){return eval('('+e+')')}webpackJsonp..."
    url = "https://employee-attendance-syste-m.netlify.app/assets/index-Bsm1DrMS.js"
    assert scan_rce(url, body) == []


def test_rce_evidence_names_shell_token():
    findings = scan_rce(
        "https://x.com/run?cmd=id",
        "sh: id: command not found\n",
    )
    assert findings
    category, severity, detail, evidence = findings[0]
    assert category == "rce"
    assert evidence
    assert "matched `" in evidence
    assert "sh:" in evidence.lower() or "command not found" in evidence.lower()


def test_sqli_evidence_names_sql_error_token():
    findings = scan_sql_injection(
        "https://x.com/item?id=1'",
        "Warning: mysql_fetch_array(): SQL syntax error near '''",
    )
    assert findings and findings[0][3]
    assert "mysql_fetch" in findings[0][3].lower() or "sql syntax" in findings[0][3].lower()
    assert "matched `" in findings[0][3]


def test_xss_reflected_evidence_includes_param_value():
    findings = scan_xss(
        "https://x.com/search?q=<script>alert(1)</script>",
        "Results for <script>alert(1)</script>",
    )
    assert findings
    assert any(
        f[3] and ("<script>" in f[3].lower() or "reflected_param" in f[3])
        for f in findings
    )


def test_ssrf_evidence_includes_target():
    findings = scan_ssrf(
        "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/"
    )
    assert findings and findings[0][3]
    assert "169.254.169.254" in findings[0][3]


def test_traversal_evidence_includes_payload():
    findings = scan_directory_traversal("https://x.com/file?path=../../../etc/passwd")
    assert findings and findings[0][3]
    assert "../" in findings[0][3] or "etc/passwd" in findings[0][3]


def test_open_redirect_evidence_includes_target():
    findings = scan_open_redirect(
        "https://app.example/login?next=https://evil-phish.example/x"
    )
    assert findings and findings[0][3]
    assert "evil-phish.example" in findings[0][3]


def test_api_leak_graphql_evidence_names_schema_token():
    findings = scan_api_leaks(
        "https://api.example/graphql",
        '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
        {},
        "application/json",
    )
    assert findings
    assert any(f[3] and "__schema" in f[3] for f in findings)


def test_assessment_groups_preserve_match_evidence():
    raw = [
        {
            "category": "rce",
            "severity": "high",
            "url": "https://x.com/run?cmd=id",
            "detail": "Command param(s) cmd with shell execution evidence (precise passive RCE)",
            "evidence": "shell_evidence: matched `sh:` @ offset 0: sh: id: command not found",
        }
    ]
    groups = group_findings_for_report(raw)
    assert groups
    assert groups[0]["evidence"]
    assert "matched `sh:`" in groups[0]["evidence"][0]
