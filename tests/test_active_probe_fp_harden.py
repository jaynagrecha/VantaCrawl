"""Active / passive injection probe FP hardening."""

from __future__ import annotations

import asyncio

from security_scan import (
    run_active_vuln_probes,
    scan_sql_injection,
)


class _Resp:
    def __init__(self, text, headers=None, status=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status


class _Client:
    def __init__(self, mode: str):
        self.mode = mode
        self.n = 0

    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        params = params or {}
        joined = " ".join(str(v) for v in params.values())
        self.n += 1
        if self.mode == "baseline_sql_docs":
            if "'" in joined:
                return _Resp("Docs: PostgreSQL ERROR example. nonce=222")
            return _Resp("Docs: PostgreSQL ERROR example. nonce=111")
        if self.mode == "empty_baseline_then_waf":
            if self.n == 1:
                raise RuntimeError("timeout")
            return _Resp("WAF blocked: possible SQL syntax attack")
        if self.mode == "ssrf_reflect":
            if "169.254" in joined:
                return _Resp("Invalid URL: http://169.254.169.254/latest/meta-data/")
            return _Resp("ok")
        if self.mode == "ssrf_true":
            if "169.254" in joined:
                return _Resp('{"ami-id":"ami-0abcdef1234567890","instance-id":"i-0123456789abcdef0"}')
            return _Resp("ok")
        if self.mode == "true_sqli":
            if "'" in joined:
                return _Resp("You have an error in your SQL syntax; check the manual")
            return _Resp("Product id 1 details")
        if self.mode == "xss_reflect":
            if "<crawler-xss-probe>" in joined:
                return _Resp("hello <crawler-xss-probe> world")
            return _Resp("hello world")
        if self.mode == "xss_encoded":
            if "<crawler-xss-probe>" in joined:
                return _Resp("hello &lt;crawler-xss-probe&gt; world")
            return _Resp("hello world")
        if self.mode == "rce_reflect":
            if "crawler-rce-probe-9f3a" in joined:
                return _Resp("invalid command: ;echo crawler-rce-probe-9f3a")
            return _Resp("ok")
        if self.mode == "rce_true":
            if "crawler-rce-probe-9f3a" in joined:
                return _Resp("output:\ncrawler-rce-probe-9f3a\ndone")
            return _Resp("ok")
        return _Resp("ok")

    async def post(self, *a, **k):
        return _Resp("ok")


def _run(mode: str, url: str):
    return asyncio.run(
        run_active_vuln_probes(_Client(mode), url, max_params=3, max_forms=0)
    )


def test_active_sqli_baseline_docs_not_fp():
    findings = _run("baseline_sql_docs", "https://x.com/item?id=1")
    assert not any(f[0] == "sql_injection" for f in findings)


def test_active_sqli_failed_baseline_not_fp():
    findings = _run("empty_baseline_then_waf", "https://x.com/item?id=1")
    assert not any(f[0] == "sql_injection" for f in findings)


def test_active_sqli_true_positive():
    findings = _run("true_sqli", "https://x.com/item?id=1")
    assert any(f[0] == "sql_injection" and f[1] == "high" for f in findings)


def test_active_ssrf_ip_reflection_not_fp():
    findings = _run("ssrf_reflect", "https://x.com/fetch?url=http://example.com")
    assert not any(f[0] == "ssrf" for f in findings)


def test_active_ssrf_metadata_proof_is_tp():
    findings = _run("ssrf_true", "https://x.com/fetch?url=http://example.com")
    assert any(f[0] == "ssrf" and f[1] == "high" for f in findings)


def test_active_xss_plain_reflection_is_medium_not_critical():
    findings = _run("xss_reflect", "https://example.com/search?q=test")
    xss = [f for f in findings if f[0] == "xss"]
    assert xss
    assert xss[0][1] == "medium"
    assert "reflection" in xss[0][2].lower()


def test_active_xss_entity_encoded_not_fp():
    findings = _run("xss_encoded", "https://example.com/search?q=test")
    # Raw marker absent (only &lt;…&gt;) — Client returns encoded body; marker string
    # "<crawler-xss-probe>" is NOT in the body, so no hit.
    assert not any(f[0] == "xss" for f in findings)


def test_active_rce_command_reflection_not_fp():
    findings = _run("rce_reflect", "https://x.com/run?cmd=id")
    assert not any(f[0] == "rce" for f in findings)


def test_active_rce_executed_marker_is_tp():
    findings = _run("rce_true", "https://x.com/run?cmd=id")
    assert any(f[0] == "rce" and f[1] == "critical" for f in findings)


def test_passive_select_word_not_payload_shaped():
    findings = scan_sql_injection(
        "https://x.com/search?q=select+shoes",
        "PostgreSQL ERROR: something unrelated in footer docs",
    )
    # Named param `q` + SQL error → medium name-only, NOT high payload-shaped
    assert findings
    assert findings[0][1] == "medium"
    assert "payload-shaped" not in findings[0][2]


def test_passive_quote_still_payload_shaped_high():
    findings = scan_sql_injection(
        "https://x.com/item?id=1'",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert findings and findings[0][1] == "high"
