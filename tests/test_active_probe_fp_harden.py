"""Active / passive injection probe FP hardening + acceptance matrix (#75 follow-up)."""

from __future__ import annotations

import asyncio

from security_scan import (
    _bodies_meaningfully_differ,
    _build_active_proof,
    _classify_active_response,
    _classify_xss_probe,
    _mutation_form_blocked,
    _normalize_probe_text,
    _XSS_BREAKOUT_PAYLOAD,
    _XSS_MARKER,
    run_active_vuln_probes,
    scan_sql_injection,
)


class _Resp:
    def __init__(self, text, headers=None, status=200, url=""):
        self.text = text
        self.headers = headers or {}
        self.status_code = status
        self.url = url or ""


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
        if self.mode == "waf_sql_injection_detected":
            if "'" in joined:
                return _Resp(
                    "Cloudflare WAF blocked: SQL injection detected near quote",
                    status=403,
                )
            return _Resp("Product id 1 details")
        if self.mode == "quote_reflect_no_sql":
            if "'" in joined:
                return _Resp("You searched for: 1'")
            return _Resp("You searched for: 1")
        if self.mode == "nonce_only":
            if "'" in joined:
                return _Resp("ok page nonce=9876 csrf=abcdef12")
            return _Resp("ok page nonce=1234 csrf=abcdef99")
        if self.mode == "ssrf_reflect":
            if "169.254" in joined:
                return _Resp("Invalid URL: http://169.254.169.254/latest/meta-data/")
            return _Resp("ok")
        if self.mode == "ssrf_true":
            if "169.254" in joined:
                return _Resp('{"ami-id":"ami-0abcdef1234567890","instance-id":"i-0123456789abcdef0"}')
            return _Resp("ok")
        if self.mode == "ssrf_waf_echo":
            if "169.254" in joined:
                return _Resp(
                    "Akamai WAF denied request containing 169.254.169.254",
                    status=403,
                )
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
            if "<crawler-xss-probe>" in joined or "data-crawler-xss" in joined:
                return _Resp("hello &lt;crawler-xss-probe&gt; world")
            return _Resp("hello world")
        if self.mode == "xss_breakout":
            if "data-crawler-xss" in joined:
                return _Resp('results: "><img data-crawler-xss="1" src=x> done')
            if "<crawler-xss-probe>" in joined:
                return _Resp("hello &lt;crawler-xss-probe&gt; world")
            return _Resp("hello world")
        if self.mode == "xss_script_context":
            if "<crawler-xss-probe>" in joined:
                return _Resp("<script>var x='<crawler-xss-probe>';</script>")
            return _Resp("<script>var x='';</script>")
        if self.mode == "rce_reflect":
            if "crawler-rce-probe-9f3a" in joined:
                return _Resp("invalid command: ;echo crawler-rce-probe-9f3a")
            return _Resp("ok")
        if self.mode == "rce_true":
            if "crawler-rce-probe-9f3a" in joined:
                return _Resp("output:\ncrawler-rce-probe-9f3a\ndone")
            return _Resp("ok")
        if self.mode == "rce_comment":
            if "crawler-rce-probe-9f3a" in joined:
                return _Resp("<!-- log: crawler-rce-probe-9f3a -->")
            return _Resp("ok")
        return _Resp("ok")

    async def post(self, *a, **k):
        return _Resp("ok")


def _run(mode: str, url: str, forms=None):
    return asyncio.run(
        run_active_vuln_probes(_Client(mode), url, forms=forms, max_params=3, max_forms=2)
    )


def test_active_sqli_baseline_docs_not_fp():
    findings = _run("baseline_sql_docs", "https://x.com/item?id=1")
    assert not any(f[0] == "sql_injection" for f in findings)


def test_active_sqli_failed_baseline_not_fp():
    findings = _run("empty_baseline_then_waf", "https://x.com/item?id=1")
    assert not any(f[0] == "sql_injection" for f in findings)


def test_active_sqli_waf_page_not_sqli():
    findings = _run("waf_sql_injection_detected", "https://x.com/item?id=1")
    assert not any(f[0] == "sql_injection" for f in findings)


def test_active_sqli_quote_reflect_without_error_negative():
    findings = _run("quote_reflect_no_sql", "https://x.com/search?q=shoes")
    assert not any(f[0] == "sql_injection" for f in findings)


def test_active_sqli_nonce_only_negative():
    findings = _run("nonce_only", "https://x.com/item?id=1")
    assert not any(f[0] == "sql_injection" for f in findings)
    assert not _bodies_meaningfully_differ(
        "ok page nonce=1234 csrf=abcdef99",
        "ok page nonce=9876 csrf=abcdef12",
    )


def test_active_sqli_true_positive_with_evidence():
    findings = _run("true_sqli", "https://x.com/item?id=1")
    sqli = [f for f in findings if f[0] == "sql_injection"]
    assert sqli
    assert sqli[0][1] == "high"
    assert "differential" in sqli[0][2].lower()
    assert len(sqli[0]) >= 5 and isinstance(sqli[0][4], dict)
    proof = sqli[0][4]["proof"]
    assert proof["payload_class"] == "sqli_quote"
    assert proof["validation_state"] == "differential_signal"
    assert proof["waf_or_checkpoint"] is False
    assert proof["response_classification"] == "application_response"
    assert proof["baseline_normalized_hash"]
    assert proof["probe_normalized_hash"]
    assert proof["new_evidence"]


def test_active_ssrf_ip_reflection_not_fp():
    findings = _run("ssrf_reflect", "https://x.com/fetch?url=http://example.com")
    assert not any(f[0] == "ssrf" for f in findings)


def test_active_ssrf_waf_echo_not_fp():
    findings = _run("ssrf_waf_echo", "https://x.com/fetch?url=http://example.com")
    assert not any(f[0] == "ssrf" for f in findings)


def test_active_ssrf_metadata_proof_is_tp():
    findings = _run("ssrf_true", "https://x.com/fetch?url=http://example.com")
    ssrf = [f for f in findings if f[0] == "ssrf"]
    assert ssrf and ssrf[0][1] == "high"
    assert "server-side" in ssrf[0][2].lower()
    assert ssrf[0][4]["proof"]["validation_state"] == "confirmed_server_side_behavior"


def test_active_xss_plain_reflection_is_info_not_medium():
    findings = _run("xss_reflect", "https://example.com/search?q=test")
    xss = [f for f in findings if f[0] == "xss"]
    assert xss
    assert xss[0][1] in ("info", "low")
    assert "reflection" in xss[0][2].lower()
    assert xss[0][4]["proof"]["validation_state"] == "reflection_only"


def test_active_xss_entity_encoded_not_fp():
    findings = _run("xss_encoded", "https://example.com/search?q=test")
    assert not any(f[0] == "xss" for f in findings)


def test_active_xss_breakout_is_medium_candidate():
    findings = _run("xss_breakout", "https://example.com/search?q=test")
    xss = [f for f in findings if f[0] == "xss"]
    assert xss
    assert any(f[1] == "medium" for f in xss)
    assert any("breakout" in f[2].lower() for f in xss)


def test_active_xss_script_context_not_browser_confirmed():
    findings = _run("xss_script_context", "https://example.com/search?q=test")
    xss = [f for f in findings if f[0] == "xss"]
    assert xss
    assert xss[0][1] == "medium"
    assert "not browser-confirmed" in xss[0][2].lower()
    assert xss[0][4]["proof"]["validation_state"] == "sink_context_candidate"
    assert xss[0][4]["proof"]["validation_state"] != "confirmed_browser_execution"


def test_active_rce_command_reflection_not_fp():
    findings = _run("rce_reflect", "https://x.com/run?cmd=id")
    assert not any(f[0] == "rce" for f in findings)


def test_active_rce_comment_marker_not_fp():
    findings = _run("rce_comment", "https://x.com/run?cmd=id")
    assert not any(f[0] == "rce" for f in findings)


def test_active_rce_executed_marker_is_tp():
    findings = _run("rce_true", "https://x.com/run?cmd=id")
    rce = [f for f in findings if f[0] == "rce"]
    assert rce and rce[0][1] == "critical"
    assert rce[0][4]["proof"]["validation_state"] == "confirmed_server_side_behavior"


def test_passive_select_word_not_payload_shaped():
    findings = scan_sql_injection(
        "https://x.com/search?q=select+shoes",
        "PostgreSQL ERROR: something unrelated in footer docs",
    )
    assert findings
    assert findings[0][1] == "medium"
    assert "payload-shaped" not in findings[0][2]


def test_passive_quote_still_payload_shaped_high():
    findings = scan_sql_injection(
        "https://x.com/item?id=1'",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert findings and findings[0][1] == "high"


def test_mutation_blacklist_blocks_state_changing_post():
    assert _mutation_form_blocked("https://x.com/account/delete", "POST") is True
    assert _mutation_form_blocked("https://x.com/checkout", "POST") is True
    assert _mutation_form_blocked("https://x.com/search", "POST") is False
    assert _mutation_form_blocked("https://x.com/account/delete", "GET") is False


def test_mutation_blacklist_skips_active_post_probes():
    forms = [
        {
            "action": "https://x.com/account/delete",
            "method": "POST",
            "fields": ["confirm"],
        }
    ]
    findings = _run("true_sqli", "https://x.com/", forms=forms)
    # Only GET URL has no params; form should be skipped — no sqli from form
    assert not any(f[0] == "sql_injection" for f in findings)


def test_classify_encoded_xss_rejected():
    disp = _classify_xss_probe(
        "hello &lt;crawler-xss-probe&gt; world",
        _XSS_MARKER,
        "hello world",
    )
    assert disp is None


def test_classify_waf_response():
    assert (
        _classify_active_response(
            403,
            "Cloudflare WAF blocked: SQL injection detected",
            {"server": "cloudflare"},
        )
        == "generic_waf_deny"
    )


def test_normalize_ignores_nonce_churn():
    a = _normalize_probe_text("Hello nonce=abc12345 csrf=zzz9999")
    b = _normalize_probe_text("Hello nonce=def67890 csrf=yyy1111")
    assert a == b


def test_active_sqli_redirect_change_alone_not_positive():
    """Redirect to /error without a new SQL error is interesting, not SQLi."""

    class _RedirectClient:
        n = 0

        async def get(self, url, params=None, timeout=8, follow_redirects=True):
            params = params or {}
            joined = " ".join(str(v) for v in params.values())
            self.n += 1
            if "'" in joined:
                return _Resp("oops", status=302, url="https://x.com/error")
            return _Resp("search results", status=200, url="https://x.com/search")

        async def post(self, *a, **k):
            return _Resp("ok")

    findings = asyncio.run(
        run_active_vuln_probes(_RedirectClient(), "https://x.com/search?q=shoes", max_params=2, max_forms=0)
    )
    assert not any(f[0] == "sql_injection" for f in findings)


def test_broken_headline_excludes_access_denied():
    from crawl_stats import CrawlStats

    summary = CrawlStats.summarize_broken_links(
        [
            {"url": "https://a/x", "status": "403", "class": "access_denied"},
            {"url": "https://a/y", "status": "404", "class": "not_found"},
            {"url": "https://a/z", "status": "503", "class": "temporary_unavailable"},
        ]
    )
    assert summary["headline_broken"] == 2
    assert summary["unique_access_denied"] == 1
    assert summary["unique_urls"] == 3


def test_build_active_proof_contract():
    proof = _build_active_proof(
        endpoint="https://x.com/item",
        method="GET",
        parameter="id",
        baseline_status=200,
        probe_status=200,
        baseline_body="ok",
        probe_body="SQL syntax error",
        payload_class="sqli_quote",
        new_evidence=["SQL syntax"],
        response_classification="application_response",
        confidence="medium",
        validation_state="differential_signal",
        evidence_line="sql_error: SQL syntax",
    )
    for key in (
        "endpoint",
        "method",
        "parameter",
        "baseline_status",
        "probe_status",
        "baseline_normalized_hash",
        "probe_normalized_hash",
        "payload_class",
        "new_evidence",
        "response_classification",
        "waf_or_checkpoint",
        "confidence",
        "validation_state",
        "request_proof_redacted",
        "response_proof_redacted",
    ):
        assert key in proof
