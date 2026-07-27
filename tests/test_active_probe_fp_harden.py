"""Safe Active mini-payload kit + FP acceptance matrix."""

from __future__ import annotations

import asyncio
import re

from active_probe_kit import (
    ProbeModeSettings,
    build_payload_specs,
    classify_response,
    classify_xss,
    new_probe_nonce,
    normalize_mode,
    normalize_probe_text,
    run_active_probe_kit,
)
from crawl_stats import CrawlStats
from security_scan import run_active_vuln_probes, scan_sql_injection


class _Resp:
    def __init__(self, text, headers=None, status=200, url=""):
        self.text = text
        self.headers = headers or {}
        self.status_code = status
        self.url = url or ""


class _Client:
    """Mode-driven fake origin for acceptance fixtures."""

    def __init__(self, mode: str):
        self.mode = mode
        self.n = 0

    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        params = params or {}
        joined = " ".join(str(v) for v in params.values())
        self.n += 1

        if self.mode == "baseline_sql_docs":
            return _Resp("Docs: PostgreSQL ERROR example. nonce=111")
        if self.mode == "empty_baseline_then_waf":
            if self.n == 1:
                raise RuntimeError("timeout")
            return _Resp("WAF blocked: possible SQL syntax attack", status=403)
        if self.mode == "waf_sql_injection_detected":
            if "'" in joined:
                return _Resp(
                    "Cloudflare WAF blocked: SQL injection detected near quote",
                    status=403,
                )
            return _Resp("Product id 1 details")
        if self.mode == "quote_reflect_no_sql":
            if "'" in joined:
                return _Resp(f"You searched for: {joined}")
            return _Resp("You searched for: shoes")
        if self.mode == "nonce_only":
            return _Resp(f"ok page nonce={self.n} csrf=abcdef{self.n:02d}")
        if self.mode == "true_sqli":
            if "'" in joined:
                return _Resp("You have an error in your SQL syntax; check the manual")
            return _Resp("Product id 1 details")
        if self.mode == "bool_sqli":
            if "1=1" in joined or "'1'='1" in joined:
                return _Resp("RESULTS: many rows here alpha")
            if "1=2" in joined or "'1'='2" in joined:
                return _Resp("RESULTS: zero rows")
            return _Resp("RESULTS: default listing")
        if self.mode == "xss_reflect":
            m = re.search(r"VCXSS_[0-9a-f]+", joined)
            if m and "<b" not in joined and "svg" not in joined and "onfocus" not in joined:
                return _Resp(f"hello {m.group(0)} world")
            return _Resp("hello world")
        if self.mode == "xss_encoded":
            m = re.search(r"VCXSS_[0-9a-f]+", joined)
            if m:
                tok = m.group(0)
                # Fully entity-encoded — token only appears inside &lt;…&gt;
                return _Resp(f"hello &lt;{tok}&gt; world")
            return _Resp("hello world")
        if self.mode == "xss_breakout":
            m = re.search(r"VCXSS_[0-9a-f]+", joined)
            if m and "<b" in joined:
                tok = m.group(0)
                return _Resp(f'results: "><b id="{tok}">{tok}</b> done')
            return _Resp("hello world")
        if self.mode == "ssrf_reflect":
            if "169.254" in joined or "callback" in joined:
                return _Resp(f"Invalid URL: {joined}")
            return _Resp("ok")
        if self.mode == "ssrf_imds":
            if "169.254" in joined:
                return _Resp('{"ami-id":"ami-0abcdef1234567890","instance-id":"i-0123456789abcdef0"}')
            return _Resp("ok")
        if self.mode == "rce_reflect":
            if "VC_RCE_" in joined or "7319" in joined:
                return _Resp(f"invalid command: {joined}")
            return _Resp("ok")
        if self.mode == "rce_true":
            if "printf" in joined or "echo" in joined:
                m = re.search(r"VC_RCE_[0-9a-f]+", joined)
                if m:
                    return _Resp(f"output:\n{m.group(0)}\ndone")
            if "expr" in joined:
                return _Resp("7603")
            return _Resp("ok")
        if self.mode == "ssti_true":
            if "7319" in joined and "284" in joined:
                # Evaluated — result only
                return _Resp("value=7603")
            return _Resp("value=ok")
        if self.mode == "ssti_reflect":
            if "7319" in joined:
                return _Resp(f"echo: {joined}")
            return _Resp("ok")
        if self.mode == "trav_canary":
            if "VC_TRAVERSAL_" in joined and "vantacrawl-fixtures" in joined:
                m = re.search(r"VC_TRAVERSAL_([0-9a-f]+)", joined)
                if m:
                    return _Resp(f"file content VC_TRAVERSAL_PROOF_{m.group(1)}")
            return _Resp("not found")
        if self.mode == "crlf_true":
            # Simulate injected response header (scanner checks headers, not body)
            m = re.search(r"X-VantaCrawl-Proof:%20([0-9a-f]+)", joined) or re.search(
                r"X-VantaCrawl-Proof: ([0-9a-f]+)", joined
            )
            # Payload arrives URL-encoded in param value
            raw = " ".join(str(v) for v in params.values())
            if "X-VantaCrawl-Proof" in raw or "%0d%0aX-VantaCrawl" in raw.lower() or "%0d%0ax-vantacrawl" in raw.lower():
                # Extract nonce from payload
                nm = re.search(r"Proof:%20([0-9a-f]+)", raw) or re.search(r"Proof%3A%20([0-9a-f]+)", raw)
                nonce = nm.group(1) if nm else "dead"
                # Also try trailing hex after Proof
                if not nm:
                    nm2 = re.search(r"([0-9a-f]{4})$", raw.replace("%20", " "))
                    nonce = nm2.group(1) if nm2 else "dead"
                return _Resp("ok", headers={"X-VantaCrawl-Proof": nonce})
            return _Resp("ok")
        if self.mode == "redirect_true":
            if "redirect-proof.vantacrawl-lab.example" in joined:
                return _Resp(
                    "",
                    status=302,
                    headers={"Location": f"https://redirect-proof.vantacrawl-lab.example/x"},
                    url="https://x.com/go",
                )
            return _Resp("ok", url="https://x.com/go")
        return _Resp("ok")

    async def post(self, *a, **k):
        return _Resp("ok")


def _run(mode: str, url: str, *, probe_mode: str = "safe", forms=None, **kwargs):
    return asyncio.run(
        run_active_vuln_probes(
            _Client(mode),
            url,
            forms=forms,
            max_params=6,
            max_forms=2,
            mode=probe_mode,
            **kwargs,
        )
    )


def test_mode_normalize():
    assert normalize_mode("SAFE") == "safe"
    assert normalize_mode("lab") == "lab"
    assert normalize_mode("off") == "passive"


def test_safe_payloads_include_mini_set_not_destructive():
    specs = build_payload_specs(ProbeModeSettings(mode="safe", callback_base="https://cb.example"), "a81f")
    classes = {s.payload_class for s in specs}
    assert "sqli_quote" in classes
    assert "sqli_bool_true_str" in classes
    assert "xss_reflect" in classes
    assert "xss_html_breakout" in classes
    assert "rce_printf_semi" in classes
    assert "rce_expr" in classes
    assert "ssti_jinja" in classes
    assert "ssrf_callback_ping" in classes
    assert "trav_canary" in classes
    assert "crlf_header" in classes
    assert "redirect_abs" in classes
    # Safe must NOT include destructive / IMDS / passwd / XXE
    assert "ssrf_imds_lab" not in classes
    assert "trav_passwd_lab" not in classes
    assert "xxe_oob" not in classes
    joined = " ".join(s.payload for s in specs)
    assert "DROP" not in joined.upper()
    assert "UNION SELECT" not in joined.upper()
    assert "169.254.169.254" not in joined


def test_lab_adds_deeper_and_imds_passwd_xxe():
    specs = build_payload_specs(
        ProbeModeSettings(mode="lab", callback_base="https://cb.example"), "a81f"
    )
    classes = {s.payload_class for s in specs}
    assert "ssrf_imds_lab" in classes
    assert "trav_passwd_lab" in classes
    assert "xxe_oob" in classes
    assert "sqli_lab_or_true" in classes


def test_active_sqli_true_positive():
    findings = _run("true_sqli", "https://x.com/item?id=1")
    sqli = [f for f in findings if f[0] == "sql_injection"]
    assert sqli
    assert any("differential" in f[2].lower() for f in sqli)
    assert sqli[0][4]["proof"]["validation_state"] == "differential_signal"


def test_active_sqli_boolean_split():
    findings = _run("bool_sqli", "https://x.com/item?id=1")
    assert any(f[0] == "sql_injection" and "boolean" in f[2].lower() for f in findings)


def test_active_sqli_baseline_docs_not_fp():
    assert not any(f[0] == "sql_injection" for f in _run("baseline_sql_docs", "https://x.com/item?id=1"))


def test_active_sqli_waf_not_fp():
    assert not any(
        f[0] == "sql_injection" for f in _run("waf_sql_injection_detected", "https://x.com/item?id=1")
    )


def test_active_sqli_failed_baseline_not_fp():
    assert not any(
        f[0] == "sql_injection" for f in _run("empty_baseline_then_waf", "https://x.com/item?id=1")
    )


def test_active_sqli_quote_reflect_negative():
    assert not any(
        f[0] == "sql_injection" for f in _run("quote_reflect_no_sql", "https://x.com/search?q=shoes")
    )


def test_active_sqli_nonce_only_negative():
    assert not any(f[0] == "sql_injection" for f in _run("nonce_only", "https://x.com/item?id=1"))
    assert normalize_probe_text("ok page nonce=1 csrf=abcdef01") == normalize_probe_text(
        "ok page nonce=9 csrf=abcdef99"
    )


def test_active_xss_plain_reflection_info():
    findings = _run("xss_reflect", "https://example.com/search?q=test")
    xss = [f for f in findings if f[0] == "xss"]
    assert xss
    assert xss[0][1] in ("info", "low")
    assert xss[0][4]["proof"]["validation_state"] == "reflected_only"


def test_active_xss_encoded_negative():
    assert not any(f[0] == "xss" for f in _run("xss_encoded", "https://example.com/search?q=test"))


def test_active_xss_dom_node_medium():
    findings = _run("xss_breakout", "https://example.com/search?q=test")
    xss = [f for f in findings if f[0] == "xss"]
    assert any(f[1] == "medium" for f in xss)
    assert any("dom" in f[2].lower() or "breakout" in f[2].lower() for f in xss)


def test_active_xss_browser_confirm_optional():
    async def _eval(url, expr):
        return True

    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("xss_breakout"),
            "https://example.com/search?q=test",
            max_params=4,
            max_forms=0,
            mode="safe",
            browser_evaluate=_eval,
        )
    )
    # Browser confirm may fire on event payloads if body still has token
    assert isinstance(findings, list)


def test_safe_mode_skips_imds():
    findings = _run("ssrf_imds", "https://x.com/fetch?url=http://example.com", probe_mode="safe")
    assert not any(f[0] == "ssrf" for f in findings)


def test_lab_mode_imds_proof():
    findings = _run("ssrf_imds", "https://x.com/fetch?url=http://example.com", probe_mode="lab")
    assert any(f[0] == "ssrf" and f[1] == "high" for f in findings)


def test_ssrf_callback_confirm():
    async def _cb(nonce):
        return True

    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("ssrf_reflect"),
            "https://x.com/fetch?url=http://example.com",
            max_params=3,
            max_forms=0,
            mode="safe",
            callback_base="https://a81f.callback.vantacrawl-lab.example",
            callback_received=_cb,
        )
    )
    assert any(f[0] == "ssrf" for f in findings)
    assert any(
        f[4]["proof"]["validation_state"] == "out_of_band_callback_confirmed"
        for f in findings
        if f[0] == "ssrf" and len(f) > 4
    )


def test_ssrf_url_echo_without_callback_negative():
    findings = _run(
        "ssrf_reflect",
        "https://x.com/fetch?url=http://example.com",
        probe_mode="safe",
        callback_base="https://cb.example",
    )
    # No callback_received → must not confirm
    assert not any(f[0] == "ssrf" for f in findings)


def test_rce_reflection_negative():
    assert not any(f[0] == "rce" for f in _run("rce_reflect", "https://x.com/run?cmd=id"))


def test_rce_marker_and_arith_positive():
    findings = _run("rce_true", "https://x.com/run?cmd=id")
    assert any(f[0] == "rce" for f in findings)


def test_ssti_evaluated_positive():
    findings = _run("ssti_true", "https://x.com/page?name=x")
    assert any(f[0] == "ssti" for f in findings)


def test_ssti_raw_reflection_negative():
    assert not any(f[0] == "ssti" for f in _run("ssti_reflect", "https://x.com/page?name=x"))


def test_traversal_canary_positive():
    findings = _run("trav_canary", "https://x.com/view?file=note.txt")
    assert any(f[0] == "directory_traversal" for f in findings)


def test_crlf_header_confirm():
    findings = _run("crlf_true", "https://x.com/search?q=test")
    assert any(f[0] == "header_injection" for f in findings)


def test_open_redirect_confirm():
    findings = _run("redirect_true", "https://x.com/go?next=/home")
    assert any(f[0] == "open_redirect" for f in findings)


def test_passive_select_word_not_payload_shaped():
    findings = scan_sql_injection(
        "https://x.com/search?q=select+shoes",
        "PostgreSQL ERROR: something unrelated in footer docs",
    )
    assert findings and findings[0][1] == "medium"


def test_passive_quote_still_payload_shaped_high():
    findings = scan_sql_injection(
        "https://x.com/item?id=1'",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert findings and findings[0][1] == "high"


def test_waf_classify():
    assert (
        classify_response(403, "Cloudflare WAF blocked: SQL injection detected", {"server": "cloudflare"})
        == "generic_waf_deny"
    )


def test_broken_headline_still_ok():
    summary = CrawlStats.summarize_broken_links(
        [
            {"url": "https://a/x", "status": "403", "class": "access_denied"},
            {"url": "https://a/y", "status": "404", "class": "not_found"},
        ]
    )
    assert summary["headline_broken"] == 1


def test_classify_xss_encoded_none():
    assert classify_xss("hello &lt;VCXSS_a81f&gt;", "VCXSS_a81f", "hello") is None


def test_passive_mode_sends_nothing():
    findings = _run("true_sqli", "https://x.com/item?id=1", probe_mode="passive")
    assert findings == []
