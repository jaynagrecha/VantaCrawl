"""Production integration tests for active-probe ledger, browser, OOB, traversal, RCE."""

from __future__ import annotations

import asyncio
import re

from active_probe_kit import ProbeModeSettings, build_payload_specs, for_mode, run_active_probe_kit
from crawl_stats import CrawlStats
from oob_callback import OobCallbackCorrelator
from security_scan import run_active_vuln_probes


class _Resp:
    def __init__(self, text, headers=None, status=200, url=""):
        self.text = text
        self.headers = headers or {}
        self.status_code = status
        self.url = url or ""


class _Client:
    def __init__(self, mode: str = "ok"):
        self.mode = mode
        self.n = 0
        self.calls = []

    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        params = params or {}
        self.n += 1
        self.calls.append(("GET", url, dict(params)))
        joined = " ".join(str(v) for v in params.values())
        if self.mode == "xss_breakout":
            m = re.search(r"VCXSS_[0-9a-f]+", joined)
            if m and "<b" in joined:
                tok = m.group(0)
                return _Resp(f'results: "><b id="{tok}">{tok}</b> done', url=url)
            if m and ("onload" in joined or "onfocus" in joined):
                return _Resp(f"attr {joined}", url=url)
            if m:
                return _Resp(f"hello {m.group(0)} world", url=url)
            return _Resp("hello world", url=url)
        if self.mode == "ssrf_reflect":
            return _Resp(f"Invalid URL: {joined}" if "callback" in joined or "http" in joined else "ok", url=url)
        if self.mode == "rce_marker":
            m = re.search(r"VC_RCE_[0-9a-f]+", joined)
            if m and ("printf" in joined or "echo" in joined):
                # Marker appears without command syntax → probable only
                return _Resp(f"output:\n{m.group(0)}\ndone", url=url)
            return _Resp("ok", url=url)
        if self.mode == "rce_arith":
            if "expr" in joined and "7319" in joined:
                return _Resp("value=7603", url=url)
            return _Resp("ok", url=url)
        if self.mode == "trav_canary":
            if "VC_TRAVERSAL_" in joined or "fixture" in joined or "canary.txt" in joined:
                return _Resp("file content CANARY_OK_TOKEN", url=url)
            return _Resp("not found", url=url)
        if self.mode == "waf":
            if "'" in joined or "VCXSS" in joined:
                return _Resp("Cloudflare WAF blocked: SQL injection detected", status=403, url=url)
            return _Resp("ok", url=url)
        if self.mode == "sqli_true":
            if "'" in joined:
                return _Resp("You have an error in your SQL syntax; check the manual", url=url)
            return _Resp("Product id 1 details", url=url)
        return _Resp("ok", url=url)

    async def post(self, *a, **k):
        return _Resp("ok")


def test_active_requests_appear_in_request_ledger():
    stats = CrawlStats()

    async def _run():
        return await run_active_vuln_probes(
            _Client("sqli_true"),
            "https://x.com/item?id=1",
            max_params=3,
            max_forms=0,
            mode="safe",
            stats=stats,
        )

    findings = asyncio.run(_run())
    assert findings
    probe_rows = [r for r in stats.request_ledger if r.get("phase") == "active_probe"]
    assert probe_rows, "expected active_probe ledger rows"
    roles = {r.get("probe_role") for r in probe_rows}
    assert "baseline" in roles
    assert "control" in roles
    assert "probe" in roles
    assert any(r.get("probe_role") == "replay" for r in probe_rows)
    assert all("payload_redacted" in r or r.get("probe_role") == "baseline" for r in probe_rows)
    assert all(r.get("mode") == "safe" for r in probe_rows if r.get("mode"))


def test_xss_cannot_confirm_without_browser_execution():
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("xss_breakout"),
            "https://example.com/search?q=test",
            max_params=4,
            max_forms=0,
            mode="safe",
            browser_evaluate=None,
        )
    )
    xssish = [f for f in findings if f[0] in ("xss", "html_injection")]
    assert xssish
    for f in xssish:
        assert f[4].get("validation") != "confirmed"
        assert f[4]["proof"]["validation_state"] != "browser_execution_confirmed"
        assert f[1] != "high" or "unavailable" in f[2].lower() or f[1] in ("info", "low", "medium")
    # Harmless <b> node → HTML injection low, not XSS medium
    html = [f for f in xssish if f[0] == "html_injection"]
    assert html
    assert html[0][1] == "low"
    assert html[0][4]["proof"]["validation_state"] == "html_injection"


def test_browser_dataset_execution_confirms_xss():
    async def _eval(page_url, js_expr, **kwargs):
        return {
            "executed": True,
            "final_url": page_url,
            "console_errors": [],
            "csp_blocked": [],
            "browser_request_id": "test-browser-1",
            "evidence": "dataset_eval=true",
        }

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
    confirmed = [
        f
        for f in findings
        if f[0] == "xss" and f[4]["proof"]["validation_state"] == "browser_execution_confirmed"
    ]
    assert confirmed
    assert confirmed[0][1] == "high"
    assert confirmed[0][4].get("validation") == "confirmed"
    assert "browser" in confirmed[0][4]["proof"]


def test_callback_url_generation_alone_does_not_confirm_ssrf():
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("ssrf_reflect"),
            "https://x.com/fetch?url=http://example.com",
            max_params=3,
            max_forms=0,
            mode="safe",
            callback_base="https://a81f.callback.vantacrawl-lab.example",
            callback_received=None,
        )
    )
    ssrf = [f for f in findings if f[0] == "ssrf"]
    # May emit unconfirmed probe-sent info, but never oob confirmed
    assert not any(
        f[4]["proof"]["validation_state"] == "oob_callback_confirmed" for f in ssrf if len(f) > 4
    )
    assert not any(f[4].get("validation") == "confirmed" for f in ssrf if len(f) > 4)


def test_correlated_callback_confirms_ssrf():
    oob = OobCallbackCorrelator(scan_id="t1", callback_base="https://cb.example")

    async def _cb(nonce):
        return await oob.received(nonce)

    async def _run():
        # Record event after probes register — simulate callback arriving mid-scan
        client = _Client("ssrf_reflect")

        async def received(nonce):
            oob.record_event(nonce, callback_type="http", request_path=f"/ping/{nonce}")
            return await oob.received(nonce)

        return await run_active_vuln_probes(
            client,
            "https://x.com/fetch?url=http://example.com",
            max_params=3,
            max_forms=0,
            mode="safe",
            callback_base="https://cb.example",
            callback_received=received,
            oob=oob,
        )

    findings = asyncio.run(_run())
    ssrf = [f for f in findings if f[0] == "ssrf"]
    assert any(f[4]["proof"]["validation_state"] == "oob_callback_confirmed" for f in ssrf)
    assert any(f[4].get("validation") == "confirmed" for f in ssrf)


def test_traversal_skips_without_fixture():
    specs = for_mode("safe", nonce="a81f")
    assert not any(s.payload_class.startswith("trav_canary") for s in specs)
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("trav_canary"),
            "https://x.com/view?file=note.txt",
            max_params=4,
            max_forms=0,
            mode="safe",
        )
    )
    assert any(f[0] == "active_probe_coverage" and "skipped" in f[2].lower() for f in findings)
    assert not any(
        f[0] == "directory_traversal" and f[4]["proof"]["validation_state"] == "canary_file_confirmed"
        for f in findings
        if len(f) > 4
    )


def test_traversal_confirms_with_fixture():
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("trav_canary"),
            "https://x.com/view?file=note.txt",
            max_params=4,
            max_forms=0,
            mode="safe",
            traversal_canary_path="../../../../opt/fixtures/canary.txt",
            traversal_canary_expected_content="CANARY_OK_TOKEN",
        )
    )
    trav = [f for f in findings if f[0] == "directory_traversal"]
    assert any(f[4]["proof"]["validation_state"] == "canary_file_confirmed" for f in trav)
    assert any(f[4].get("validation") == "confirmed" for f in trav)


def test_reflected_rce_marker_does_not_confirm():
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("rce_marker"),
            "https://x.com/run?cmd=id",
            max_params=4,
            max_forms=0,
            mode="safe",
        )
    )
    rce = [f for f in findings if f[0] == "rce"]
    assert rce
    for f in rce:
        assert f[4]["proof"]["validation_state"] == "marker_output_signal"
        assert f[4].get("validation") != "confirmed"
        assert f[1] != "critical"


def test_arithmetic_execution_does_confirm():
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("rce_arith"),
            "https://x.com/run?cmd=id",
            max_params=4,
            max_forms=0,
            mode="safe",
        )
    )
    rce = [f for f in findings if f[0] == "rce"]
    assert any(f[4]["proof"]["validation_state"] == "server_execution_confirmed" for f in rce)
    assert any(f[1] == "critical" and f[4].get("validation") == "confirmed" for f in rce)


def test_waf_checkpoint_responses_remain_excluded():
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("waf"),
            "https://x.com/item?id=1",
            max_params=4,
            max_forms=0,
            mode="safe",
        )
    )
    assert not any(f[0] == "sql_injection" for f in findings)


def test_oob_supports_dns_and_http_events():
    oob = OobCallbackCorrelator(scan_id="s", callback_base="https://cb.example")
    oob.register_probe("abcd", probe_id="p1", endpoint="https://t/x", parameter="url")
    oob.record_event("abcd", callback_type="dns", source_ip="1.2.3.4")
    assert oob.has_event("abcd")
    assert oob.get_event("abcd").callback_type == "dns"
    oob.record_event("ef01", callback_type="http", request_path="/ping/ef01")
    assert asyncio.run(oob.received("ef01")) is True


def test_canary_payloads_require_both_path_and_content():
    specs = build_payload_specs(
        ProbeModeSettings(mode="lab", traversal_canary_path="/x", traversal_canary_expected_content=""),
        "a81f",
    )
    assert "trav_canary" not in {s.payload_class for s in specs}
    specs2 = build_payload_specs(
        ProbeModeSettings(
            mode="safe",
            traversal_canary_path="/opt/x/canary.txt",
            traversal_canary_expected_content="OK",
        ),
        "a81f",
    )
    assert "trav_canary" in {s.payload_class for s in specs2}
