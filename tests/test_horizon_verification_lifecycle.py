"""Strict Horizon acceptance: matching result_state only counts as TP."""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from crawl_stats import CrawlStats
from horizon_benchmark.evaluate import evaluate_fixture_against_stats, evaluate_stats
from horizon_benchmark.manifest import supported_mandatory_fixtures
from security_scan import run_active_vuln_probes


def test_recall_requires_matching_result_state_not_partial():
    stats = CrawlStats()
    path = "https://horizon-catalog.onrender.com/cmdi/ping"
    stats.discovered_urls.add(path)
    stats.record_request(
        phase="active_probe",
        source="rce",
        url=f"{path}?host=x",
        status=200,
        method="GET",
        probe_class="rce",
        probe_name="rce_printf_semi",
        probe_role="probe",
        parameter="host",
        payload_redacted=";printf VC_RCE_ab",
        result_state="negative",
        target_selection_reason="route_semantic_match",
    )
    fix = next(f for f in supported_mandatory_fixtures() if f["path"] == "/cmdi/ping")
    row = evaluate_fixture_against_stats(fix, stats=stats, mode="safe")
    assert row["status"] == "fail"
    assert row["mismatch"] == "expected_execution_confirmed_got_negative"
    assert row["root_cause_stage"] == "response_classification"
    result = evaluate_stats(stats, mode="safe")
    assert result["summary"]["supported_fixture_recall"] < 1.0
    assert any(fn["path"] == "/cmdi/ping" for fn in result["summary"]["false_negatives"])


def test_cmdi_nonce_marker_confirms_execution():
    """Generic VC_RCE_/arith confirmation only — no playground-specific classifier markers."""

    class _Resp:
        def __init__(self, text, headers=None, status=200, url=""):
            self.text = text
            self.headers = headers or {}
            self.status_code = status
            self.url = url or ""

    class _Client:
        async def get(self, url, params=None, timeout=8, follow_redirects=True):
            params = dict(params or {})
            host = str(params.get("host") or "")
            if any(ch in host for ch in ";|&`$"):
                # Simulate shell: echo nonce markers / eval expr from injected command.
                import re

                echoed = re.findall(r"VC_RCE_[A-Za-z0-9_]+", host)
                arith = re.search(r"expr\s+(\d+)\s*\+\s*(\d+)", host)
                lines = [f"$ ping -c 1 {host}", "PLAYGROUND_CMDI_MARKER", "uid=0(root) gid=0(root)"]
                lines.extend(echoed)
                if arith:
                    lines.append(str(int(arith.group(1)) + int(arith.group(2))))
                body = "<pre>" + "\n".join(lines) + "\n</pre>"
            else:
                body = f"<pre>$ ping -c 1 {host}\nPING {host}: 1 packets transmitted</pre>"
            return _Resp(body, url=url)

        async def post(self, *a, **k):
            return _Resp("ok")

    stats = CrawlStats()
    url = "https://horizon-catalog.onrender.com/cmdi/ping"
    stats.discovered_urls.add(url)

    async def _run():
        return await run_active_vuln_probes(
            _Client(),
            url,
            max_params=4,
            max_forms=0,
            mode="safe",
            stats=stats,
        )

    findings = asyncio.run(_run())
    probes = [
        r
        for r in stats.request_ledger
        if r.get("phase") == "active_probe"
        and r.get("probe_role") == "probe"
        and (urlparse(str(r.get("url") or "")).path or "") == "/cmdi/ping"
    ]
    assert probes, "expected CMDI probes"
    assert all(r.get("result_state") for r in probes), probes[:3]
    states = {r.get("result_state") for r in probes}
    assert "execution_confirmed" in states, states
    assert findings, "expected CMDI finding emission"
    # Production classifier must not rely on playground-only strings.
    from active_probe_kit import __dict__ as kit_ns

    assert "_CMDI_EXEC_MARKERS" not in kit_ns


def test_ssrf_without_oob_is_confirmation_unavailable_not_negative():
    class _Resp:
        def __init__(self, text, headers=None, status=200, url=""):
            self.text = text
            self.headers = headers or {}
            self.status_code = status
            self.url = url or ""

    class _Client:
        async def get(self, url, params=None, timeout=8, follow_redirects=True):
            params = dict(params or {})
            u = str(params.get("url") or "")
            if "/ssrf/reflect" in url:
                return _Resp(f"<p>Invalid URL echoed: {u}</p>", url=url)
            return _Resp(
                f"<p>Server-side fetch.</p><pre>url={u}</pre><pre>err=timed out</pre>",
                url=url,
            )

        async def post(self, *a, **k):
            return _Resp("ok")

    stats = CrawlStats()
    fetch = "https://horizon-catalog.onrender.com/ssrf/fetch"
    reflect = "https://horizon-catalog.onrender.com/ssrf/reflect"
    stats.discovered_urls.update({fetch, reflect})

    async def _run():
        await run_active_vuln_probes(_Client(), fetch, max_params=4, max_forms=0, mode="safe", stats=stats)
        await run_active_vuln_probes(_Client(), reflect, max_params=4, max_forms=0, mode="safe", stats=stats)

    asyncio.run(_run())
    fetch_states = {
        r.get("result_state")
        for r in stats.request_ledger
        if r.get("probe_role") == "probe" and "/ssrf/fetch" in str(r.get("url") or "")
    }
    reflect_states = {
        r.get("result_state")
        for r in stats.request_ledger
        if r.get("probe_role") == "probe" and "/ssrf/reflect" in str(r.get("url") or "")
    }
    assert "confirmation_unavailable" in fetch_states, fetch_states
    assert "negative" not in fetch_states or "confirmation_unavailable" in fetch_states
    assert "reflected_only" in reflect_states, reflect_states

    fix = next(f for f in supported_mandatory_fixtures() if f["path"] == "/ssrf/fetch")
    assert fix["expected_result_state"] == "oob_callback_confirmed"
    row = evaluate_fixture_against_stats(fix, stats=stats, mode="safe")
    assert row["status"] == "coverage_gap"
    assert row["mismatch"] == "confirmation_unavailable_not_true_positive"
    assert row["result_state"] == "confirmation_unavailable"
    result = evaluate_stats(stats, mode="safe")
    assert result["summary"]["supported_fixture_recall"] < 1.0
    assert any(
        g["path"] == "/ssrf/fetch"
        for g in result["summary"].get("verification_coverage_gaps") or []
    )
    assert result["assessment_complete"] is False
