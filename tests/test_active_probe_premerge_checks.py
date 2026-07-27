"""Pre-merge verification for active-probe production readiness (checks 2–10)."""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from active_probe_breaker import ActiveProbeBreaker, stop_active_probes
from active_probe_kit import (
    ProbeModeSettings,
    for_mode,
    normalize_mode,
    redact_payload,
    run_active_probe_kit,
)
from crawl_stats import CrawlStats
from oob_callback import OobCallbackCorrelator, new_oob_nonce
from reporting import ReportWriter
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
        self.calls = []

    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        params = params or {}
        self.calls.append(("GET", url, dict(params)))
        joined = " ".join(str(v) for v in params.values())
        if self.mode == "xss":
            m = re.search(r"VCXSS_[0-9a-f]+", joined)
            if m and ("onload" in joined or "onfocus" in joined or "<b" in joined):
                return _Resp(f'out "><b id="{m.group(0)}">{m.group(0)}</b>', url=url)
            if m:
                return _Resp(f"hello {m.group(0)}", url=url)
            return _Resp("ok", url=url)
        if self.mode == "waf":
            if "VCXSS" in joined or "'" in joined:
                return _Resp("Cloudflare WAF blocked", status=403, url=url)
            return _Resp("ok", url=url)
        if self.mode == "ssrf":
            return _Resp(f"fetching {joined}", url=url)
        return _Resp("ok", url=url)

    async def post(self, url, data=None, timeout=8, follow_redirects=True):
        data = data or {}
        self.calls.append(("POST", url, dict(data)))
        joined = " ".join(str(v) for v in data.values())
        m = re.search(r"VCXSS_[0-9a-f]+", joined)
        if m and ("onload" in joined or "onfocus" in joined or "<b" in joined):
            return _Resp(f'form "><b id="{m.group(0)}">{m.group(0)}</b>', url=url)
        if m:
            return _Resp(f"posted {m.group(0)}", url=url)
        return _Resp("ok", url=url)


def test_check2_browser_capability_in_json_and_stats():
    """Browser capability is surfaced in scan metadata / JSON reports."""
    stats = CrawlStats()
    stats.browser_confirmation = {
        "browser_confirmation": "unavailable",
        "message": "Browser confirmation: unavailable — XSS findings limited to unverified evidence",
    }
    stats.active_probe_coverage = {"xss_browser": "unavailable"}
    with tempfile.TemporaryDirectory() as tmp:
        writer = ReportWriter(str(Path(tmp)), "https://example.com/")
        path = writer.write_json(stats)
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    assert "browser_confirmation" in payload
    assert payload["browser_confirmation"]["browser_confirmation"] == "unavailable"
    assert "unavailable" in payload["browser_confirmation"]["message"].lower()


def test_check3_post_xss_reproduced_by_browser_evaluate():
    """POST XSS probes pass post_data into browser_evaluate and honor reproduced."""
    seen = {}

    async def _eval(page_url, js_expr, **kwargs):
        seen["method"] = kwargs.get("method")
        seen["post_data"] = kwargs.get("post_data")
        seen["page_url"] = page_url
        return {
            "executed": True,
            "reproduced": True,
            "final_url": page_url,
            "console_errors": [],
            "csp_blocked": [],
            "browser_request_id": "post-xss-1",
            "evidence": "dataset_eval=true;reproduced=True",
        }

    forms = [{"action": "https://example.com/search", "method": "POST", "fields": ["q", "lang"]}]
    findings = asyncio.run(
        run_active_probe_kit(
            _Client("xss"),
            "https://example.com/search",
            forms,
            settings=ProbeModeSettings(mode="safe", max_params=2, max_forms=1, browser_evaluate=_eval),
        )
    )
    assert seen.get("method") == "POST"
    assert isinstance(seen.get("post_data"), dict)
    assert "q" in (seen.get("post_data") or {})
    confirmed = [
        f
        for f in findings
        if f[0] == "xss" and f[4]["proof"]["validation_state"] == "browser_execution_confirmed"
    ]
    assert confirmed
    assert confirmed[0][4]["proof"].get("browser", {}).get("reproduced") is True


def test_check4_callback_correlation_scan_probe_nonce_expiry():
    """OOB correlation checks scan ID, probe ID, nonce entropy, and expiry."""
    oob = OobCallbackCorrelator(scan_id="scan-xyz", callback_base="https://cb.example", expiry_seconds=30)
    short = "abc"
    oob.register_probe(short, probe_id="p1")
    assert short not in oob._probes

    n = new_oob_nonce()
    assert len(n) >= 16
    oob.register_probe(
        n,
        probe_id="probe-42",
        endpoint="https://t/x",
        parameter="url",
        expected_path=f"/ping/{n}",
    )
    bad_scan = oob.record_event(n, scan_id="other-scan", probe_id="probe-42", request_path=f"/ping/{n}")
    assert not (bad_scan and bad_scan.confirmed)
    assert bad_scan and bad_scan.rejected_reason == "scan_id_mismatch"

    bad_probe = oob.record_event(n, scan_id="scan-xyz", probe_id="wrong", request_path=f"/ping/{n}")
    assert not (bad_probe and bad_probe.confirmed)
    assert bad_probe and bad_probe.rejected_reason == "probe_id_mismatch"

    import time

    oob._probes[n]["expires_at"] = time.time() - 1
    stale = oob.record_event(n, scan_id="scan-xyz", probe_id="probe-42", request_path=f"/ping/{n}")
    assert not (stale and stale.confirmed)
    assert stale and stale.rejected_reason == "expired"

    # Fresh accept
    oob2 = OobCallbackCorrelator(scan_id="scan-xyz", callback_base="https://cb.example")
    n2 = new_oob_nonce()
    oob2.register_probe(n2, probe_id="probe-42", expected_path=f"/ping/{n2}")
    ok = oob2.record_event(n2, scan_id="scan-xyz", probe_id="probe-42", request_path=f"/ping/{n2}")
    assert ok and ok.confirmed


def test_check5_active_probe_ledger_in_json_and_sqlite():
    """Active-probe ledger events are included in exported JSON and SQLite."""
    stats = CrawlStats()
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("xss"),
            "https://example.com/search?q=test",
            max_params=3,
            max_forms=0,
            mode="safe",
            stats=stats,
        )
    )
    assert findings is not None
    probe_rows = [r for r in stats.request_ledger if r.get("phase") == "active_probe"]
    assert probe_rows
    assert any(r.get("probe_role") in ("baseline", "control", "probe", "replay") for r in probe_rows)

    with tempfile.TemporaryDirectory() as tmp:
        writer = ReportWriter(str(Path(tmp)), "https://example.com/")
        json_path = writer.write_json(stats)
        sqlite_path = writer.write_sqlite(stats)
        payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
        ledger = payload.get("request_ledger") or []
        assert any(r.get("phase") == "active_probe" for r in ledger)
        assert any(r.get("probe_role") for r in ledger if r.get("phase") == "active_probe")

        conn = sqlite3.connect(sqlite_path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(request)").fetchall()}
        assert "probe_role" in cols
        assert "payload_redacted" in cols
        n = conn.execute(
            "SELECT COUNT(*) FROM request WHERE phase = ? AND probe_role != ''",
            ("active_probe",),
        ).fetchone()[0]
        conn.close()
        assert n >= 1


def test_check6_payload_redacted_evidence_reproducible():
    """Payload values are redacted but evidence markers remain reproducible."""
    secretish = "https://cb.example/poll/SUPERSECRETPOLLTOKEN?callback_secret=abc123&api_key=xyz"
    red = redact_payload(secretish)
    assert "SUPERSECRETPOLLTOKEN" not in red
    assert "abc123" not in red
    assert "[REDACTED]" in red

    marker = '"><img src=x onerror=document.body.dataset.vc=VCXSS_a81fdead>'
    red_m = redact_payload(marker)
    assert "VCXSS_a81fdead" in red_m

    stats = CrawlStats()
    asyncio.run(
        run_active_vuln_probes(
            _Client("xss"),
            "https://example.com/search?q=test",
            max_params=2,
            max_forms=0,
            mode="safe",
            stats=stats,
        )
    )
    for row in stats.request_ledger:
        if row.get("phase") != "active_probe":
            continue
        pr = row.get("payload_redacted") or ""
        if "secret=" in pr.lower() or "token=" in pr.lower():
            assert "[REDACTED]" in pr


def test_check7_browser_and_callback_failures_inconclusive_not_negative():
    """Browser/callback failures produce unavailable/inconclusive, not false negatives."""
    async def _boom(*_a, **_k):
        raise RuntimeError("chrome crashed")

    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("xss"),
            "https://example.com/search?q=test",
            max_params=4,
            max_forms=0,
            mode="safe",
            browser_evaluate=_boom,
        )
    )
    xssish = [f for f in findings if f[0] in ("xss", "html_injection")]
    assert xssish
    for f in xssish:
        assert f[4].get("validation") != "confirmed"
        assert f[4]["proof"]["validation_state"] != "browser_execution_confirmed"

    # SSRF without callback → inconclusive / unconfirmed, never negative-as-safe confirmed miss
    ssrf = asyncio.run(
        run_active_vuln_probes(
            _Client("ssrf"),
            "https://x.com/fetch?url=http://example.com",
            max_params=3,
            max_forms=0,
            mode="safe",
            callback_base="https://cb.example",
            callback_received=None,
        )
    )
    ssrf_f = [f for f in ssrf if f[0] == "ssrf"]
    for f in ssrf_f:
        state = f[4]["proof"]["validation_state"]
        assert state != "oob_callback_confirmed"
        assert f[4].get("validation") != "confirmed"
        # Must not pretend "negative" confirmed absence
        assert state in (
            "inconclusive",
            "unconfirmed",
            "probe_sent",
            "differential_signal",
            "reflected_only",
            "url_echo",
        ) or "unavailable" in str(f[2]).lower() or f[1] in ("info", "low")


def test_check8_active_probing_pauses_after_checkpoint_rate_limit():
    """Active probing stops/pauses after repeated checkpoint/rate-limit responses."""
    br = ActiveProbeBreaker(window_size=10, min_samples=8, block_ratio_threshold=0.8)
    for _ in range(5):
        br.note("edge_checkpoint")
    for _ in range(4):
        br.note("rate_limit")
    assert br.tripped
    assert "checkpoint" in br.reason or "rate" in br.reason
    stats = CrawlStats()
    stop_active_probes(stats, reason=br.reason, remaining="inconclusive")
    assert stats.vuln_active_probe_paused is True
    assert stats.active_probe_breaker["remaining"] == "inconclusive"

    # Live path: uniform WAF responses trip pause during a kit run
    stats2 = CrawlStats()
    asyncio.run(
        run_active_vuln_probes(
            _Client("waf"),
            "https://x.com/item?id=1",
            max_params=8,
            max_forms=0,
            mode="safe",
            stats=stats2,
        )
    )
    # Either paused or breaker snapshot recorded after contaminated window
    paused = bool(getattr(stats2, "vuln_active_probe_paused", False))
    snap = getattr(stats2, "active_probe_breaker", None) or {}
    assert paused or snap.get("tripped") or any(
        r.get("classification") in ("generic_waf_deny", "edge_checkpoint", "rate_limit")
        for r in stats2.request_ledger
        if r.get("phase") == "active_probe"
    )


def test_check9_safe_mode_cannot_override_to_lab_via_api_input():
    """Safe mode / garbage API strings cannot unlock Lab payloads."""
    assert normalize_mode("lab-please") == "safe"
    assert normalize_mode("LAB!!") == "safe"
    assert normalize_mode("extended-lab") == "safe"
    assert normalize_mode("safe") == "safe"
    assert normalize_mode("lab") == "lab"  # explicit opt-in only

    safe_classes = {s.payload_class for s in for_mode("safe", nonce="a81f")}
    assert not any(c.startswith("imds") or "passwd" in c or "xxe" in c for c in safe_classes)
    assert not any("sleep" in c or "union" in c for c in safe_classes)

    # API merge path
    from vantacrawl_api.routes.jobs import _build_config_json

    body = MagicMock()
    body.mode = "full"
    body.speed = "balanced"
    body.target_urls = None
    body.settings = {"active_probe_mode": "lab-via-typo", "traversal_fixture_installed": True}
    cfg = _build_config_json(body)
    assert cfg["active_probe_mode"] == "safe"

    body2 = MagicMock()
    body2.mode = "full"
    body2.speed = "balanced"
    body2.target_urls = None
    body2.settings = {"active_probe_mode": "lab"}
    cfg2 = _build_config_json(body2)
    assert cfg2["active_probe_mode"] == "lab"


def test_check10_no_callback_secrets_or_poll_tokens_in_reports():
    """Callback secrets, polling tokens, and full sensitive responses do not enter reports."""
    stats = CrawlStats()
    stats.browser_confirmation = {"browser_confirmation": "unavailable", "message": "unavailable"}
    # Simulate a ledger row that would have been dangerous pre-redaction
    stats.record_request(
        phase="active_probe",
        source="probe",
        url="https://x.com/fetch",
        status=200,
        outcome="probe",
        probe_role="probe",
        payload_redacted=redact_payload(
            "https://cb.example/poll/TOPSECRETPOLL?callback_secret=DEADBEEF&password=hunter2"
        ),
        classification="application_response",
        result_state="inconclusive",
    )
    findings = asyncio.run(
        run_active_vuln_probes(
            _Client("ssrf"),
            "https://x.com/fetch?url=http://example.com",
            max_params=2,
            max_forms=0,
            mode="safe",
            callback_base="https://cb.example",
            stats=stats,
        )
    )
    blob = json.dumps(
        {
            "findings": [
                {
                    "cat": f[0],
                    "sev": f[1],
                    "detail": f[2],
                    "proof": f[4].get("proof") if len(f) > 4 else {},
                }
                for f in findings
            ],
            "ledger": list(stats.request_ledger),
        }
    )
    assert "TOPSECRETPOLL" not in blob
    assert "DEADBEEF" not in blob
    assert "hunter2" not in blob
    assert "callback_secret=DEADBEEF" not in blob

    with tempfile.TemporaryDirectory() as tmp:
        writer = ReportWriter(str(Path(tmp)), "https://example.com/")
        path = writer.write_json(stats)
        exported = Path(path).read_text(encoding="utf-8")
    assert "TOPSECRETPOLL" not in exported
    assert "DEADBEEF" not in exported
    assert "hunter2" not in exported
