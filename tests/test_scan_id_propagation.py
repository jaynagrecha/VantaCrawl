"""Regression: canonical scan_id must exist before probes and survive finalization."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

from active_probe_kit import ProbeModeSettings, run_active_probe_kit
from crawl_stats import CrawlStats
from security_scan import run_active_vuln_probes
from verifiers.runtime.finalize import finalize_phase1_runtime


class _Resp:
    def __init__(self, text="ok", status=200, url="", headers=None):
        self.text = text
        self.status_code = status
        self.url = url or "https://lab.example/ui/xss/view"
        self.headers = headers or {"content-type": "text/html"}


class _Client:
    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        return _Resp(url=url)

    async def post(self, url, data=None, json=None, timeout=8, follow_redirects=True):
        return _Resp(url=url)


def test_run_active_vuln_probes_sets_scan_id_on_stats_before_kit():
    stats = CrawlStats()
    assert stats.scan_id == ""

    async def _run():
        return await run_active_vuln_probes(
            _Client(),
            "https://lab.example/ui/xss/view?q=1",
            forms=[],
            mode="safe",
            stats=stats,
            scan_id="job-uuid-fixed",
            max_params=2,
            max_forms=1,
        )

    asyncio.run(_run())
    assert stats.scan_id == "job-uuid-fixed"
    for row in stats.request_ledger:
        if row.get("phase") == "active_probe":
            assert row.get("scan_id") == "job-uuid-fixed", row


def test_supplied_job_uuid_survives_finalize_without_patching():
    stats = CrawlStats()
    stats.scan_id = "job-uuid-persist"
    stats.discovered_urls.add("https://lab.example/ui/xss/view")
    stats.request_ledger.append(
        {
            "phase": "active_probe",
            "probe_role": "probe",
            "probe_class": "xss",
            "probe_name": "xss_event_onload",
            "probe_id": "xss_event_onload:q:/ui/xss/view:abc",
            "nonce": "VCXSS_aaa",
            "parameter": "q",
            "url": "https://lab.example/ui/xss/view?q=1",
            "result_state": "browser_execution_confirmed",
            "scan_id": "job-uuid-persist",
            "candidate_id": "job-uuid-persist:cand:/ui/xss/view:xss",
        }
    )
    stats.request_ledger.append(
        {
            "phase": "active_probe",
            "probe_role": "browser_execution_confirmed",
            "probe_class": "xss",
            "probe_id": "xss_event_onload:q:/ui/xss/view:abc",
            "nonce": "VCXSS_aaa",
            "parameter": "q",
            "url": "https://lab.example/ui/xss/view?q=1",
            "result_state": "browser_execution_confirmed",
            "browser_context_id": "ctx-1",
            "marker_before": "",
            "marker_after": "VCXSS_aaa",
            "scan_id": "job-uuid-persist",
            "candidate_id": "job-uuid-persist:cand:/ui/xss/view:xss",
            "correlation_reason": "ok",
        }
    )

    class _Cfg:
        active_probe_mode = "lab"
        job_id = "job-uuid-persist"
        report_title = "t"

    with tempfile.TemporaryDirectory() as td:
        out = finalize_phase1_runtime(
            stats, config=_Cfg(), report_dir=td, scan_id="job-uuid-persist"
        )
        assert stats.scan_id == "job-uuid-persist"
        status = json.loads(Path(td, "phase1_runtime_status.json").read_text(encoding="utf-8"))
        assert status["scan_id"] == "job-uuid-persist"
        prov = json.loads(Path(td, "evidence_provenance.json").read_text(encoding="utf-8"))
        ledger = json.loads(Path(td, "request_ledger.json").read_text(encoding="utf-8"))
        for row in ledger:
            if row.get("phase") == "active_probe":
                assert row.get("scan_id") == "job-uuid-persist"
        # Provenance cites same scan_id and confirming candidate_id as ledger
        row = next(e for e in prov if e.get("path") == "/ui/xss/view")
        assert row["scan_id"] == "job-uuid-persist"
        assert row["correlation"]["scan_id"] == "job-uuid-persist"
        assert row["correlation"]["candidate_id"] == "job-uuid-persist:cand:/ui/xss/view:xss"
        assert row["correlation"]["probe_id"] == "xss_event_onload:q:/ui/xss/view:abc"
        assert row["correlation"]["nonce"] == "VCXSS_aaa"


def test_kit_refuses_empty_fallback_identity_collision_across_scans():
    """Two kits with distinct scan_ids must not share candidate prefixes."""
    stats_a = CrawlStats()
    stats_b = CrawlStats()

    async def _one(stats, sid, path):
        settings = ProbeModeSettings(
            mode="safe",
            scan_id=sid,
            stats=stats,
            max_params=2,
            max_forms=1,
        )
        await run_active_probe_kit(
            _Client(),
            f"https://lab.example{path}?q=1",
            forms=[],
            settings=settings,
            body_text="<html></html>",
        )

    asyncio.run(_one(stats_a, "scan-A", "/ui/xss/alpha"))
    asyncio.run(_one(stats_b, "scan-B", "/ui/xss/beta"))
    ids_a = {r.get("candidate_id") for r in stats_a.request_ledger if r.get("candidate_id")}
    ids_b = {r.get("candidate_id") for r in stats_b.request_ledger if r.get("candidate_id")}
    assert ids_a
    assert ids_b
    assert all(str(i).startswith("scan-A:") for i in ids_a)
    assert all(str(i).startswith("scan-B:") for i in ids_b)
    assert ids_a.isdisjoint(ids_b)
    for row in list(stats_a.request_ledger) + list(stats_b.request_ledger):
        if row.get("phase") == "active_probe":
            assert row.get("scan_id") in ("scan-A", "scan-B")
            assert row.get("scan_id")


def test_dom_clobber_about_blank_uses_shared_lock_source():
    """Source audit: negative/replay about:blank must reference selenium_driver_lock."""
    text = Path("dom_clobber/verify.py").read_text(encoding="utf-8")
    assert "selenium_driver_lock" in text
    # The about:blank replay lives inside _run_negative_controls under the lock.
    assert "browser.driver.get(\"about:blank\")" in text
    idx_lock = text.find("with selenium_driver_lock()")
    idx_blank = text.find("browser.driver.get(\"about:blank\")")
    assert idx_lock != -1 and idx_blank != -1
    assert idx_lock < idx_blank
