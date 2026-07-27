"""Regression: vulnerability-aware active-probe target selection (Horizon Catalog)."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from active_probe_kit import ProbeModeSettings, classify_xss, run_active_probe_kit
from active_probe_targeting import (
    build_probe_plan,
    classify_applicability,
    required_horizon_fixtures,
    selection_coverage_report,
    synthetic_params_for_path,
)
from crawl_stats import CrawlStats
from finding_impact import assess_active_vuln
from report_status import scan_status_from_stats
from security_scan import run_active_vuln_probes


class _Resp:
    def __init__(self, text, headers=None, status=200, url=""):
        self.text = text
        self.headers = headers or {}
        self.status_code = status
        self.url = url or ""


class _RecordingClient:
    def __init__(self):
        self.calls = []

    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        params = dict(params or {})
        self.calls.append(("GET", url, params))
        path = urlparse(url).path or "/"
        joined = " ".join(str(v) for v in params.values())
        # Minimal fixtures so probes complete without false positives.
        if "/sqli/" in path and ("'" in joined or "%27" in joined):
            return _Resp("ok", url=url)
        if "/xss/" in path:
            m = re.search(r"VCXSS_[0-9a-f]+", joined)
            if m:
                return _Resp(f"echo {m.group(0)}", url=url)
        return _Resp("ok", url=url)

    async def post(self, url, data=None, timeout=8, follow_redirects=True):
        self.calls.append(("POST", url, dict(data or {})))
        return _Resp("ok", url=url)


def test_route_semantic_scores_horizon_fixtures():
    fixtures = {
        "/sqli/error": "sqli",
        "/sqli/search": "sqli",
        "/rce/arith": "rce",
        "/cmdi/ping": "rce",
        "/ssti/eval": "ssti",
        "/ssrf/fetch": "ssrf",
        "/crlf": "crlf",
        "/trav/download": "traversal",
        "/xss/browser": "xss",
    }
    for path, family in fixtures.items():
        synth = synthetic_params_for_path(path)
        assert synth, f"expected synthetic params for {path}"
        param = next(iter(synth))
        score, reason = classify_applicability(path=path, param=param, family=family)
        assert reason == "route_semantic_match", (path, family, reason, score)
        assert score >= 80, (path, family, score)


def test_build_probe_plan_prioritises_dedicated_fixtures():
    surface = [
        "https://horizon-catalog.onrender.com/sqli/error",
        "https://horizon-catalog.onrender.com/rce/arith",
        "https://horizon-catalog.onrender.com/cmdi/ping",
        "https://horizon-catalog.onrender.com/ssti/eval",
        "https://horizon-catalog.onrender.com/ssrf/fetch",
        "https://horizon-catalog.onrender.com/crlf",
        "https://horizon-catalog.onrender.com/trav/download",
        "https://horizon-catalog.onrender.com/xss/browser",
        "https://horizon-catalog.onrender.com/mass-assign/profile?name=a",
        "https://horizon-catalog.onrender.com/graphql?query=q",
    ]
    plan = build_probe_plan(
        surface_urls=surface,
        families=("sqli", "rce", "ssti", "ssrf", "traversal", "crlf", "xss"),
        max_generic_per_family=1,
        max_targets_per_family=8,
    )
    by_fam = {}
    for t in plan:
        by_fam.setdefault(t.family, []).append(t)
    # Dedicated fixtures must be selected with route_semantic_match
    for family, paths in required_horizon_fixtures().items():
        hits = [t for t in by_fam.get(family, []) if any(p in t.url for p in paths)]
        assert hits, f"{family} missing dedicated fixture in plan"
        assert any(t.reason == "route_semantic_match" for t in hits), family
    # Generic graphql/mass-assign must not crowd out fixtures for RCE/SSRF/trav
    rce_urls = [urlparse(t.url).path for t in by_fam.get("rce", [])]
    assert any(p in ("/rce/arith", "/cmdi/ping") for p in rce_urls)
    ssrf_urls = [urlparse(t.url).path for t in by_fam.get("ssrf", [])]
    assert "/ssrf/fetch" in ssrf_urls


def test_kit_selects_horizon_fixtures_and_stamps_ledger():
    stats = CrawlStats()
    stats.discovered_urls.update(
        {
            "https://horizon-catalog.onrender.com/sqli/error",
            "https://horizon-catalog.onrender.com/rce/arith",
            "https://horizon-catalog.onrender.com/ssti/eval",
            "https://horizon-catalog.onrender.com/ssrf/fetch",
            "https://horizon-catalog.onrender.com/crlf",
            "https://horizon-catalog.onrender.com/trav/download",
            "https://horizon-catalog.onrender.com/xss/browser",
            "https://horizon-catalog.onrender.com/cmdi/ping",
        }
    )
    client = _RecordingClient()

    async def _run_all():
        urls = [
            "https://horizon-catalog.onrender.com/sqli/error",
            "https://horizon-catalog.onrender.com/rce/arith",
            "https://horizon-catalog.onrender.com/cmdi/ping",
            "https://horizon-catalog.onrender.com/ssti/eval",
            "https://horizon-catalog.onrender.com/ssrf/fetch",
            "https://horizon-catalog.onrender.com/crlf",
            "https://horizon-catalog.onrender.com/trav/download",
            "https://horizon-catalog.onrender.com/xss/browser",
        ]
        for u in urls:
            await run_active_vuln_probes(
                client,
                u,
                max_params=4,
                max_forms=0,
                mode="safe",
                stats=stats,
            )

    asyncio.run(_run_all())
    probes = [
        r
        for r in stats.request_ledger
        if r.get("phase") == "active_probe" and r.get("probe_role") == "probe"
    ]
    assert probes, "expected active probe ledger rows"
    assert all(r.get("target_selection_reason") for r in probes)
    assert all(r.get("result_state") for r in probes)

    def _hit(family_class_substr, path):
        return any(
            path in (r.get("url") or "")
            and family_class_substr in (r.get("probe_class") or r.get("source") or "")
            for r in probes
        )

    assert _hit("sql_injection", "/sqli/error")
    assert _hit("rce", "/rce/arith") or _hit("rce", "/cmdi/ping")
    assert _hit("ssti", "/ssti/eval")
    assert _hit("ssrf", "/ssrf/fetch")
    assert _hit("header_injection", "/crlf")
    assert _hit("directory_traversal", "/trav/download")
    assert _hit("xss", "/xss/browser")

    cov = getattr(stats, "target_selection_coverage", None) or {}
    assert cov.get("status") in ("complete", "partial", "insufficient")
    selected = cov.get("selected_by_family") or {}
    assert selected.get("sqli")
    assert selected.get("rce")
    assert selected.get("ssrf")
    assert selected.get("xss")
    assert selected.get("traversal")
    assert selected.get("crlf")
    assert selected.get("ssti")


def test_attribute_xss_not_confirmed_without_browser():
    cls = classify_xss(
        'x " autofocus onfocus="document.body.dataset.vc=\'VCXSS_abcd1234\'"',
        "VCXSS_abcd1234",
        "baseline",
        payload='" autofocus onfocus="document.body.dataset.vc=\'VCXSS_abcd1234\'',
    )
    assert cls is not None
    assert cls["validation_state"] == "attribute_breakout"
    assert cls["verification"] == "detected"
    detail = (
        "Active xss medium-confidence XSS candidate (attribute/event context; "
        "not browser-confirmed) on form field 'query'"
    )
    impact = assess_active_vuln("xss", detail, "medium")
    assert impact.validation == "unverified"
    assert impact.impact != "confirmed"


def test_api_leak_dedupes_by_route_and_source_asset():
    stats = CrawlStats()
    evidence = "js_route: `/bac/admin` source_asset=`https://h.example/app.js`"
    stats.record_finding(
        "api_leak",
        "medium",
        "https://h.example/",
        "Sensitive route referenced in client bundle: /bac/admin",
        evidence=evidence,
    )
    stats.record_finding(
        "api_leak",
        "medium",
        "https://h.example/redirect",
        "Sensitive route referenced in client bundle: /bac/admin",
        evidence=evidence,
    )
    stats.record_finding(
        "api_leak",
        "medium",
        "https://h.example/other",
        "Sensitive route referenced in client bundle: /bac/admin",
        evidence="js_route: `/bac/admin` source_asset=`https://h.example/other.js`",
    )
    api = [f for f in stats.findings if f["category"] == "api_leak"]
    assert len(api) == 2


def test_split_coverage_marks_incomplete_when_fixtures_missed():
    class FakeStats:
        queue_size = 0
        pages_crawled = 40
        enum_words_total = 100
        enum_words_tested = 100
        finished_at = 1.0
        _remaining_jobs = 0
        enum_edge_blocked = False
        assessment_inconclusive_reason = ""
        target_content_coverage = "ok"
        _scan_status = "final"
        enum_configured = True
        enum_complete = True
        enum_started_at = 1.0
        enum_skip_reason = None
        target_selection_coverage = {
            "status": "insufficient",
            "missing_families": ["rce", "ssrf"],
        }
        active_validation_coverage = "partial"
        api_recon_probes_done = 0
        api_recon_probes_total = 0
        active_probe_coverage = {"xss_browser": "available"}

    status = scan_status_from_stats(FakeStats())
    assert status["assessment_status"] == "incomplete"
    assert status["target_selection_coverage"] == "insufficient"
    assert status["crawl_coverage"] == "complete"
    assert status["enum_coverage"] == "complete"


def test_fixture_path_does_not_spray_unrelated_families():
    """ /sqli/error should not receive RCE/SSRF spray. """
    stats = CrawlStats()
    client = _RecordingClient()

    asyncio.run(
        run_active_vuln_probes(
            client,
            "https://horizon-catalog.onrender.com/sqli/error",
            max_params=6,
            max_forms=0,
            mode="safe",
            stats=stats,
        )
    )
    probes = [
        r
        for r in stats.request_ledger
        if r.get("phase") == "active_probe" and r.get("probe_role") == "probe"
    ]
    classes = {r.get("probe_class") for r in probes}
    assert "sql_injection" in classes
    assert "rce" not in classes
    assert "ssrf" not in classes
    assert all(r.get("target_selection_reason") == "route_semantic_match" for r in probes)
