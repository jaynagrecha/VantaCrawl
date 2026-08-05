"""Regression: vulnerability-aware active-probe target selection (generic)."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from active_probe_kit import ProbeModeSettings, classify_xss, run_active_probe_kit
from active_probe_targeting import (
    build_probe_plan,
    classify_applicability,
    family_fallback_seed_params,
    primary_route_family,
    seed_params_for_path,
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


def test_route_semantic_scores_without_fixture_route_map():
    surfaces = {
        "/app/sqli/error": "sqli",
        "/app/sqli/search": "sqli",
        "/svc/rce/arith": "rce",
        "/svc/cmdi/ping": "rce",
        "/render/ssti/eval": "ssti",
        "/net/ssrf/fetch": "ssrf",
        "/hdr/crlf": "crlf",
        "/files/trav/download": "traversal",
        "/ui/xss/browser": "xss",
    }
    for path, family in surfaces.items():
        assert primary_route_family(path) == family
        seeds, fam, reason = seed_params_for_path(path)
        assert fam == family
        assert reason == "family_fallback_seed"
        assert seeds == family_fallback_seed_params(family)
        param = next(iter(seeds))
        score, why = classify_applicability(path=path, param=param, family=family)
        assert why == "route_semantic_match", (path, family, why, score)
        assert score >= 80, (path, family, score)


def test_no_exact_fixture_route_hardcodes_in_targeting_seeds():
    text = open("active_probe_targeting.py", encoding="utf-8").read()
    for banned in (
        "/xss/reflected",
        "/xss/encoded",
        "/xss/dom-clobber",
        "ROUTE_SYNTHETIC_PARAMS",
        "horizon-catalog",
        "onrender.com",
    ):
        assert banned not in text, banned


def test_build_probe_plan_prioritises_route_semantic_surfaces():
    surface = [
        "https://lab.example/app/sqli/error",
        "https://lab.example/svc/rce/arith",
        "https://lab.example/svc/cmdi/ping",
        "https://lab.example/render/ssti/eval",
        "https://lab.example/net/ssrf/fetch",
        "https://lab.example/hdr/crlf",
        "https://lab.example/files/trav/download",
        "https://lab.example/ui/xss/browser",
        "https://lab.example/nav/redirect",
        "https://lab.example/nav/redirect/safe",
        "https://lab.example/mass-assign/profile?name=a",
        "https://lab.example/graphql?query=q",
    ]
    plan = build_probe_plan(
        surface_urls=surface,
        families=("sqli", "rce", "ssti", "ssrf", "traversal", "crlf", "redirect", "xss"),
        max_generic_per_family=1,
        max_targets_per_family=8,
    )
    by_fam = {}
    for t in plan:
        by_fam.setdefault(t.family, []).append(t)
    for family in ("sqli", "rce", "ssti", "ssrf", "traversal", "crlf", "xss", "redirect"):
        hits = by_fam.get(family) or []
        assert hits, f"{family} missing route-semantic target in plan"
        assert any(
            t.reason in ("route_semantic_match", "family_fallback_seed") for t in hits
        ), family
    rce_urls = [urlparse(t.url).path for t in by_fam.get("rce", [])]
    assert any("rce" in p or "cmdi" in p for p in rce_urls)
    ssrf_urls = [urlparse(t.url).path for t in by_fam.get("ssrf", [])]
    assert any("ssrf" in p for p in ssrf_urls)


def test_kit_selects_route_semantic_surfaces_and_stamps_ledger():
    stats = CrawlStats()
    stats.discovered_urls.update(
        {
            "https://lab.example/app/sqli/error",
            "https://lab.example/svc/rce/arith",
            "https://lab.example/render/ssti/eval",
            "https://lab.example/net/ssrf/fetch",
            "https://lab.example/hdr/crlf",
            "https://lab.example/files/trav/download",
            "https://lab.example/ui/xss/browser",
            "https://lab.example/svc/cmdi/ping",
        }
    )
    client = _RecordingClient()

    async def _run_all():
        urls = [
            "https://lab.example/app/sqli/error",
            "https://lab.example/svc/rce/arith",
            "https://lab.example/svc/cmdi/ping",
            "https://lab.example/render/ssti/eval",
            "https://lab.example/net/ssrf/fetch",
            "https://lab.example/hdr/crlf",
            "https://lab.example/files/trav/download",
            "https://lab.example/ui/xss/browser",
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
    assert probes, "expected active probes"
    families = {r.get("probe_class") for r in probes}
    assert "sqli" in families or any("sqli" in str(r.get("url")) for r in probes)
    # Seeded params should appear for path-only surfaces.
    assert any("q=" in str(r.get("url") or "") or "id=" in str(r.get("url") or "") for r in probes)


def test_selection_coverage_report_is_fixture_path_free():
    plan = build_probe_plan(
        surface_urls=["https://lab.example/app/sqli/error", "https://lab.example/ui/xss/browser"],
        families=("sqli", "xss"),
    )
    report = selection_coverage_report(plan, ["/app/sqli/error", "/ui/xss/browser"])
    assert "required_any_of" not in str(report)
    assert report["status"] in ("complete", "partial", "n/a", "insufficient")


def test_synthetic_params_are_family_level_not_route_map():
    a = synthetic_params_for_path("/any/xss/surface")
    b = synthetic_params_for_path("/other/xss/page")
    assert a == b == family_fallback_seed_params("xss")
