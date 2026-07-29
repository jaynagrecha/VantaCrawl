"""Tests for Horizon Catalog acceptance benchmark manifest + evaluation."""

from __future__ import annotations

import asyncio

from crawl_stats import CrawlStats
from horizon_benchmark.evaluate import evaluate_stats, build_coverage_gaps
from horizon_benchmark.manifest import (
    BUCKET_SUPPORTED,
    build_manifest,
    load_catalog_from_playground,
    mandatory_for_mode,
    supported_mandatory_fixtures,
    write_manifest,
)
from security_scan import run_active_vuln_probes


def test_manifest_contains_mandatory_supported_and_controls():
    catalog = load_catalog_from_playground()
    manifest = build_manifest(catalog)
    assert manifest["counts"][BUCKET_SUPPORTED] >= 18
    paths = {r["path"] for r in manifest["routes"] if r.get("mandatory")}
    for required in (
        "/sqli/error",
        "/sqli/safe",
        "/rce/arith",
        "/rce/reflect",
        "/cmdi/ping",
        "/ssti/eval",
        "/ssti/reflect",
        "/ssrf/fetch",
        "/ssrf/reflect",
        "/crlf",
        "/trav/download",
        "/xss/reflected",
        "/xss/encoded",
        "/xss/browser",
        "/redirect",
        "/redirect/safe",
    ):
        assert required in paths, required
    controls = [r for r in supported_mandatory_fixtures() if r["must_not_confirm"]]
    assert {c["path"] for c in controls} >= {
        "/sqli/safe",
        "/rce/reflect",
        "/ssti/reflect",
        "/ssrf/reflect",
        "/xss/encoded",
        "/redirect/safe",
    }
    write_manifest()


def test_mandatory_for_safe_excludes_lab_only():
    manifest = build_manifest(load_catalog_from_playground())
    safe = {r["path"] for r in mandatory_for_mode(manifest, "safe")}
    assert "/sqli/error" in safe
    assert "/xss/browser" not in safe  # lab-only
    assert "/trav/view" not in safe
    lab = {r["path"] for r in mandatory_for_mode(manifest, "lab")}
    assert "/xss/browser" in lab
    assert "/trav/view" in lab


def test_negative_controls_do_not_confirm():
    stats = CrawlStats()
    stats.discovered_urls.update(
        {
            "https://horizon-catalog.onrender.com/sqli/safe",
            "https://horizon-catalog.onrender.com/rce/reflect",
            "https://horizon-catalog.onrender.com/ssti/reflect",
            "https://horizon-catalog.onrender.com/ssrf/reflect",
            "https://horizon-catalog.onrender.com/xss/encoded",
            "https://horizon-catalog.onrender.com/redirect/safe",
        }
    )

    class _Resp:
        def __init__(self, text="ok", status=200, url="", headers=None):
            self.text = text
            self.status_code = status
            self.url = url
            self.headers = headers or {}

    class _Client:
        async def get(self, url, params=None, timeout=8, follow_redirects=True):
            # Echo-safe / encoded / same-origin behaviours
            params = params or {}
            if "/redirect/safe" in url:
                from urllib.parse import urlparse as _up

                nxt = str(params.get("next") or "/")
                parsed = _up(nxt)
                if parsed.scheme or parsed.netloc or nxt.startswith("//"):
                    nxt = "/"
                return _Resp("ok", status=302, url=url, headers={"Location": nxt})
            if "/xss/encoded" in url:
                from html import escape

                q = escape(str(params.get("q") or ""), quote=True)
                return _Resp(f"<p>Results for: {q}</p>", url=url)
            if "/sqli/safe" in url:
                return _Resp("<pre>catalog entry</pre>", url=url)
            if "/rce/reflect" in url:
                return _Resp(f"<pre>cmd={params.get('cmd')}</pre>", url=url)
            if "/ssti/reflect" in url:
                return _Resp(f"<p>Hello {params.get('name')}</p>", url=url)
            if "/ssrf/reflect" in url:
                return _Resp(f"<p>Invalid URL echoed: {params.get('url')}</p>", url=url)
            return _Resp("ok", url=url)

        async def post(self, *a, **k):
            return _Resp("ok")

    async def _run():
        for path in (
            "/sqli/safe",
            "/rce/reflect",
            "/ssti/reflect",
            "/ssrf/reflect",
            "/xss/encoded",
            "/redirect/safe",
        ):
            await run_active_vuln_probes(
                _Client(),
                f"https://horizon-catalog.onrender.com{path}",
                max_params=4,
                max_forms=0,
                mode="safe",
                stats=stats,
            )

    asyncio.run(_run())
    result = evaluate_stats(stats, mode="safe")
    fps = result["summary"]["false_positives"]
    assert not fps, fps
    for row in result["rows"]:
        if row.get("must_not_confirm") and row.get("path") in {
            "/sqli/safe",
            "/rce/reflect",
            "/ssti/reflect",
            "/ssrf/reflect",
            "/xss/encoded",
            "/redirect/safe",
        }:
            assert row.get("confirmed") is False
            assert row.get("probe_sent") is True, row


def test_coverage_gap_for_untested_discovered_fixture():
    stats = CrawlStats()
    stats.discovered_urls.add("https://horizon-catalog.onrender.com/sqli/error")
    # No probes scheduled
    gaps = build_coverage_gaps(stats=stats, mode="safe")
    assert any(g.get("path") == "/sqli/error" and g.get("mandatory") for g in gaps)
    result = evaluate_stats(stats, mode="safe")
    assert result["assessment_complete"] is False
