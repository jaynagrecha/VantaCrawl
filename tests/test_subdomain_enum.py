"""Subdomain enum must not stall silently — concurrency + progress."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from crawl_stats import CrawlStats  # noqa: E402
from discovery_extra import enumerate_subdomains  # noqa: E402
from vantacrawl_api.services.live_progress import build_live_progress  # noqa: E402


def test_subdomain_enum_concurrent_progress(tmp_path):
    wl = tmp_path / "subs.txt"
    wl.write_text("www\nmail\napi\ndev\n", encoding="utf-8")

    async def exists(url: str) -> bool:
        await asyncio.sleep(0.01)
        return "www" in url

    stats = CrawlStats()
    progress = []

    hits = asyncio.run(
        enumerate_subdomains(
            "example.com",
            str(wl),
            client=None,
            exists_checker=exists,
            output_callback=lambda m: None,
            limit=4,
            concurrency=4,
            update_progress=lambda t, d, text: progress.append((t, d, text)),
            stats=stats,
            probe_timeout=2.0,
        )
    )
    assert any("www.example.com" in u for u in hits)
    assert stats.subdomain_probes_done == 4
    assert stats.subdomain_probes_total == 4
    assert stats.subdomain_hits >= 1
    assert progress
    assert any("Subdomain enum" in str(p[2]) for p in progress)


def test_subdomain_progress_fills_recon_cockpit():
    base = {
        "pages_crawled": 0,
        "links_found": 0,
        "enum_hits": 0,
        "enum_words_tested": 0,
        "enum_words_total": 0,
        "enum_hit_urls": [],
        "bytes_downloaded": 0,
        "errors": 0,
        "queue_size": 0,
        "urls_per_minute": 0.0,
        "status_codes": {},
        "enum_status_codes": {},
        "findings_count": 0,
        "broken_links_count": 0,
        "technologies": {},
        "paused": False,
        "elapsed_seconds": 120.0,
        "backoff_remaining_seconds": 0.0,
        "heartbeat": "",
        "defense": {
            "caught_by_protection": 0,
            "completed_without_challenge": 0,
            "protections_detected": ["cloudflare"],
            "block_journal": [],
            "block_status_counts": {},
            "protection_block_counts": {},
        },
        "findings": [],
        "session_total_estimate": 0,
        "subdomain_probes_done": 120,
        "subdomain_probes_total": 500,
        "subdomain_hits": 2,
        "subdomain_current_host": "mail.irctc.co.in",
        "subdomain_probing": "Subdomain: mail.irctc.co.in · 120/500",
    }
    stats = SimpleNamespace(
        snapshot=lambda: base,
        findings=[],
        session_total_estimate=0,
    )
    out = build_live_progress(
        stats, progress_text="Subdomain enum 120/500 · mail.irctc.co.in", phase="recon"
    )
    assert out["phase"] == "recon"
    assert out["progress_pct"] == 24
    assert out["enum_words_tested"] == 120
    assert out["enum_words_total"] == 500
    assert out["enum_hits"] == 2
    assert "mail.irctc.co.in" in out["enum_probing"]
