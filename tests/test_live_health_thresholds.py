"""Health / Challenged thresholds for the live cockpit."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from vantacrawl_api.services.live_progress import build_live_progress  # noqa: E402


def _stats(**kwargs):
    base = {
        "pages_crawled": 4,
        "links_found": 10,
        "enum_hits": 0,
        "enum_words_tested": 0,
        "enum_words_total": 0,
        "enum_hit_urls": [],
        "bytes_downloaded": 0,
        "errors": 0,
        "queue_size": 100,
        "urls_per_minute": 5.0,
        "status_codes": {},
        "enum_status_codes": {},
        "findings_count": 0,
        "broken_links_count": 0,
        "technologies": {},
        "paused": False,
        "elapsed_seconds": 60.0,
        "backoff_remaining_seconds": 0.0,
        "heartbeat": "",
        "defense": {
            "caught_by_protection": 4,
            "completed_without_challenge": 0,
            "protections_detected": ["sucuri"],
            "block_journal": [],
            "block_status_counts": {"403": 4},
            "protection_block_counts": {"sucuri": 4},
        },
        "findings": [],
        "session_total_estimate": 192,
    }
    base.update(kwargs)
    return SimpleNamespace(
        snapshot=lambda: base,
        findings=base.get("findings") or [],
        session_total_estimate=base.get("session_total_estimate") or 0,
    )


def test_few_waf_blocks_are_slowing_not_challenged():
    """4 Sucuri 403s used to flip Challenged — too twitchy for real sites."""
    out = build_live_progress(_stats(), progress_text="Progress: 60s elapsed", phase="security")
    assert out["health"] == "Slowing"
    assert out["challenge_events"] == 4


def test_high_block_rate_with_sample_is_challenged():
    defense = {
        "caught_by_protection": 15,
        "completed_without_challenge": 5,
        "protections_detected": ["sucuri"],
        "block_journal": [],
        "block_status_counts": {"403": 15},
        "protection_block_counts": {"sucuri": 15},
    }
    out = build_live_progress(
        _stats(pages_crawled=20, defense=defense),
        progress_text="Progress: 2m elapsed",
        phase="crawl",
    )
    assert out["health"] == "Challenged"
    assert out["challenge_events"] >= 12


def test_absolute_block_floor_is_challenged():
    defense = {
        "caught_by_protection": 25,
        "completed_without_challenge": 400,
        "protections_detected": ["cloudflare"],
        "block_journal": [],
        "block_status_counts": {"403": 25},
        "protection_block_counts": {"cloudflare": 25},
    }
    out = build_live_progress(
        _stats(pages_crawled=425, defense=defense),
        progress_text="Progress: 10m elapsed",
        phase="crawl",
    )
    assert out["health"] == "Challenged"


def test_heartbeat_surfaces_during_backoff():
    out = build_live_progress(
        _stats(backoff_remaining_seconds=4.2, heartbeat="Waiting on WAF backoff… 5s"),
        progress_text="Progress: 60s elapsed",
        phase="security",
    )
    assert out["heartbeat"].startswith("Waiting on WAF backoff")
    assert "Waiting on WAF backoff" in out["health_detail"]


def test_api_recon_fills_cockpit_probe_tiles():
    """During API recon, Enum words / Probing / hits tiles show active probe state."""
    out = build_live_progress(
        _stats(
            pages_crawled=11,
            enum_hits=0,
            enum_words_tested=0,
            enum_words_total=0,
            api_recon_probes_done=272,
            api_recon_probes_total=800,
            api_recon_hits=3,
            api_recon_current_path="/api/v1/users",
            api_recon_probing="API probe: /api/v1/users · 272/800",
            api_recon_eta_seconds=120,
            defense={
                "caught_by_protection": 2,
                "completed_without_challenge": 10,
                "protections_detected": ["akamai"],
                "block_journal": [],
                "block_status_counts": {"403": 2},
                "protection_block_counts": {"akamai": 2},
            },
        ),
        progress_text="API recon 272/800 · /api/v1/users",
        phase="api_recon",
    )
    assert out["phase"] == "api_recon"
    assert out["progress_pct"] == 34  # 272/800
    assert out["enum_words_tested"] == 272
    assert out["enum_words_total"] == 800
    assert out["enum_hits"] == 3
    assert out["enum_current_word"] == "users"
    assert out["enum_current_path"] == "/api/v1/users"
    assert "API probe:" in out["enum_probing"]
    assert out["eta_seconds"] == 120
    assert out["api_recon_probes_done"] == 272
