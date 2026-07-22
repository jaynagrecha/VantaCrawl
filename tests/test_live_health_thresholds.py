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


def test_crawl_does_not_keep_sticky_api_enum_hits():
    """Regression: cockpit showed API hit count while Results Enum hits said None yet."""
    prev = {
        "phase": "api_recon",
        "enum_hits": 10,
        "enum_words_tested": 500,
        "enum_words_total": 800,
        "enum_hit_urls": ["https://example.com/api/v1/a"],
        "enum_probing": "API probe: /api/v1/a",
        "enum_current_word": "a",
        "api_recon_hits": 10,
    }
    out = build_live_progress(
        _stats(
            pages_crawled=92,
            enum_hits=0,
            enum_words_tested=0,
            enum_words_total=0,
            enum_hit_urls=[],
            enum_probing="",
            enum_current_word="",
            api_recon_hits=10,
            api_recon_probes_done=800,
            api_recon_probes_total=800,
            findings_count=3,
            findings=[
                {
                    "severity": "High",
                    "detail": "Exposed Boomr API Key in response",
                    "url": "https://www.westernunion.com/",
                    "category": "secrets_exposure",
                    "evidence": "abc",
                }
            ],
            session_total_estimate=1840,
        ),
        progress_text="Page 92 of ~1840 · queue 1840",
        phase="crawl",
        previous=prev,
    )
    assert out["phase"] == "crawl"
    assert out["enum_hits"] == 0
    assert out["enum_hit_urls"] == []
    assert out["enum_words_tested"] == 0
    assert out["api_recon_hits"] == 10
    assert out["findings"] == 3


def test_api_recon_surfaces_hit_urls_in_enum_hit_urls():
    stats = _stats(
        enum_hits=0,
        api_recon_probes_done=10,
        api_recon_probes_total=100,
        api_recon_hits=2,
        api_recon_current_path="/api/health",
        api_recon_probing="API probe: /api/health · 10/100",
    )
    stats.api_endpoint_urls = [  # type: ignore[attr-defined]
        "https://lab.example/api/health",
        "https://lab.example/api/users",
    ]
    out = build_live_progress(
        stats,
        progress_text="API recon 10/100 · /api/health",
        phase="api_recon",
    )
    assert out["enum_hits"] == 2
    assert out["enum_hit_urls"] == [
        "https://lab.example/api/health",
        "https://lab.example/api/users",
    ]


def test_access_deny_surfaces_status_without_waf_blocks():
    """Netlify-style 403s: Blocks stays 0; deny totals stay out of the WAF status strip."""
    defense = {
        "caught_by_protection": 0,
        "completed_without_challenge": 20,
        "protections_detected": [],
        "block_journal": [],
        "block_status_counts": {},
        "access_deny_count": 12,
        "access_deny_status_counts": {"403": 11, "401": 1},
        "access_deny_journal": [
            {
                "url": f"https://app.netlify.app/x{i}.bak",
                "status": 403,
                "signal": "access_deny",
                "protections": [],
                "reason": "HTTP 403 without WAF",
                "time": "12:00:00 IST",
            }
            for i in range(8)
        ],
        "protection_block_counts": {},
    }
    out = build_live_progress(
        _stats(pages_crawled=25, defense=defense),
        progress_text="Progress: 5m elapsed",
        phase="enum",
    )
    assert out["blocks"] == 0
    assert out["challenge_events"] == 0
    assert out["access_deny_count"] == 12
    # WAF status strip must not absorb deny counts (avoids "403×N" looking like bot walls)
    assert not out["block_status_counts"]
    assert out["access_deny_status_counts"].get("403") == 11
    # Tiny sample only — never dump the full deny journal into the panel
    assert out["block_journal"]
    assert len(out["block_journal"]) <= 5
    assert out["block_journal"][0]["signal"] == "access_deny"


<<<<<<< HEAD
def test_credential_cookie_preview_masks_but_keeps_full():
    """possible_credential cookies get Show-full: masked for display, full in evidence_full."""
    from vantacrawl_api.services.live_progress import _findings_preview

    full = "9810abcdef0123456789abcdef8199"
    stats = SimpleNamespace(
        findings=[
            {
                "category": "authentication",
                "severity": "low",
                "url": "https://westernunion.com/",
                "detail": (
                    "Cookie `AKZip` — unclassified but looks like an opaque token. "
                    "Impact: possible_credential."
                ),
                "evidence": full,
                "impact": "possible_credential",
            }
        ]
    )
    preview = _findings_preview(stats)
    assert preview
    row = preview[0]
    assert row["impact"] == "possible_credential"
    assert row["evidence_full"] == full
    assert "…" in row["evidence_masked"]
    assert row["evidence_masked"] != full
    assert row["evidence_masked"].startswith("9810") or "9810" in row["evidence_masked"]
=======
def test_protections_label_keeps_all_fingerprints():
    """Stacked perimeters must not drop later names (e.g. recaptcha) from the tile."""
    names = ["akamai", "cloudflare", "datadome", "perimeterx", "recaptcha"]
    defense = {
        "caught_by_protection": 10,
        "completed_without_challenge": 100,
        "protections_detected": names,
        "block_journal": [],
        "block_status_counts": {"403": 10},
        "protection_block_counts": {"akamai": 10},
        "access_deny_count": 0,
        "access_deny_status_counts": {},
        "access_deny_journal": [],
    }
    out = build_live_progress(
        _stats(pages_crawled=50, defense=defense),
        progress_text="Progress: 5m elapsed",
        phase="crawl",
    )
    assert out["protections"] == names
    assert out["protections_count"] == 5
    assert "recaptcha" in out["protections_label"]
    assert out["protections_label"] == ", ".join(names)
>>>>>>> 7bab9e4 (Show all protection fingerprints in the cockpit tile)
