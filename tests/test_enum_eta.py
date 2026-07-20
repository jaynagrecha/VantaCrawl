"""Enum-phase ETA must not use whole-job elapsed (avoids ~112h ghosts)."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from crawl_stats import CrawlStats
from vantacrawl_api.services.live_progress import build_live_progress


def test_enum_eta_hidden_during_warmup():
    stats = CrawlStats()
    stats.enum_words_total = 14887
    stats.note_enum_progress(35, word="admin", path="/", depth=0)
    assert stats.enum_eta_seconds() is None
    assert stats.enum_probing_label() == "Trying: /admin · level 0"


def test_enum_eta_uses_phase_clock_not_job_clock():
    stats = CrawlStats()
    # Pretend crawl already ran for a long time
    stats.started_at = time.time() - 900
    stats.enum_words_total = 14887
    stats.enum_started_at = time.time() - 20
    stats.enum_words_tested = 400
    stats._enum_rate_samples = [
        (time.time() - 20, 0),
        (time.time() - 10, 200),
        (time.time(), 400),
    ]
    eta = stats.enum_eta_seconds()
    assert eta is not None
    # Phase rate ~20 words/s → remaining ~14487/20 ≈ 12 minutes, not 100+ hours
    assert eta < 6 * 3600


def test_live_progress_enum_eta_and_probing():
    stats = CrawlStats()
    stats.pages_crawled = 134
    stats.session_total_estimate = 134
    stats.enum_words_total = 1000
    stats.enum_started_at = time.time() - 30
    stats.enum_words_tested = 250
    stats.enum_current_word = "backup"
    stats.enum_current_path = "/"
    stats.enum_current_depth = 0
    stats._enum_rate_samples = [(time.time() - 30, 0), (time.time(), 250)]

    out = build_live_progress(stats, progress_text="Trying folder/file names", phase="enum")
    assert out["phase"] == "enum"
    assert out["enum_probing"] == "Trying: /backup · level 0"
    assert out["enum_current_word"] == "backup"
    assert out["eta_seconds"] is not None
    assert out["eta_seconds"] < 6 * 3600
    assert out["progress_pct"] >= 1
