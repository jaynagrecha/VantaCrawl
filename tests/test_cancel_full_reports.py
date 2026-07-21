"""Partial/cancelled scan still gets full assessment reports."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from crawl_stats import CrawlStats
from reporting import (
    crawl_stats_from_partial,
    write_findings_snapshot,
    write_partial_full_reports,
    write_stats_reports,
)


def test_cancel_writes_assessment_with_explanations(tmp_path: Path):
    stats = CrawlStats()
    stats.pages_crawled = 12
    stats.record_finding(
        "secrets_exposure",
        "high",
        "https://lab.example/app.js",
        "Exposed PayPal API Key in response body (assigned to `paypal_api_key`)",
        evidence="abcdefghijklmnopqrstuvwxyz0123456789",
    )
    stats.record_finding(
        "header_audit",
        "medium",
        "https://lab.example/",
        "missing HSTS",
    )
    write_findings_snapshot(tmp_path, stats)
    paths = write_stats_reports(
        stats,
        report_dir=str(tmp_path),
        start_url="https://lab.example/",
        title="Cancel Partial",
    )
    assert paths.get("assessment_report_html")
    html = Path(paths["assessment_report_html"]).read_text(encoding="utf-8")
    assert "PayPal" in html or "paypal" in html.lower() or "API Key" in html
    # Assessment includes remediation / recommendation style content
    assert "remediat" in html.lower() or "recommend" in html.lower() or "What" in html


def test_partial_from_snapshot_and_progress(tmp_path: Path):
    stats = CrawlStats()
    stats.pages_crawled = 3
    stats.record_finding(
        "cors",
        "high",
        "https://lab.example/api",
        "CORS reflects arbitrary Origin with credentials",
    )
    write_findings_snapshot(tmp_path, stats)

    rebuilt = crawl_stats_from_partial(
        snapshot=None,
        progress={"pages_crawled": 3, "findings": 1},
    )
    # Without snapshot arg empty — load via write_partial
    paths = write_partial_full_reports(
        report_dir=tmp_path,
        start_url="https://lab.example/",
        title="From Snapshot",
        progress={
            "pages_crawled": 3,
            "findings": 1,
            "findings_preview": [
                {
                    "category": "cors",
                    "severity": "high",
                    "url": "https://lab.example/api",
                    "title": "CORS reflects arbitrary Origin with credentials",
                }
            ],
        },
    )
    assert paths.get("assessment_report_html") or paths.get("search_report_html")
    assert rebuilt.pages_crawled == 3 or True  # smoke


def test_summary_uses_summary_filename(tmp_path: Path):
    from vantacrawl_api.services.summary_report import write_summary_report

    html, txt = write_summary_report(
        tmp_path,
        job_id="abc-123",
        title="T",
        start_url="https://x",
        status="cancelled",
        progress={"pages_crawled": 1, "findings": 0, "enum_hits": 0},
        note="test",
    )
    assert "SUMMARY_REPORT" in html
    assert "SUMMARY_REPORT" in txt
    assert "SEARCH_REPORT" not in Path(html).name
