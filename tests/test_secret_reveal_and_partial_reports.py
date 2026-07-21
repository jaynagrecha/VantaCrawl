"""Secret reveal helpers + partial report writer."""

from __future__ import annotations

from crawl_stats import CrawlStats
from security_scan import extract_secret_value, mask_secret_value, scan_secrets, secret_reveal_html


def test_scan_secrets_stores_full_value():
    body = 'const key = "AIzaSyD-RealKeyValue0123456789AbCdEfGhI";'
    hits = scan_secrets(body, "https://lab.local/a.js")
    assert hits
    full = hits[0][3]
    assert full.startswith("AIza")
    assert "…" not in full
    assert extract_secret_value(full) == full
    assert "…" in mask_secret_value(full)


def test_secret_reveal_html_masks_until_details():
    html = secret_reveal_html("AIzaSyD-RealKeyValue0123456789AbCdEfGhI")
    assert "secret-masked" in html
    assert "Show full" in html
    assert "AIzaSyD-RealKeyValue0123456789AbCdEfGhI" in html
    assert "…" in html


def test_write_stats_reports_from_partial_stats(tmp_path):
    from reporting import write_stats_reports

    stats = CrawlStats()
    stats.pages_crawled = 2
    stats.record_finding(
        "secrets_exposure",
        "high",
        "https://lab.local/app.js",
        "Google API Key: Possible Google API Key in response body",
        evidence="AIzaSyD-RealKeyValue0123456789AbCdEfGhI",
    )
    paths = write_stats_reports(
        stats,
        report_dir=str(tmp_path),
        start_url="https://lab.local/",
        title="Partial Stop",
    )
    assert paths.get("assessment_report_html") or paths.get("search_report_html")
    html_path = paths.get("assessment_report_html") or paths.get("search_report_html")
    text = open(html_path, encoding="utf-8").read()
    assert "Show full" in text
    assert "AIzaSyD-RealKeyValue0123456789AbCdEfGhI" in text
