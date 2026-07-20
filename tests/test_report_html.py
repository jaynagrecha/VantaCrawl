"""Interactive dark SaaS search report HTML."""

from crawl_stats import CrawlStats
from report_html import render_search_report_html, short_url, url_table_html
from search_report import build_search_conclusion


def test_short_url_truncates():
    long = "https://example.com/" + ("a" * 120)
    assert "…" in short_url(long)
    assert len(short_url(long)) < len(long)


def test_url_table_has_copy_and_truncation():
    html = url_table_html(["https://example.com/" + ("x" * 100)], limit=5)
    assert "copy-btn" in html
    assert "expand-btn" in html
    assert "url-table" in html


def test_search_report_has_interactive_chrome():
    stats = CrawlStats()
    stats.record_finding("header_audit", "medium", "https://lab.example/", "missing HSTS")
    stats.record_url("subdomain", "https://a.lab.example/")
    stats.emails.append("sec@lab.example")
    conclusion = build_search_conclusion(
        stats,
        "https://lab.example/",
        profile="full",
        config_meta={"profile": "full", "security_scan": True},
    )
    html = render_search_report_html(
        start_url="https://lab.example/",
        base_name="crawl_lab",
        conclusion=conclusion,
        stats=stats,
        profile="full",
    )
    assert "Vanta" in html and "Crawl" in html and "Technical Report" in html
    assert 'id="report-search"' in html
    assert 'id="btn-export"' in html
    assert 'id="btn-collapse"' in html
    assert "sev-filters" in html
    assert 'id="b5b"' in html
    assert 'id="b5c"' in html
    assert "press /" in html.lower() or "press /" in html
