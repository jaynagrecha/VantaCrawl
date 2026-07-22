from crawl_stats import CrawlStats
from user_output import (
    format_duration_friendly,
    format_friendly_finding,
    format_friendly_hits,
    format_friendly_stats,
    simplify_log_line,
)


def test_simplify_hit_line():
    line = simplify_log_line("HIT [403] https://example.com/.env (size=1234)")
    assert "Found hidden path" in line
    assert "https://example.com/.env" in line
    assert "HTTP 403" in line
    assert "blocked" in line


def test_simplify_finding_line():
    line = simplify_log_line(
        "FINDING [high] sql_injection: https://example.com?id=1 — SQL error pattern in response body"
    )
    assert "Important" in line
    assert "SQL injection" in line
    assert "example.com" in line


def test_simplify_stats_line():
    line = simplify_log_line("[Stats] crawled=10 found=25 enum=2 tested=100/500 queue=3 12.0/min errors=1 findings=4")
    assert line.startswith("Progress:")
    assert "10 page" in line
    assert "2 hidden" in line


def test_format_duration_friendly():
    assert format_duration_friendly(9) == "9s"
    assert format_duration_friendly(75) == "1m 15s"
    assert format_duration_friendly(3661) == "1h 01m"


def test_friendly_stats():
    stats = CrawlStats()
    stats.pages_crawled = 5
    stats.enum_hits = 1
    stats.enum_words_tested = 50
    stats.enum_words_total = 100
    line = format_friendly_stats(stats)
    assert "Progress:" in line
    assert "elapsed" in line
    assert "50%" in line or "50 of 100" in line


def test_stats_mark_finished_freezes_elapsed():
    stats = CrawlStats()
    stats.started_at = stats.started_at - 12.5
    first = stats.mark_finished()
    assert first >= 12
    frozen = stats.elapsed_seconds()
    assert abs(frozen - first) < 0.01
    assert "elapsed" in format_friendly_stats(stats)


def test_friendly_hits_empty():
    text = format_friendly_hits([])
    assert "No hidden" in text


def test_friendly_finding():
    text = format_friendly_finding(
        {"severity": "high", "category": "xss", "url": "https://x.com", "detail": "payload reflected"}
    )
    assert "Important" in text
    assert "cross-site scripting" in text
