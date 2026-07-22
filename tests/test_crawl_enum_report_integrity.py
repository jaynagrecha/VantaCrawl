"""Crawl/enum/report integrity — concurrent enum state, defense classes, IST+UTC, grouping."""

from __future__ import annotations

import time
from pathlib import Path

from assessment_report import build_assessment_document
from crawl_config import CrawlConfig
from crawl_stats import CrawlStats
from crawl_url_policy import RouteTemplateTracker
from defense_verify import DefenseTracker, classify_defense_event
from finding_explain import group_findings_for_report
from finding_impact import assess_cors
from report_status import scan_status_from_stats
from report_time import format_dual, format_ist, format_utc, timestamp_fields
from reporting import ReportWriter
from tier_security import scan_auth_account_surfaces


def test_timestamps_ist_primary_with_real_utc():
    ts = 1_721_000_000.0  # fixed unix
    ist = format_ist(ts)
    utc = format_utc(ts)
    dual = format_dual(ts)
    assert ist.endswith("IST")
    assert utc.endswith("UTC")
    assert "IST" in dual and "UTC" in dual
    fields = timestamp_fields(ts)
    assert fields["time_ist"].endswith("IST")
    assert fields["time_utc"].endswith("UTC")
    # Must not mislabel IST as UTC
    assert "IST" not in fields["time_utc"]
    assert "UTC" not in fields["time_ist"]


def test_assessment_generated_at_mentions_ist_and_utc():
    stats = CrawlStats()
    doc = build_assessment_document(stats, "https://example.com/", job_title="t", mode="full")
    stamp = str(doc.get("generated_at") or "")
    assert "IST" in stamp
    assert "UTC" in stamp


def test_enum_state_model_configured_not_started():
    stats = CrawlStats()
    stats.enum_configured = True
    stats.enum_complete = False
    stats.enum_skip_reason = None
    stats._directory_enum_enabled = True
    stats._directory_enum_started = False
    stats.enum_words_total = 3000
    stats.enum_words_tested = 0
    stats.pages_crawled = 50
    stats.queue_size = 100
    meta = scan_status_from_stats(stats)
    assert meta["enum_configured"] is True
    assert meta["directory_enum_enabled"] is True
    assert meta["directory_enum_started"] is False
    assert meta.get("enum_skip_reason") in (None, "")


def test_route_template_cap_before_enqueue():
    tracker = RouteTemplateTracker(
        max_instances_per_route_template=2,
        max_locales_per_route_template=2,
        same_locale_only=False,
        start_url="https://example.com/us/en/",
    )
    urls = [
        "https://example.com/us/en/send-money.html",
        "https://example.com/cr/es/send-money.html",
        "https://example.com/gb/en/send-money.html",
        "https://example.com/in/hi/send-money.html",
    ]
    allowed = [u for u in urls if tracker.allow(u)]
    assert len(allowed) == 2
    assert tracker.skipped_variants >= 2


def test_origin_dns_failure_not_bot_catch():
    assert (
        classify_defense_event(
            status_code=503,
            body_preview="503 Service Unavailable - DNS failure",
            signal="",
        )
        == "origin_dns_failure"
    )
    tracker = DefenseTracker(start_url="https://example.com/")
    tracker.record_response(
        url="https://example.com/x",
        status_code=503,
        headers={},
        body_preview="503 Service Unavailable - DNS failure",
    )
    data = tracker.to_dict()
    assert data["origin_failure_count"] >= 1
    assert data["caught_by_protection"] == 0


def test_cors_403_stays_informational():
    proof = {
        "request": "GET /sitemap_index.xml HTTP/1.1\nHost: lab.example\nOrigin: https://evil.example",
        "response": (
            "HTTP/1.1 403\nAccess-Control-Allow-Origin: https://evil.example\n"
            "Access-Control-Allow-Credentials: true"
        ),
    }
    result = assess_cors(
        "CORS reflects arbitrary Origin with credentials",
        "high",
        url="https://lab.example/sitemap_index.xml",
        cookies=[{"name": "session", "host": "lab.example", "role": "auth_session"}],
        proof=proof,
    )
    assert result.severity == "info"
    assert result.impact == "informational"
    assert "403" in result.summary


def test_xss_and_mixed_group_by_evidence():
    sink = "eval(sessionStorage.getItem('x'))"
    evid = f"xss_sink: {sink}"
    findings = []
    for i in range(10):
        findings.append(
            {
                "category": "xss",
                "severity": "info",
                "detail": "Potential DOM execution sink — source-to-sink flow not established",
                "url": f"https://example.com/page{i}",
                "evidence": evid,
            }
        )
    resource = "http://i.po.st/static/v3/post-widget.js"
    for i in range(5):
        findings.append(
            {
                "category": "mixed_content",
                "severity": "medium",
                "detail": f"HTTPS page loads HTTP resource (mixed content): {resource}",
                "url": f"https://example.com/p{i}",
                "evidence": resource,
            }
        )
    groups = group_findings_for_report(findings, max_groups=40)
    xss_groups = [g for g in groups if g["category"] == "xss"]
    mixed_groups = [g for g in groups if g["category"] == "mixed_content"]
    assert len(xss_groups) == 1
    assert xss_groups[0]["count"] == 10
    assert len(mixed_groups) == 1
    assert mixed_groups[0]["count"] == 5


def test_otp_faq_keyword_not_auth_surface():
    hits = scan_auth_account_surfaces(
        "https://example.com/us/en/frequently-asked-questions.html",
        "Customers may use OTP/MFA when logging in. See our fraud awareness tips.",
        forms=[],
    )
    assert hits == []


def test_broken_links_unique_summary():
    rows = [
        {"url": "https://example.com/a", "status": "404", "class": "not_found"},
        {"url": "https://example.com/a", "status": "404", "class": "not_found"},
        {"url": "https://example.com/b", "status": "403", "class": "access_denied"},
        {"url": "https://example.com/c", "status": "error", "class": "fetch_error"},
    ]
    summary = CrawlStats.summarize_broken_links(rows)
    assert summary["rows_total"] == 4
    assert summary["unique_urls"] == 3
    assert summary["unique_404"] == 1
    assert summary["unique_access_denied"] == 1


def test_sqlite_expanded_tables(tmp_path: Path):
    stats = CrawlStats()
    stats.findings.append(
        {
            "category": "xss",
            "severity": "info",
            "url": "https://example.com/",
            "detail": "Potential DOM execution sink — source-to-sink flow not established",
            "time": time.time(),
        }
    )
    stats.broken_links.append(
        {"url": "https://example.com/missing", "status": "404", "class": "not_found"}
    )
    stats.route_templates.append("/{country}/{language}/send-money.html")
    stats.record_request(
        phase="crawl", source="page", url="https://example.com/", status=200, outcome="ok"
    )
    writer = ReportWriter(str(tmp_path), "https://example.com/", title="t")
    db_path = writer.write_sqlite(stats)
    import sqlite3

    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for name in (
        "findings",
        "request",
        "broken_link",
        "route_template",
        "defense_event",
        "form",
        "cookie",
        "enumeration_result",
        "url",
    ):
        assert name in tables
    assert conn.execute("SELECT COUNT(*) FROM request").fetchone()[0] >= 1
    assert conn.execute("SELECT COUNT(*) FROM broken_link").fetchone()[0] == 1
    conn.close()


def test_config_parallel_enum_defaults():
    cfg = CrawlConfig(start_url="https://example.com/")
    assert cfg.enum_parallel_with_crawl is True
    assert cfg.max_instances_per_route_template == 2
    assert cfg.enum_start_after_pages >= 1
