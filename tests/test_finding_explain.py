from crawl_stats import CrawlStats
from finding_explain import explain_finding, format_finding_group_lines, group_findings_for_report
from search_report import build_search_conclusion


def test_explain_hsts_has_attacker_and_fix():
    expl = explain_finding("header_audit", "missing HSTS")
    assert "HTTPS" in expl["what"] or "HTTPS" in expl["attacker"]
    assert expl["attacker"]
    assert expl["fix"]


def test_group_collapses_same_header():
    findings = [
        {"category": "header_audit", "severity": "medium", "url": "https://a/x", "detail": "missing HSTS"},
        {"category": "header_audit", "severity": "medium", "url": "https://a/y", "detail": "missing HSTS"},
        {"category": "header_audit", "severity": "medium", "url": "https://b/", "detail": "missing HSTS"},
    ]
    groups = group_findings_for_report(findings)
    assert len(groups) == 1
    assert groups[0]["count"] == 3
    assert "attacker" in groups[0]


def test_format_finding_group_includes_paths_and_secret():
    findings = [
        {
            "category": "secrets_exposure",
            "severity": "high",
            "url": "https://lab.local/config.js",
            "detail": "Google API Key: Possible Google API Key in response body",
            "evidence": "AIza…wxyz",
        },
        {
            "category": "sql_injection",
            "severity": "medium",
            "url": "https://lab.local/item?id=1",
            "detail": "SQL error pattern in response",
        },
    ]
    groups = group_findings_for_report(findings)
    lines = []
    for g in groups:
        lines.extend(format_finding_group_lines(g))
    joined = "\n".join(lines)
    assert "Path: https://lab.local/config.js" in joined
    assert "Secret (accessible, masked): AIza…wxyz" in joined
    assert "Path: https://lab.local/item?id=1" in joined


def test_mask_secret_value():
    from security_scan import mask_secret_value, scan_secrets

    assert "…" in mask_secret_value("AKIAIOSFODNN7EXAMPLE")
    body = 'const key = "AIzaSyD-RealKeyValue0123456789AbCdEfGhI";'  # AIza + 35 chars
    hits = scan_secrets(body, "https://x.test/a.js")
    assert hits, "expected a real-looking Google API key to be detected"
    assert hits[0][3]  # evidence present when accessible


def test_record_finding_dedupes_headers_per_host():
    stats = CrawlStats()
    stats.record_finding("header_audit", "medium", "https://lab.local/", "missing HSTS")
    stats.record_finding("header_audit", "medium", "https://lab.local/about", "missing HSTS")
    stats.record_finding("header_audit", "medium", "https://other.local/", "missing HSTS")
    assert len(stats.findings) == 2
    assert stats.finding_repeat_suppressed == 1


def test_search_conclusion_includes_explanations():
    stats = CrawlStats()
    stats.pages_crawled = 3
    stats.record_finding("header_audit", "medium", "https://lab.local/", "missing HSTS")
    stats.enum_hit_urls.append("https://lab.local/admin")
    stats.enum_hits = 1
    conclusion = build_search_conclusion(stats, "https://lab.local/")
    assert "How an attacker could use this" in conclusion["text"]
    assert conclusion["recommendations"]
    assert conclusion["finding_groups"]
