from crawl_stats import CrawlStats
from detailed_report import build_report_model, render_detailed_text
from search_report import build_search_conclusion


def _sample_stats() -> CrawlStats:
    stats = CrawlStats()
    stats.pages_crawled = 3
    stats.links_found = 10
    stats.enum_words_tested = 100
    stats.enum_words_total = 1000
    stats.enum_hits = 2
    stats.enum_hit_urls = ["https://example.com/admin", "https://example.com/.env"]
    stats.sensitive_urls = ["https://example.com/.env"]
    stats.record_url("historical", "https://example.com/old")
    stats.record_url("subdomain", "https://api.example.com")
    stats.record_url("js", "https://example.com/app#/dashboard")
    stats.record_url("s3", "https://bucket.s3.amazonaws.com/")
    stats.record_url("vhost", "staging.example.com")
    stats.discovered_urls.update(["https://example.com/", "https://example.com/about"])
    stats.forms.append({"action": "/login", "method": "post", "fields": ["user", "pass"]})
    stats.parameters.append({"name": "id", "url": "https://example.com/x", "source": "query"})
    stats.record_finding("header_audit", "medium", "https://example.com", "Missing Strict-Transport-Security")
    stats.broken_links.append({"url": "https://example.com/missing", "status": "404"})
    stats.technologies["nginx"] += 1
    return stats


def test_record_url_dedupes():
    stats = CrawlStats()
    stats.record_url("s3", "https://a.s3.amazonaws.com/")
    stats.record_url("s3", "https://a.s3.amazonaws.com/")
    assert len(stats.s3_buckets) == 1


def test_detailed_text_has_parts():
    stats = _sample_stats()
    conclusion = build_search_conclusion(
        stats,
        "https://example.com",
        config_meta={
            "profile": "full",
            "download_files": False,
            "security_scan": True,
            "use_wordlist": True,
            "wordlist_file": "big.txt",
            "crawl_concurrency": 4,
            "enum_concurrency": 20,
            "download_concurrency": 5,
        },
    )
    text = conclusion["text"]
    assert "PART A — EXECUTIVE SUMMARY" in text
    assert "PART B — DETAILED RESULTS BY AREA" in text
    assert "PART C — TECHNICAL APPENDIX" in text
    assert "B2. Hidden paths" in text
    assert "https://example.com/admin" in text
    assert "https://api.example.com" in text
    assert "staging.example.com" in text
    assert conclusion["report_model"]["enum_hits"]


def test_build_report_model_counts():
    stats = _sample_stats()
    model = build_report_model(stats, "https://example.com", verdict_title="t", verdict_body="b")
    assert model["discovered_total"] == 2
    assert len(model["enum_hits"]) == 2
    assert "PART A" in render_detailed_text(model)
