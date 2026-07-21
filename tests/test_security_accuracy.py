"""False-positive / false-negative accuracy tests for security + enum filters."""

from crawl_config import CrawlConfig
from crawl_stats import CrawlStats
from enum_engine import ProbeResult, WildcardProfile, build_status_filter, is_probe_hit
from false_positive_store import FalsePositiveStore
from security_scan import (
    check_cors,
    mask_secret_value,
    scan_api_leaks,
    scan_directory_traversal,
    scan_rce,
    scan_secrets,
    scan_sensitive_path,
    scan_sql_injection,
    scan_ssrf,
    scan_xss,
)


def test_sql_name_only_not_medium_fp():
    findings = scan_sql_injection("https://shop.example/search?q=laptop&id=1", "Welcome to our shop")
    assert not any(f[0] == "sql_injection" and f[1] in ("medium", "high") for f in findings)


def test_sql_error_still_detected():
    findings = scan_sql_injection(
        "https://x.com/page?id=1",
        "Warning: mysql_fetch_array(): SQL syntax error near",
    )
    assert any(f[0] == "sql_injection" and f[1] == "high" for f in findings)


def test_ssrf_relative_next_not_fp():
    findings = scan_ssrf("https://app.example/login?next=/dashboard")
    assert findings == []


def test_ssrf_internal_url_detected():
    findings = scan_ssrf("https://app.example/fetch?url=http://127.0.0.1:8080/admin")
    assert any(f[0] == "ssrf" and f[1] == "high" for f in findings)


def test_xss_plain_reflection_not_fp():
    findings = scan_xss(
        "https://x.com/search?q=laptop",
        "<html><title>Results for laptop</title><body>laptop</body></html>",
    )
    assert findings == []


def test_xss_metachar_reflection_detected():
    findings = scan_xss(
        "https://x.com/search?q=%3Cscript%3E",
        '<html><body>query: "<script>"</body></html>',
    )
    # value after parse_qs may be decoded depending on caller; simulate decoded
    findings = scan_xss(
        "https://x.com/search?q=<script>",
        '<html><body>query: "<script>"</body></html>',
    )
    assert any(f[0] == "xss" for f in findings)


def test_secret_placeholder_filtered():
    body = 'const api_key = "your_api_key_here_12345";'
    assert scan_secrets(body, "https://x.com/a.js") == []


def test_secret_real_key_detected():
    body = 'const key = "AIzaSyD-RealKeyValue0123456789AbCdEfGhI";'
    hits = scan_secrets(body, "https://x.com/a.js")
    assert hits, "expected a real-looking Google API key to be detected"
    full = hits[0][3]
    assert full and full.startswith("AIza")
    assert "…" not in full
    assert "…" in mask_secret_value(full)


def test_sensitive_path_backup_guide_not_fp():
    assert scan_sensitive_path("https://x.com/backup-restore-policy") is None
    assert scan_sensitive_path("https://x.com/.env") is not None
    assert scan_sensitive_path("https://x.com/backup.zip") is not None


def test_rce_docs_not_fp():
    body = "```python\nos.system('ls')\n```\nThis tutorial explains eval()."
    findings = scan_rce("https://docs.example/rce", body)
    assert findings == []


def test_api_oauth_token_not_critical_fp():
    findings = scan_api_leaks(
        "https://api.example/oauth/token",
        '{"access_token":"aaaa.bbbb.cccc","token_type":"bearer"}',
        {},
        "application/json",
    )
    assert not any(f[1] == "critical" for f in findings)


def test_traversal_still_detected():
    findings = scan_directory_traversal("https://x.com/file?path=../../../etc/passwd")
    assert any(f[0] == "directory_traversal" for f in findings)


def test_record_finding_does_not_host_dedupe_non_headers():
    stats = CrawlStats()
    stats.record_finding("xss", "medium", "https://a/x?q=<b>", "reflected")
    stats.record_finding("xss", "medium", "https://a/y?q=<b>", "reflected")
    assert len(stats.findings) == 2


def test_fp_store_scoped_by_host():
    store = FalsePositiveStore("")
    store.record(200, 100, "deadbeef", "https://a.example/soft404")
    assert store.is_false_positive(200, 100, "deadbeef", "https://a.example/other")
    assert not store.is_false_positive(200, 100, "deadbeef", "https://b.example/other")


def test_enum_hit_keeps_distinct_hash_despite_similar_length():
    config = CrawlConfig(start_url="https://example.com", smart_false_positive=True, enum_similarity_threshold=50)
    filt = build_status_filter(config)
    # Same length as baseline (±10) but different body hash → should remain a hit
    probe = ProbeResult("https://example.com/admin", "admin", 200, 1010, "uniquehash", [])
    assert is_probe_hit(
        probe,
        status_filter=filt,
        wildcard=WildcardProfile(),
        baseline=(1000, 200),
        config=config,
        fp_store=None,
        exclude_lengths=set(),
        exclude_hashes=set(),
    )


def test_enum_soft404_head_only_suppressed():
    config = CrawlConfig(start_url="https://example.com", smart_false_positive=True, enum_similarity_threshold=50)
    filt = build_status_filter(config)
    probe = ProbeResult("https://example.com/nope", "nope", 200, 1000, "head-only", [])
    assert not is_probe_hit(
        probe,
        status_filter=filt,
        wildcard=WildcardProfile(),
        baseline=(1000, 200),
        config=config,
        fp_store=None,
        exclude_lengths=set(),
        exclude_hashes=set(),
    )


def test_mask_secret_still_works():
    assert "…" in mask_secret_value("AKIAIOSFODNN7EXAMPLE")
