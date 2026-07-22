import pytest

from crawler_common import (
    BYPASS_HTTP_CODES,
    looks_like_existing_path,
    should_accept_http_status,
    init_crawl_state,
    enqueue_discovered_url,
)
from content_filters import should_skip_download
from crawl_config import CrawlConfig


def test_bypass_forbidden_status():
    assert should_accept_http_status(403, bypass_forbidden=True)
    assert not should_accept_http_status(403, bypass_forbidden=False)


def test_enum_similarity_threshold():
    assert looks_like_existing_path(404, 1000, 1000, 404, similarity_threshold=50) is False
    assert looks_like_existing_path(403, 100, 1000, 404, bypass_forbidden=True) is True


def test_enqueue_dedupes():
    discovered = set()
    queue = []
    log = []
    enqueue_discovered_url("https://a.com", discovered, queue, "out.txt", log.append)
    enqueue_discovered_url("https://a.com", discovered, queue, "out.txt", log.append)
    assert len(queue) == 1


def test_skip_tracking_pixel():
    config = CrawlConfig(start_url="https://example.com", skip_tracking_downloads=True)
    assert should_skip_download("https://x.com/pixel.gif", "image/gif", 43, config)


def test_init_crawl_state():
    discovered, queue = init_crawl_state("https://example.com", True, True)
    assert "https://example.com" in discovered


def test_invalid_ipv6_url_rejected():
    from crawler_common import is_valid_url, is_html_url, init_crawl_state

    assert not is_valid_url("http://[bad-ipv6")
    assert not is_html_url("http://[bad-ipv6")
    discovered, queue = init_crawl_state("https://example.com", True, True, extra_seeds=["http://[bad-ipv6", "https://ok.com/x"])
    assert "https://ok.com/x" in discovered
    assert "http://[bad-ipv6" not in discovered


def test_vuln_scan_sql_error_passive_suppressed():
    from security_scan import scan_sql_injection

    # Passive SQL-error pages are suppressed; active probes confirm SQLi
    assert (
        scan_sql_injection(
            "https://x.com/page?id=1",
            "Warning: mysql_fetch_array(): SQL syntax error near",
        )
        == []
    )


def test_vuln_scan_traversal_passive_suppressed():
    from security_scan import scan_directory_traversal

    # Passive traversal is suppressed; active /etc/passwd probes confirm disclosure
    assert scan_directory_traversal("https://x.com/file?path=../../../etc/passwd") == []


def test_apply_live_settings_preserves_identity():
    running = CrawlConfig(
        start_url="https://target.example",
        extensions=["pdf"],
        enum_extensions="php",
        download_files=False,
        wordlist_file="keep-this.txt",
    )
    fresh = CrawlConfig(
        start_url="https://other.example",
        extensions=["png", "jpg"],
        enum_extensions="php,bak",
        download_files=True,
        wordlist_file="changed.txt",
    )
    changed = running.apply_live_settings(fresh)
    assert running.start_url == "https://target.example"
    assert running.wordlist_file == "keep-this.txt"
    assert running.extensions == ["png", "jpg"]
    assert running.enum_extensions == "php,bak"
    assert running.download_files is True
    assert "extensions" in changed
    assert "start_url" not in changed
    assert "wordlist_file" not in changed
