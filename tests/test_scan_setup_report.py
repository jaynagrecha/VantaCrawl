from crawl_config import CrawlConfig
from crawl_stats import CrawlStats
from scan_setup_report import build_scan_setup, config_to_report_meta
from search_report import build_search_conclusion


def test_config_meta_omits_passwords():
    config = CrawlConfig(
        start_url="https://example.com",
        auth_password="secret-pass",
        login_password="login-secret",
        cookie_string="session=abc",
        download_files=False,
        security_scan=True,
        vuln_active_probe=True,
        crawl_concurrency=4,
        enum_concurrency=20,
        download_concurrency=5,
    )
    meta = config_to_report_meta(config)
    assert "auth_password" not in meta
    assert "login_password" not in meta
    assert meta["cookie_string"] == "set"
    assert meta["crawl_concurrency"] == 4


def test_build_scan_setup_narrative_and_rows():
    setup = build_scan_setup(
        {
            "profile": "full",
            "download_files": False,
            "use_wordlist": True,
            "wordlist_file": r"C:\Wordlist\directory-list-2.3-big.txt",
            "mutation_enum": True,
            "security_scan": True,
            "vuln_scan": True,
            "vuln_active_probe": True,
            "evasion_enabled": True,
            "evasion_level": "stealth",
            "wayback_seeds": True,
            "crawl_concurrency": 4,
            "enum_concurrency": 20,
            "download_concurrency": 5,
        }
    )
    assert "did not download a full" in setup["narrative"].lower() or "did not download" in setup["narrative"].lower()
    assert "active injection" in setup["narrative"].lower()
    assert any("4 crawl" in row[1] for row in setup["rows"])
    assert any("directory-list-2.3-big.txt" in row[1] for row in setup["rows"])
    assert setup["actions"]


def test_search_report_includes_setup_section():
    stats = CrawlStats()
    stats.pages_crawled = 2
    conclusion = build_search_conclusion(
        stats,
        "https://example.com",
        config_meta={
            "profile": "full",
            "download_files": True,
            "mirror_page_assets": True,
            "security_scan": True,
            "use_wordlist": True,
            "wordlist_file": "big.txt",
            "crawl_concurrency": 4,
            "enum_concurrency": 35,
            "download_concurrency": 6,
        },
    )
    text = conclusion["text"]
    assert "PART A — EXECUTIVE SUMMARY" in text
    assert "B10. What this scan was configured to do" in text
    assert "Settings snapshot" in text or "Key settings:" in text
    assert conclusion["scan_setup"]["narrative"]
