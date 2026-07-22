import asyncio

from crawl_config import CrawlConfig
from evasion_layer import (
    detect_challenge,
    evasion_from_crawl_config,
    EvasionConfig,
    EvasionSession,
)


def test_browser_headers_include_sec_fetch_in_stealth():
    session = EvasionSession(
        EvasionConfig(enabled=True, level="stealth", browser_profile="chrome", referer_chain=True)
    )
    session._last_url = "https://lab.local/home"
    headers = session.build_headers("https://lab.local/admin")
    assert "User-Agent" in headers
    assert "Chrome" in headers["User-Agent"]
    assert "Chrome/146" in headers["User-Agent"]
    assert headers.get("Sec-Fetch-Mode") == "navigate"
    assert headers.get("Referer") == "https://lab.local/home"
    assert "Sec-CH-UA" in headers
    assert "Sec-CH-UA-Full-Version-List" not in headers
    assert "Accept-CH" not in headers
    assert "Linux" not in headers["User-Agent"]
    assert "X11" not in headers["User-Agent"]
    assert "Macintosh" not in headers["User-Agent"]
    assert '"Windows"' in headers.get("Sec-CH-UA-Platform", "")
    assert "Google Chrome" in headers["Sec-CH-UA"]


def test_netlify_403_is_not_waf_backoff():
    """Permission / missing-path 403s on Netlify must not arm WAF backoff."""
    assert detect_challenge(403, "Not Found", headers={"Server": "Netlify"}) == ""
    assert detect_challenge(403, "Access denied", headers={"server": "Netlify"}) == ""
    session = EvasionSession(EvasionConfig(enabled=True, adaptive_backoff=True, challenge_detect=True))
    session.after_request(
        "https://app.netlify.app/missing.aspx",
        403,
        "Access denied",
        headers={"Server": "Netlify"},
    )
    assert session.backoff_remaining() < 0.05
    assert session._challenge_hits == 0


def test_akamai_empty_body_403_still_detected_via_headers():
    assert detect_challenge(403, "", headers={"Server": "AkamaiGHost"}) in (
        "akamai",
        "akamai_block",
        "akamaighost",
    )
    session = EvasionSession(EvasionConfig(enabled=True, adaptive_backoff=True, challenge_detect=True))
    session.after_request("https://lab.local/x", 403, "", headers={"Server": "AkamaiGHost"})
    assert session._challenge_hits >= 1
    assert session.backoff_remaining() > 0


def test_sticky_host_keeps_same_ua():
    session = EvasionSession(
        EvasionConfig(enabled=True, level="aggressive", ua_strategy="sticky_host", browser_profile="firefox")
    )
    a = session.build_headers("https://a.test/x")["User-Agent"]
    b = session.build_headers("https://a.test/y")["User-Agent"]
    assert a == b


def test_detect_rate_limit_and_cloudflare():
    assert detect_challenge(429, "") == "rate_limit"
    assert detect_challenge(403, "cf-ray cloudflare") == "cloudflare_block"
    assert detect_challenge(503, "checking your browser before access") == "checking your browser"


def test_detect_akamai_rate_burst():
    body = (
        "Access Denied. Your IP has been flagged as DoS traffic under the rule Rate-Burst. "
        "AkamaiGHost / errors.edgesuite.net"
    )
    assert detect_challenge(403, body) == "akamai_rate_burst"


def test_rate_burst_backoff_uses_harder_path():
    session = EvasionSession(EvasionConfig(enabled=True, level="stealth", adaptive_backoff=True))
    body = "Akamai Rate-Burst DoS traffic denied"
    session.after_request("https://lab.local/x", 403, body)
    assert session.last_challenge == "akamai_rate_burst"
    # Harder than mild WAF 403 pacing (0.5 * 2^1 = 1s first hit → rate path 1*2^1=2s)
    assert session.backoff_remaining() > 0


def test_detect_akamai_soft_and_hard():
    assert detect_challenge(403, "AkamaiGHost access denied") in ("akamai", "akamai_block")
    soft = detect_challenge(
        200,
        "<html>Access Denied</html><!-- AkamaiGHost --> Reference #18.abc",
    )
    assert soft == "akamai_soft_deny"
    # Normal Akamai-fronted 200 must not backoff
    assert detect_challenge(200, "Welcome to Western Union · powered by edgesuite") == ""


def test_backoff_after_challenge():
    session = EvasionSession(EvasionConfig(enabled=True, level="aggressive", adaptive_backoff=True))
    session.after_request("https://lab.local/x", 429, "")
    assert session._backoff_until > 0
    assert session.last_challenge == "rate_limit"
    assert session.backoff_remaining() > 0


def test_waf_403_backoff_milder_than_old_30s_cap():
    session = EvasionSession(EvasionConfig(enabled=True, level="stealth", adaptive_backoff=True))
    for _ in range(6):
        session.after_request("https://lab.local/x", 403, "sucuri cloudproxy access denied")
    # Hard WAF blocks should not park the crawl for tens of seconds
    assert session.backoff_remaining() <= 6.5
    assert "Waiting on WAF backoff" in session.heartbeat_label()


def test_config_profile_stealth_sets_stealth_evasion():
    cfg = CrawlConfig(start_url="https://lab.local", profile="stealth")
    cfg.apply_profile()
    assert cfg.evasion_level == "stealth"
    assert cfg.evasion_decoy_requests is False
    assert cfg.enum_method == "GET"
    assert cfg.api_recon_method == "GET"
    assert cfg.evasion_chrome_tls is True
    session = evasion_from_crawl_config(cfg)
    assert session.effective_level() == "stealth"


def test_decoy_paths_only_aggressive():
    session = EvasionSession(EvasionConfig(enabled=True, level="aggressive", decoy_requests=True))
    assert session.decoy_paths()
    session2 = EvasionSession(EvasionConfig(enabled=True, level="basic", decoy_requests=True))
    assert session2.decoy_paths() == []


def test_jitter_off_is_zero():
    session = EvasionSession(EvasionConfig(enabled=False, level="off"))
    assert session.jitter_range_ms() == (0, 0)


def test_before_request_returns_headers():
    session = EvasionSession(EvasionConfig(enabled=True, level="basic", jitter_min_ms=0, jitter_max_ms=0))
    headers = asyncio.run(session.before_request("https://lab.local/"))
    assert "User-Agent" in headers
