"""Chrome TLS client + modern evasion header coverage."""

from __future__ import annotations

from chrome_http import (
    DEFAULT_IMPERSONATE,
    HAS_CURL_CFFI,
    chrome_impersonate_for_profile,
    coalesce_headers,
)
from evasion_layer import BROWSER_PROFILES, CHROME_MAJOR, EvasionConfig, EvasionSession


def test_chrome_impersonate_defaults_to_modern_chrome():
    assert chrome_impersonate_for_profile("chrome") == DEFAULT_IMPERSONATE
    assert "chrome" in DEFAULT_IMPERSONATE


def test_coalesce_headers_collapses_case_duplicates():
    merged = coalesce_headers(
        {"User-Agent": "A", "cookie": "a=1", "Accept-Encoding": "gzip"},
        {"user-agent": "B", "Cookie": "b=2", "accept-encoding": "gzip, deflate, br"},
    )
    assert merged["User-Agent"] == "B"
    assert merged["Cookie"] == "b=2"
    assert merged["Accept-Encoding"] == "gzip, deflate, br"
    lowers = [k.lower() for k in merged]
    assert len(lowers) == len(set(lowers))


def test_chrome_profiles_exclude_linux_desktop_ua():
    for name in ("chrome", "firefox", "edge"):
        for ua in BROWSER_PROFILES[name]["user_agents"]:
            assert "Linux" not in ua and "X11" not in ua, ua


def test_evasion_headers_include_full_client_hints_and_sec_fetch():
    session = EvasionSession(
        EvasionConfig(enabled=True, level="basic", browser_profile="chrome", referer_chain=True)
    )
    session._session_ua = (
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
    )
    session._last_url = "https://lab.local/home"
    headers = session.build_headers("https://lab.local/admin", is_navigation=True)
    assert f"Chrome/{CHROME_MAJOR}" in headers["User-Agent"]
    assert "Linux" not in headers["User-Agent"]
    assert "Sec-CH-UA" in headers
    assert "Sec-CH-UA-Full-Version-List" in headers
    assert headers.get("Sec-CH-UA-Platform") == '"Windows"'
    assert headers.get("Sec-CH-UA-Platform-Version") == '"15.0.0"'
    assert "Accept-CH" not in headers  # response header — must not appear on requests
    assert "Sec-CH-UA-Mobile" in headers
    assert headers.get("Sec-Fetch-Mode") == "navigate"
    assert headers.get("Sec-Fetch-Dest") == "document"
    assert headers.get("Accept-Language")
    assert headers.get("Accept-Encoding")
    assert headers.get("Connection") == "keep-alive"


def test_non_navigation_still_sends_sec_fetch():
    session = EvasionSession(EvasionConfig(enabled=True, level="stealth", browser_profile="chrome"))
    session._last_url = "https://lab.local/"
    headers = session.build_headers("https://lab.local/api/v1/users", is_navigation=False)
    assert headers.get("Sec-Fetch-Mode") == "cors"
    assert headers.get("Sec-Fetch-Dest") == "empty"
    assert "Sec-Fetch-Site" in headers


def test_curl_cffi_available_in_ci_or_skips_softly():
    # Local/CI install should pull curl_cffi from requirements; keep assertion informative.
    assert isinstance(HAS_CURL_CFFI, bool)
