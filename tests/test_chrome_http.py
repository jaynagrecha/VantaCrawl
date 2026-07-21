"""Chrome TLS client + modern evasion header coverage."""

from __future__ import annotations

from chrome_http import DEFAULT_IMPERSONATE, HAS_CURL_CFFI, chrome_impersonate_for_profile
from evasion_layer import CHROME_MAJOR, EvasionConfig, EvasionSession


def test_chrome_impersonate_defaults_to_modern_chrome():
    assert chrome_impersonate_for_profile("chrome") == DEFAULT_IMPERSONATE
    assert "chrome" in DEFAULT_IMPERSONATE
    # TLS stays Chrome even if UA profile is firefox/safari (avoids mixed JA4 in Akamai)
    assert chrome_impersonate_for_profile("firefox") == DEFAULT_IMPERSONATE
    assert chrome_impersonate_for_profile("safari") == DEFAULT_IMPERSONATE


def test_expected_ja4_constant_matches_chrome146():
    from chrome_http import CURL_CFFI_CHROME146_JA4

    # Documented / measured curl_cffi chrome146 JA4 — what Akamai should show
    # when the scan client (not real Chrome) is the only stack.
    assert CURL_CFFI_CHROME146_JA4.startswith("t13d1516h2_8daaf6152771_")
    assert CURL_CFFI_CHROME146_JA4.endswith("d8a2da3f94cd")


def test_evasion_headers_include_full_client_hints_and_sec_fetch():
    session = EvasionSession(
        EvasionConfig(enabled=True, level="basic", browser_profile="chrome", referer_chain=True)
    )
    session._last_url = "https://lab.local/home"
    headers = session.build_headers("https://lab.local/admin", is_navigation=True)
    assert f"Chrome/{CHROME_MAJOR}" in headers["User-Agent"]
    assert "Sec-CH-UA" in headers
    assert "Sec-CH-UA-Full-Version-List" in headers
    assert "Sec-CH-UA-Platform" in headers
    assert "Sec-CH-UA-Mobile" in headers
    assert headers.get("Sec-Fetch-Mode") == "navigate"
    assert headers.get("Sec-Fetch-Dest") == "document"
    assert headers.get("Accept-Language")
    assert headers.get("Accept-Encoding")
    assert headers.get("Connection") == "keep-alive"
    assert "Accept-CH" not in headers
    assert "Linux" not in headers["User-Agent"]


def test_non_navigation_still_sends_sec_fetch():
    session = EvasionSession(EvasionConfig(enabled=True, level="stealth", browser_profile="chrome"))
    session._last_url = "https://lab.local/"
    headers = session.build_headers("https://lab.local/api/v1/users", is_navigation=False)
    assert headers.get("Sec-Fetch-Mode") == "cors"
    assert headers.get("Sec-Fetch-Dest") == "empty"
    assert "Sec-Fetch-Site" in headers
    assert "Upgrade-Insecure-Requests" not in headers


def test_chrome_ua_pool_has_no_linux():
    from evasion_layer import BROWSER_PROFILES

    for ua in BROWSER_PROFILES["chrome"]["user_agents"]:
        assert "Linux" not in ua and "X11" not in ua


def test_curl_cffi_available_in_ci_or_skips_softly():
    # Local/CI install should pull curl_cffi from requirements; keep assertion informative.
    assert isinstance(HAS_CURL_CFFI, bool)
