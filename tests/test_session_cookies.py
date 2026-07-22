"""Per-host cookie jar + challenge heuristic tests."""

from __future__ import annotations

from browser_fetch import _response_looks_challenged
from session_cookies import SessionCookieStore


def test_cookie_store_per_host_and_header():
    store = SessionCookieStore()
    store.load_cookie_string("seed=1; theme=dark")
    store.ingest_selenium_cookies(
        [
            {"name": "session", "value": "abc", "domain": ".westernunion.com"},
            {"name": "ak_bmsc", "value": "tok", "domain": "www.westernunion.com"},
        ],
        "https://www.westernunion.com/",
    )
    header = store.header_for("https://www.westernunion.com/us/en/home.html")
    assert "seed=1" in header
    assert "session=abc" in header
    assert "ak_bmsc=tok" in header
    # Unrelated host should not get WU host cookies
    other = store.header_for("https://example.com/")
    assert "session=abc" not in other
    assert "seed=1" in other


def test_apply_to_dict_headers_client():
    class Client:
        def __init__(self):
            self.headers = {}

    store = SessionCookieStore()
    store.ingest_selenium_cookies(
        [{"name": "a", "value": "b", "domain": "lab.local"}],
        "https://lab.local/",
    )
    client = Client()
    store.apply_to_client(client, "https://lab.local/x")
    assert client.headers["Cookie"] == "a=b"


def test_challenge_heuristic():
    # Bare permission deny is not a bot wall
    assert not _response_looks_challenged(403, "Access Denied")
    assert not _response_looks_challenged(
        403,
        "Access Denied",
        headers={"Server": "AmazonS3"},
    )
    # Real Akamai / rate-limit still escalate
    assert _response_looks_challenged(403, "Access Denied", headers={"Server": "AkamaiGHost"})
    assert _response_looks_challenged(429, "")
    assert not _response_looks_challenged(200, "<html><body>Welcome</body></html>")
