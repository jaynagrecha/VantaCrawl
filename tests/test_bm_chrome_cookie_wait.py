"""BM Chrome wait + cookie sync diagnostics."""

from __future__ import annotations

from unittest.mock import MagicMock

from browser_fetch import (
    bm_cookie_names_present,
    page_suggests_bot_manager,
    _wait_for_bm_cookies,
)
from session_cookies import SessionCookieStore


def test_bm_cookie_names_present():
    assert bm_cookie_names_present(
        [{"name": "_abck", "value": "x"}, {"name": "session", "value": "1"}]
    ) == ["_abck"]
    assert bm_cookie_names_present({"bm_sz": "1", "foo": "2"}) == ["bm_sz"]


def test_page_suggests_bot_manager():
    assert page_suggests_bot_manager('<script src="https://x/akamai/..."></script>')
    assert not page_suggests_bot_manager("<html><body>hello</body></html>")


def test_wait_for_bm_cookies_polls_until_present(monkeypatch):
    driver = MagicMock()
    driver.get_cookies.side_effect = [
        [],
        [],
        [{"name": "_abck", "value": "tok"}],
    ]
    driver.execute_script.return_value = ""
    sleeps = []
    monkeypatch.setattr("browser_fetch.time.sleep", lambda s: sleeps.append(s))
    found = _wait_for_bm_cookies(driver, timeout_seconds=5)
    assert found == ["_abck"]
    assert sleeps


def test_cookie_store_syncs_bm_to_header():
    store = SessionCookieStore()
    store.ingest_selenium_cookies(
        [
            {"name": "_abck", "value": "abc", "domain": ".example.com"},
            {"name": "bm_sz", "value": "1", "domain": "www.example.com"},
        ],
        "https://www.example.com/",
    )
    header = store.header_for("https://www.example.com/path")
    assert "_abck=abc" in header
    assert "bm_sz=1" in header
