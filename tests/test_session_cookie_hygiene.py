"""Cookie jar must stay host-scoped (no mega Cookie header dumps)."""

from __future__ import annotations

from session_cookies import SessionCookieStore


def test_header_for_does_not_leak_other_host_cookies():
    store = SessionCookieStore()
    store.ingest_selenium_cookies(
        [
            {"name": "_abck", "value": "a", "domain": ".wu.example"},
            {"name": "bm_sz", "value": "b", "domain": ".wu.example"},
            {"name": "ak_bmsc", "value": "c", "domain": ".wu.example"},
        ],
        "https://www.wu.example/",
    )
    store.ingest_selenium_cookies(
        [{"name": "session", "value": "other", "domain": ".other.example"}],
        "https://other.example/",
    )
    hdr = store.header_for("https://www.wu.example/path")
    assert "_abck" in hdr and "bm_sz" in hdr
    assert "session=other" not in hdr


def test_as_cookie_string_is_not_used_for_empty_url_apply():
    store = SessionCookieStore()
    store.ingest_selenium_cookies(
        [
            {"name": "_abck", "value": "a", "domain": ".a.test"},
            {"name": "bm_sz", "value": "b", "domain": ".a.test"},
        ],
        "https://a.test/",
    )

    class Client:
        headers = {"Cookie": "stale=1"}

    client = Client()
    out = store.apply_to_client(client, url="")
    assert out == ""
    assert "Cookie" not in client.headers


def test_seed_binds_to_first_request_host():
    store = SessionCookieStore()
    store.load_cookie_string("_abck=tok; bm_sz=sz")
    hdr = store.header_for("https://lab.example/app")
    assert "_abck=tok" in hdr
    # Other host does not inherit unbound seed after bind
    hdr2 = store.header_for("https://other.example/")
    assert "_abck" not in hdr2
