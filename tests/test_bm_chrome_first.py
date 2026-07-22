"""BM detection flips Chrome-first; fetcher reads config live."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from browser_fetch import make_browser_fetcher


def test_browser_primary_honored_after_mid_scan_flip(monkeypatch):
    """Setting config.browser_primary=True after fetcher creation must force Chrome."""
    calls = {"selenium": 0}

    def fake_selenium(*_a, **_k):
        calls["selenium"] += 1
        return "<html>chrome</html>", [{"name": "a", "value": "b"}], [], []

    monkeypatch.setattr("browser_fetch.fetch_with_selenium", fake_selenium)
    monkeypatch.setattr("browser_fetch.chrome_available", lambda: True)
    monkeypatch.setattr("browser_fetch.probe_chrome", lambda: (True, "ok"))

    config = SimpleNamespace(
        cookie_string="",
        auto_sync_cookies=True,
        browser_primary=False,
        browser_on_challenge=True,
        selenium_fallback=False,
        deep_mirror=False,
        screenshot_capture=False,
        proxy_url="",
        start_url="https://example.com/",
    )
    fetcher = make_browser_fetcher(config)

    class Resp:
        status_code = 200
        text = "<html>http</html>"
        content = b"<html>http</html>"
        headers = {}

    client = AsyncMock()
    client.get = AsyncMock(return_value=Resp())

    async def _run():
        html, _ = await fetcher(client, "https://example.com/page")
        assert "http" in html
        assert calls["selenium"] == 0

        config.browser_primary = True
        html2, _ = await fetcher(client, "https://example.com/page2")
        assert "chrome" in html2
        assert calls["selenium"] == 1

    asyncio.run(_run())
