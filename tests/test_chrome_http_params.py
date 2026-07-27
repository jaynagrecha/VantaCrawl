"""Chrome HTTP client must honor httpx-style params= for active probes."""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urlparse

import pytest

from chrome_http import CompatResponse, StealthAsyncClient


class _FakeSession:
    def __init__(self):
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        body = f"url={url}".encode()
        return type(
            "R",
            (),
            {
                "status_code": 200,
                "content": body,
                "headers": {"content-type": "text/plain"},
                "url": url,
            },
        )()


def test_stealth_client_merges_params_into_url():
    session = _FakeSession()
    client = StealthAsyncClient(session, default_headers={})

    async def _run():
        return await client.get(
            "http://lab.example/sqli/vuln?id=1",
            params={"id": "'"},
            follow_redirects=False,
        )

    resp = asyncio.run(_run())
    assert isinstance(resp, CompatResponse)
    assert session.calls
    called = session.calls[0]["url"]
    q = dict(parse_qsl(urlparse(called).query))
    assert q.get("id") == "'"


def test_stealth_client_params_replace_baseline_query():
    session = _FakeSession()
    client = StealthAsyncClient(session, default_headers={})

    async def _run():
        await client.get(
            "http://lab.example/rce/arith?cmd=id",
            params={"cmd": ";expr 7319 + 284"},
        )

    asyncio.run(_run())
    called = session.calls[0]["url"]
    q = dict(parse_qsl(urlparse(called).query, keep_blank_values=True))
    assert q.get("cmd") == ";expr 7319 + 284"


def test_compat_response_raise_for_status():
    ok = CompatResponse(200, {}, b"ok", "http://x/")
    ok.raise_for_status()
    bad = CompatResponse(404, {}, b"missing", "http://x/missing")
    with pytest.raises(Exception):
        bad.raise_for_status()
