"""Enum hit follow-up must not stall directory enumeration on curl timeouts."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from enum_engine import ProbeResult
from enum_followup import EnumFollowupScheduler, should_skip_enum_followup


def test_skip_binary_and_backup_extensions():
    assert should_skip_enum_followup("https://x.netlify.app/feedback.zip", 200)
    assert should_skip_enum_followup("https://x.netlify.app/print.zip", 403)
    assert should_skip_enum_followup("https://x.netlify.app/pdf.old", 403, word="pdf.old")
    assert should_skip_enum_followup("https://x.netlify.app/legal.bak", 403, word="legal.bak")
    assert should_skip_enum_followup("https://x.netlify.app/vite.svg", 200)


def test_skip_soft_deny_file_hits():
    assert should_skip_enum_followup("https://x.netlify.app/ads.aspx", 403, word="ads.aspx")
    assert should_skip_enum_followup("https://x.netlify.app/modules.zip", 403, word="modules.zip")


def test_keep_interesting_text_hits():
    assert not should_skip_enum_followup("https://x.netlify.app/company.txt", 200, word="company.txt")
    assert not should_skip_enum_followup("https://x.netlify.app/.env", 200, word=".env")
    assert not should_skip_enum_followup("https://x.netlify.app/admin", 200, word="admin")


def test_reuse_probe_body_avoids_second_get():
    client = AsyncMock()
    client.get = AsyncMock(side_effect=AssertionError("must not re-GET when body present"))
    security = AsyncMock()
    config = SimpleNamespace(
        enum_auto_crawl_hits=True,
        enum_auto_vuln_scan=True,
        security_scan=False,
        vuln_active_probe=True,
    )
    stats = SimpleNamespace(errors=0)
    sched = EnumFollowupScheduler(
        client=client,
        config=config,
        stats=stats,
        output_callback=lambda _m: None,
        run_security=security,
        extract_forms=lambda *_a, **_k: [],
        concurrency=1,
        timeout_s=1.0,
    )
    probe = ProbeResult(
        url="https://x.netlify.app/company.txt",
        word="company.txt",
        status=200,
        content_length=42,
        body_hash="abc",
        path_segments=[],
        body=b"Company secrets API_KEY=test",
        content_type="text/plain",
    )

    async def run():
        sched.schedule(probe)
        await sched.drain(timeout=5.0)

    asyncio.run(run())
    client.get.assert_not_called()
    security.assert_awaited()
    # Active probes must stay off during enum follow-up
    assert config.vuln_active_probe is True  # restored after run
    assert config.security_scan is False


def test_timeout_circuit_breaker_disables_followups():
    class BoomClient:
        async def get(self, *args, **kwargs):
            raise TimeoutError("Failed to perform, curl: (28) Connection timed out after 12001 milliseconds")

    messages = []
    config = SimpleNamespace(
        enum_auto_crawl_hits=True,
        enum_auto_vuln_scan=True,
        security_scan=False,
        vuln_active_probe=False,
    )
    stats = SimpleNamespace(errors=0)
    sched = EnumFollowupScheduler(
        client=BoomClient(),
        config=config,
        stats=stats,
        output_callback=messages.append,
        run_security=AsyncMock(),
        extract_forms=lambda *_a, **_k: [],
        concurrency=1,
        timeout_s=0.2,
        max_followups=20,
        max_consecutive_timeouts=3,
    )

    async def run():
        for i in range(5):
            sched.schedule(
                ProbeResult(
                    url=f"https://x.netlify.app/f{i}.txt",
                    word=f"f{i}.txt",
                    status=200,
                    content_length=0,
                    body_hash="",
                    path_segments=[],
                    body=b"",  # force re-GET → timeout
                )
            )
        await sched.drain(timeout=10.0)

    asyncio.run(run())
    assert stats.errors >= 3
    assert sched._disabled is True
    assert any("paused after repeated timeouts" in m for m in messages)


def test_schedule_is_non_blocking_for_caller():
    """schedule() must return immediately even if follow-up is slow."""
    started = asyncio.Event()
    release = asyncio.Event()

    class SlowClient:
        async def get(self, *args, **kwargs):
            started.set()
            await release.wait()
            return SimpleNamespace(status_code=200, content=b"ok", headers={"content-type": "text/plain"})

    config = SimpleNamespace(
        enum_auto_crawl_hits=True,
        enum_auto_vuln_scan=True,
        security_scan=False,
        vuln_active_probe=False,
    )
    sched = EnumFollowupScheduler(
        client=SlowClient(),
        config=config,
        stats=SimpleNamespace(errors=0),
        output_callback=lambda _m: None,
        run_security=AsyncMock(),
        extract_forms=lambda *_a, **_k: [],
        concurrency=1,
    )

    async def run():
        probe = ProbeResult(
            url="https://x.netlify.app/slow.txt",
            word="slow.txt",
            status=200,
            content_length=0,
            body_hash="",
            path_segments=[],
            body=b"",
        )
        t0 = asyncio.get_event_loop().time()
        sched.schedule(probe)
        elapsed = asyncio.get_event_loop().time() - t0
        assert elapsed < 0.05
        await started.wait()
        release.set()
        await sched.drain(timeout=5.0)

    asyncio.run(run())
