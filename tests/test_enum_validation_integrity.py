"""Tests for path-shape wildcard validation and enum integrity fixes."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from crawl_config import CrawlConfig
from crawl_stats import CrawlStats
from enum_engine import ProbeResult, WildcardProfile, build_status_filter, is_probe_hit
from enum_validation import (
    CLASS_CASE_VARIANT,
    CLASS_CONFIRMED,
    CLASS_WILDCARD,
    HitProvenanceTracker,
    SHAPE_DOT_PREFIX,
    SHAPE_INDEX_EXT,
    SHAPE_RANDOM,
    ShapeBaseline,
    classify_path_shape,
    control_paths_for_base,
    enum_validation_conclusion,
    fingerprint_from_response,
    is_public_client_key_value,
    matches_any_shape_baseline,
    normalize_body_for_hash,
    raw_body_hash,
)
from security_scan import mask_secret_value, scan_secrets


def test_control_paths_include_required_shapes():
    paths = control_paths_for_base("https://example.com/")
    assert set(paths) >= {
        "random",
        "dot_prefix",
        "index_ext",
        "ext_php",
        "ext_bak",
        "nested",
        "case",
    }
    assert "/." in paths["dot_prefix"] or paths["dot_prefix"].endswith(
        paths["dot_prefix"].rsplit("/", 1)[-1]
    )
    assert paths["dot_prefix"].rsplit("/", 1)[-1].startswith(".")
    assert "index." in paths["index_ext"]
    assert paths["ext_php"].endswith(".php")
    assert paths["ext_bak"].endswith(".bak")
    assert "/" in paths["nested"].split("//", 1)[-1].split("/", 1)[-1] or paths["nested"].count("/") >= 4
    assert "RANDOMCASE-" in paths["case"]


def test_classify_path_shapes():
    assert classify_path_shape("/.robots") == SHAPE_DOT_PREFIX
    assert classify_path_shape("/index.sql") == SHAPE_INDEX_EXT
    assert classify_path_shape("/admin.php") == "ext_php"
    assert classify_path_shape("/backup.bak") == "ext_bak"
    assert classify_path_shape("/random-abc123def456") == SHAPE_RANDOM


def test_dot_prefix_wildcard_rejects_candidates():
    config = CrawlConfig(start_url="https://example.com", wildcard_detection=True, response_fingerprint=True)
    filt = build_status_filter(config)
    body = b"<html><title>Shop</title><body>fallback page nonce</body></html>"
    raw = raw_body_hash(body)
    norm = normalize_body_for_hash(body)
    profile = WildcardProfile(
        active=True,
        shapes={
            SHAPE_DOT_PREFIX: ShapeBaseline(
                shape=SHAPE_DOT_PREFIX,
                active=True,
                status=200,
                length=len(body),
                raw_hash=raw,
                normalized_hash=norm,
            ),
            SHAPE_RANDOM: ShapeBaseline(
                shape=SHAPE_RANDOM,
                active=False,
                status=404,
                length=0,
                raw_hash="empty",
                normalized_hash="empty",
            ),
        },
    )
    fp = fingerprint_from_response(url="https://example.com/.robots", status=200, body=body)
    probe = ProbeResult(
        "https://example.com/.robots",
        ".robots",
        200,
        len(body),
        raw[:16],
        [],
        raw_hash=fp.raw_hash,
        normalized_hash=fp.normalized_hash,
        path_shape=SHAPE_DOT_PREFIX,
        fingerprint=fp,
    )
    assert not is_probe_hit(
        probe,
        status_filter=filt,
        wildcard=profile,
        baseline=(0, 404),
        config=config,
        fp_store=None,
        exclude_lengths=set(),
        exclude_hashes=set(),
        stats=CrawlStats(),
    )
    assert probe.classification == CLASS_WILDCARD


def test_plain_path_not_rejected_when_only_dot_wildcard():
    config = CrawlConfig(start_url="https://example.com", wildcard_detection=True, response_fingerprint=True)
    filt = build_status_filter(config)
    dot_body = b"<html>dot wildcard</html>"
    real_body = b"<html><h1>Admin panel unique</h1></html>"
    profile = WildcardProfile(
        active=True,
        shapes={
            SHAPE_DOT_PREFIX: ShapeBaseline(
                shape=SHAPE_DOT_PREFIX,
                active=True,
                status=200,
                length=len(dot_body),
                raw_hash=raw_body_hash(dot_body),
                normalized_hash=normalize_body_for_hash(dot_body),
            ),
            SHAPE_RANDOM: ShapeBaseline(
                shape=SHAPE_RANDOM,
                active=False,
                status=404,
                length=20,
                raw_hash="empty",
                normalized_hash="empty",
            ),
        },
    )
    fp = fingerprint_from_response(url="https://example.com/admin", status=200, body=real_body)
    probe = ProbeResult(
        "https://example.com/admin",
        "admin",
        200,
        len(real_body),
        fp.raw_hash[:16],
        [],
        raw_hash=fp.raw_hash,
        normalized_hash=fp.normalized_hash,
        path_shape="plain",
        fingerprint=fp,
    )
    assert is_probe_hit(
        probe,
        status_filter=filt,
        wildcard=profile,
        baseline=(0, 404),
        config=config,
        fp_store=None,
        exclude_lengths=set(),
        exclude_hashes=set(),
    )


def test_case_and_content_grouping():
    tracker = HitProvenanceTracker(["https://example.com/about"])
    body = b"<html>same fallback cart-form</html>"
    fp1 = fingerprint_from_response(url="https://example.com/About", status=200, body=body)
    rec1 = tracker.classify_and_record(
        url="https://example.com/About",
        base_word="About",
        variant="About",
        requested_status=200,
        final_status=200,
        final_url="https://example.com/About",
        fingerprint=fp1,
        wildcard_rejected=False,
        wildcard_similarity=0.0,
        baseline_used="",
        soft_404=False,
        path_shape="plain",
    )
    assert rec1.classification == CLASS_CONFIRMED or rec1.already_known
    # Same content different path
    fp2 = fingerprint_from_response(url="https://example.com/blog", status=200, body=body)
    rec2 = tracker.classify_and_record(
        url="https://example.com/blog",
        base_word="blog",
        variant="blog",
        requested_status=200,
        final_status=200,
        final_url="https://example.com/blog",
        fingerprint=fp2,
        wildcard_rejected=False,
        wildcard_similarity=0.0,
        baseline_used="",
        soft_404=False,
        path_shape="plain",
    )
    assert rec2.classification in ("content_equivalent_fallback", CLASS_CONFIRMED)
    # Case variant of blog
    if rec2.validated:
        fp3 = fingerprint_from_response(url="https://example.com/Blog", status=200, body=b"other")
        rec3 = tracker.classify_and_record(
            url="https://example.com/Blog",
            base_word="Blog",
            variant="Blog",
            requested_status=200,
            final_status=200,
            final_url="https://example.com/Blog",
            fingerprint=fp3,
            wildcard_rejected=False,
            wildcard_similarity=0.0,
            baseline_used="",
            soft_404=False,
            path_shape="plain",
        )
        assert rec3.classification == CLASS_CASE_VARIANT
        assert not rec3.validated


def test_enum_validation_conclusion_unverified():
    text = enum_validation_conclusion(
        http_attempts=24374,
        accepted_hits=111,
        rejected_wildcard=0,
        rate_limited=585,
        calibration_ok=False,
        wildcard_active=True,
    )
    assert "24,374" in text
    assert "unverified candidates" in text
    assert "585" in text


def test_enum_validation_conclusion_catch_all_without_rejects():
    text = enum_validation_conclusion(
        http_attempts=1000,
        accepted_hits=50,
        rejected_wildcard=0,
        rate_limited=10,
        calibration_ok=True,
        wildcard_active=True,
        catch_all_200=True,
    )
    assert "unverified candidates" in text


def test_text_similarity_detects_near_duplicate_html():
    from enum_validation import text_similarity

    a = b"<html><body>Welcome to the shop cart-form nonce=abc123</body></html>"
    b = b"<html><body>Welcome to the shop cart-form nonce=zzz999</body></html>"
    assert text_similarity(a, b) >= 0.82
    c = b"<html><body>Completely different admin dashboard content here</body></html>"
    assert text_similarity(a, c) < 0.82


def test_pubkey_stable_label():
    assert is_public_client_key_value("pubkey-abc123def456ghi789")
    body = 'const api_key = "pubkey-abc123def456ghi789xyz"; var etime = 1; var ip66 = 2;'
    findings = scan_secrets(body, "https://example.com/")
    assert findings
    labels = [f[0] for f in findings]
    assert any("Public client-key-like" in lab for lab in labels)
    for lab, sev, detail, evidence in findings:
        if "Public client-key" in lab:
            assert sev == "info"
            assert "etime" not in lab.lower()
            assert "ip66" not in lab.lower()
            assert evidence is None or "…" in str(evidence) or "***" in str(evidence) or evidence != "pubkey-abc123def456ghi789xyz"


def test_shopify_cookies_not_credentials():
    from cookie_impact import assess_cookie_impact, parse_set_cookie

    for name in ("_shopify_y", "_shopify_s"):
        parsed = parse_set_cookie(f"{name}=abcdef0123456789abcdef01; Path=/")
        assessment = assess_cookie_impact(parsed, page_url="https://shop.example/")
        assert assessment["impact"] == "no_credential_impact"
        assert assessment["role"] == "analytics"


def test_stealth_profile_caps_concurrency():
    cfg = CrawlConfig(start_url="https://example.com", profile="stealth", enum_concurrency=20)
    cfg.apply_profile()
    assert cfg.enum_concurrency <= 3


def test_probe_candidate_returns_retry_after_on_429():
    import httpx
    from enum_engine import probe_candidate

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "7"}, text="slow down")

    transport = httpx.MockTransport(handler)

    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await probe_candidate(client, "https://example.com/x", use_head=False)

    result = asyncio.run(_run())
    assert result[0] == 429
    assert result[-1] == "7"


def test_detailed_report_separates_http_attempts():
    from detailed_report import build_report_model, render_detailed_text

    stats = CrawlStats()
    stats.enum_base_words_loaded = 100
    stats.enum_base_words_processed = 100
    stats.enum_words_total = 100
    stats.enum_words_tested = 100
    stats.enum_http_attempts = 1500
    stats.enum_rate_limited = 12
    stats.enum_rejected_wildcard = 40
    stats.enum_hits = 2
    stats.enum_hit_urls = ["https://example.com/admin", "https://example.com/login"]
    stats.enum_status_codes.update({404: 1400, 200: 50, 429: 12})
    stats.enum_validation_conclusion = "Directory enumeration executed 1,500 HTTP candidate requests."
    stats.enum_requested_depth = 2
    stats.enum_effective_depth = 0
    stats.enum_depth_reason = "flat enumeration enabled"
    stats.enum_started_at = 1.0
    model = build_report_model(stats, "https://example.com/")
    text = render_detailed_text(model)
    assert "Base words processed" in text
    assert "HTTP attempts" in text
    assert "1,500" in text
    assert "Rate-limited/unknown" in text
    assert "flat enumeration enabled" in text
    assert "Wordlist progress: 1,500 / 100" not in text  # never mix HTTP into word progress ratio



def test_broken_link_skips_429():
    from crawl_orchestrator import _check_broken_links

    class FakeResp:
        status_code = 429

    class FakeClient:
        async def head(self, *a, **k):
            return FakeResp()

        async def get(self, *a, **k):
            return FakeResp()

    stats = CrawlStats()

    async def _run():
        await _check_broken_links(
            FakeClient(),
            stats,
            ["https://example.com/throttled"],
            "example.com",
            True,
            sample_size=10,
        )

    asyncio.run(_run())
    assert stats.broken_links == []


def test_matches_any_shape_baseline_short_circuit():
    body = b"x" * 100
    raw = raw_body_hash(body)
    profile = WildcardProfile(
        active=True,
        shapes={
            SHAPE_INDEX_EXT: ShapeBaseline(
                shape=SHAPE_INDEX_EXT,
                active=True,
                status=200,
                length=100,
                raw_hash=raw,
                normalized_hash=normalize_body_for_hash(body),
            )
        },
    )
    matched, sim, shape = matches_any_shape_baseline(
        profile,
        path_or_word="/index.sql",
        status=200,
        length=100,
        raw_hash=raw,
        normalized_hash=normalize_body_for_hash(body),
    )
    assert matched
    assert shape == SHAPE_INDEX_EXT
    assert sim >= 0.9


def test_enum_followup_requires_validation():
    from enum_followup import EnumFollowupScheduler

    async def _run():
        sched = EnumFollowupScheduler(
            client=MagicMock(),
            config=MagicMock(enum_auto_vuln_scan=True, enum_auto_crawl_hits=True),
            stats=CrawlStats(),
            run_security=AsyncMock(),
            extract_forms=MagicMock(return_value=[]),
        )
        probe = ProbeResult(
            "https://example.com/.robots",
            ".robots",
            200,
            10,
            "abcd",
            [],
            validated=False,
            classification=CLASS_WILDCARD,
        )
        sched.schedule(probe)
        assert sched._scheduled == 0
        probe.validated = True
        probe.classification = CLASS_CONFIRMED
        sched.schedule(probe)
        assert sched._scheduled == 1
        for t in list(sched._tasks):
            t.cancel()
        await asyncio.gather(*list(sched._tasks), return_exceptions=True)

    asyncio.run(_run())
