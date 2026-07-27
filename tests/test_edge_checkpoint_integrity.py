"""Edge checkpoint / API / cloud / ledger integrity (screenshot audit P0s)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from api_recon.active import _accept_api_hit, run_active_api_enum
from cloud_enum import _is_public_listing
from content_validate import classify_bucket_response
from crawl_stats import CrawlStats
from defense_verify import DefenseTracker
from edge_checkpoint import (
    enum_blocked_conclusion,
    is_edge_checkpoint,
    looks_like_html_denial,
    uniform_checkpoint_across,
)
from enum_engine import ProbeResult, WildcardProfile, build_status_filter, detect_wildcard, is_probe_hit
from enum_validation import CLASS_BLOCKED_INCONCLUSIVE
from evasion_layer import detect_challenge, is_permission_or_storage_deny
from tier_security import scan_hidden_params_in_js


VERCEL_BODY = (
    "<!DOCTYPE html><html><head><title>Vercel Security Checkpoint</title></head>"
    "<body>Vercel Security Checkpoint — enable javascript</body></html>"
)


def test_vercel_checkpoint_detected_not_permission_deny():
    headers = {"Server": "Vercel", "content-type": "text/html"}
    assert is_edge_checkpoint(403, VERCEL_BODY, headers) == "vercel_security_checkpoint"
    assert is_permission_or_storage_deny(403, VERCEL_BODY, headers) is False
    assert detect_challenge(403, VERCEL_BODY, headers=headers) == "vercel_security_checkpoint"


def test_status_200_prose_checkpoint_words_are_not_edge_walls():
    """Blogs/docs mentioning checkpoint/cf-challenge must not trip on bare 200 text."""
    assert is_edge_checkpoint(200, "cf-challenge cloudflare") == ""
    assert is_edge_checkpoint(200, "we passed the security checkpoint today") == ""
    prose_html = (
        "<!DOCTYPE html><html><body>"
        "Our blog post about the security checkpoint and cf-challenge headers."
        "</body></html>"
    )
    assert is_edge_checkpoint(200, prose_html) == ""
    assert detect_challenge(200, "cf-challenge cloudflare") == ""


def test_status_200_real_cloudflare_interstitial_still_detected():
    body = (
        "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
        "<body>Checking your browser before accessing example.com. "
        "cf-browser-verification challenge-platform</body></html>"
    )
    headers = {"Server": "cloudflare", "cf-ray": "abc-DFW", "content-type": "text/html"}
    assert is_edge_checkpoint(200, body, headers) == "cloudflare_challenge"
    assert detect_challenge(200, body, headers=headers) == "cloudflare_challenge"


def test_bare_vercel_403_without_checkpoint_still_permission():
    headers = {"Server": "Vercel"}
    body = "<html><body>Forbidden</body></html>"
    assert is_edge_checkpoint(403, body, headers) == ""
    assert is_permission_or_storage_deny(403, body, headers) is True


def test_uniform_checkpoint_across_controls():
    samples = [
        {
            "status": 403,
            "body": VERCEL_BODY.encode(),
            "headers": {"Server": "Vercel"},
            "title": "Vercel Security Checkpoint",
            "raw_hash": "abc",
        }
        for _ in range(5)
    ]
    assert uniform_checkpoint_across(samples) == "vercel_security_checkpoint"


def test_enum_blocked_conclusion_wording():
    text = enum_blocked_conclusion(
        signal="vercel_security_checkpoint",
        blocked_count=30449,
        http_attempts=30449,
    )
    assert "could not be assessed" in text.lower()
    assert "Vercel Security Checkpoint" in text
    assert "wildcard" not in text.lower() or "not a wildcard" in text.lower()


def test_is_probe_hit_checkpoint_is_inconclusive_not_soft404():
    from crawl_config import CrawlConfig

    config = CrawlConfig(start_url="https://example.com")
    filt = build_status_filter(config)
    probe = ProbeResult(
        "https://example.com/admin",
        "admin",
        403,
        len(VERCEL_BODY),
        "abcd",
        [],
        body=VERCEL_BODY.encode(),
        content_type="text/html",
        title="Vercel Security Checkpoint",
    )
    stats = CrawlStats()
    assert (
        is_probe_hit(
            probe,
            status_filter=filt,
            wildcard=WildcardProfile(),
            baseline=(0, 404),
            config=config,
            fp_store=None,
            exclude_lengths=set(),
            exclude_hashes=set(),
            stats=stats,
        )
        is False
    )
    assert probe.classification == CLASS_BLOCKED_INCONCLUSIVE
    assert stats.enum_inconclusive == 1
    assert getattr(stats, "enum_blocked_checkpoint", 0) == 1
    assert stats.soft_404s_filtered == 0
    assert getattr(stats, "enum_rejected_wildcard", 0) == 0


def test_detect_wildcard_aborts_on_uniform_checkpoint():
    class Resp:
        status_code = 403
        headers = {"server": "Vercel", "content-type": "text/html"}
        content = VERCEL_BODY.encode()

    client = MagicMock()
    client.get = AsyncMock(return_value=Resp())

    profile = asyncio.run(detect_wildcard(client, "https://nexus.example/"))
    assert profile.edge_blocked is True
    assert "vercel" in profile.edge_checkpoint_signal
    assert profile.active is False
    assert profile.catch_all_200 is False


def test_generic_403_html_not_api_hit():
    ok, reason = _accept_api_hit(
        status=403,
        ctype="text/html",
        body=b"<html>Forbidden</html>",
        url="https://shop.example/rest/actuator/health",
        baselines=[(403, "text/html", "x")],
        stats=CrawlStats(),
    )
    assert ok is False
    assert reason == "blocked_probe_candidate"
    assert looks_like_html_denial(403, "text/html", b"<html>x</html>")


def test_json_401_is_protected_api():
    ok, reason = _accept_api_hit(
        status=401,
        ctype="application/json",
        body=b'{"error":"missing_token"}',
        url="https://shop.example/api/v1/me",
        baselines=[(403, "text/html", "other")],
        stats=CrawlStats(),
    )
    assert ok is True
    assert "protected" in reason or "api" in reason


def test_html_200_status_not_api_when_twin_exists():
    stats = CrawlStats()
    stats.discovered_urls.add("https://app.example/status.html")
    ok, reason = _accept_api_hit(
        status=200,
        ctype="text/html",
        body=b"<html>status page</html>",
        url="https://app.example/status",
        baselines=[],
        stats=stats,
    )
    assert ok is False
    assert reason == "html_application_route"


def test_cloud_403_not_public_hit():
    ok, note = classify_bucket_response(
        403,
        b'<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>',
        provider="s3",
    )
    assert ok is False
    assert not _is_public_listing(
        403,
        b'<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>',
        "s3",
    )


def test_third_party_gcs_does_not_set_perimeterx_on_target():
    tracker = DefenseTracker(start_url="https://nexus-analytics.vercel.app/")
    # GCS XML deny with no PX — must not invent PerimeterX
    gcs_body = (
        '<?xml version="1.0"?><Error><Code>AccessDenied</Code>'
        "<Message>Access denied.</Message></Error>"
    )
    tracker.record_response(
        "https://storage.googleapis.com/local/",
        403,
        {"Server": "UploadServer", "Content-Type": "application/xml"},
        gcs_body,
    )
    assert "perimeterx" not in tracker.protections_seen
    # Target checkpoint must register Vercel
    tracker.record_response(
        "https://nexus-analytics.vercel.app/admin",
        403,
        {"Server": "Vercel", "Content-Type": "text/html"},
        VERCEL_BODY,
    )
    assert "vercel" in tracker.protections_seen
    assert tracker.caught_count >= 1


def test_request_ledger_honest_totals():
    stats = CrawlStats()
    stats._request_ledger_cap = 3
    for i in range(5):
        stats.record_request(phase="enumeration", source="probe", url=f"https://x/{i}", status=403)
    assert stats.total_requests_observed == 5
    assert stats.requests_retained == 3
    assert stats.requests_omitted == 2
    snap = stats.snapshot()
    assert snap["total_requests_observed"] == 5
    assert snap["request_retention_cap"] == 3
    assert snap["requests_omitted"] == 2


def test_role_alone_not_mass_assignment():
    body = 'const el = { role: "button", ariaLabel: "x" };'
    assert scan_hidden_params_in_js("https://app.example/app.js", body) == []


def test_api_enum_skips_uniform_html_403():
    class Resp:
        def __init__(self):
            self.status_code = 403
            self.headers = {"content-type": "text/html"}
            self.content = b"<html><title>Forbidden</title></html>"

    client = MagicMock()
    client.get = AsyncMock(return_value=Resp())
    stats = CrawlStats()
    hits = asyncio.run(
        run_active_api_enum(
            client,
            "https://shop.example/",
            wordlist_file="",
            word_limit=6,
            headers={},
            concurrency=2,
            method="GET",
            stats=stats,
        )
    )
    assert hits == []
    assert stats.total_requests_observed >= 1
