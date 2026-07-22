"""Permission/storage Access Denied must not stall crawls as WAF blocks."""

from __future__ import annotations

from browser_fetch import _response_looks_challenged
from crawler_common import canonicalize_crawl_url
from defense_verify import DefenseTracker
from evasion_layer import (
    EvasionConfig,
    EvasionSession,
    detect_challenge,
    is_permission_or_storage_deny,
)


S3_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
)


def test_s3_access_denied_is_permission_not_challenge():
    headers = {"Server": "AmazonS3", "x-amz-cf-id": "abc123"}
    assert is_permission_or_storage_deny(403, S3_BODY, headers) is True
    assert detect_challenge(403, S3_BODY, headers=headers) == ""
    assert _response_looks_challenged(403, S3_BODY, headers) is False


def test_s3_deny_does_not_arm_waf_backoff():
    session = EvasionSession(EvasionConfig(enabled=True, adaptive_backoff=True, challenge_detect=True))
    session.after_request(
        "https://www.example.com/sitemap.xml",
        403,
        S3_BODY,
        headers={"Server": "AmazonS3", "x-amz-cf-id": "abc"},
    )
    assert session._challenge_hits == 0
    assert session.backoff_remaining() < 0.05


def test_s3_deny_is_access_deny_journal_not_waf_block():
    tracker = DefenseTracker(start_url="https://www.example.com")
    tracker.record_response(
        "https://www.example.com/sitemap_index.xml",
        403,
        {"Server": "AmazonS3", "x-amz-cf-id": "abc", "x-amz-request-id": "1"},
        S3_BODY,
    )
    assert tracker.caught_count == 0
    assert tracker.access_deny_count == 1
    assert "aws_waf" not in tracker.protection_block_counts
    data = tracker.to_dict()
    assert data["caught_by_protection"] == 0
    assert data["access_deny_count"] == 1


def test_generic_access_denied_body_not_challenge():
    body = "<html><body>Access Denied</body></html>"
    assert detect_challenge(403, body, headers={"Server": "nginx"}) == ""
    assert is_permission_or_storage_deny(403, body, {"Server": "nginx"}) is True
    tracker = DefenseTracker(start_url="https://app.example")
    tracker.record_response("https://app.example/secret", 403, {"Server": "nginx"}, body)
    assert tracker.caught_count == 0
    assert tracker.access_deny_count == 1


def test_akamai_ghost_still_challenges():
    headers = {"Server": "AkamaiGHost"}
    assert is_permission_or_storage_deny(403, "Access Denied", headers) is False
    assert detect_challenge(403, "Access Denied", headers=headers) in (
        "akamai",
        "akamai_block",
        "akamaighost",
    )
    assert _response_looks_challenged(403, "Access Denied", headers) is True


def test_canonicalize_upgrades_http_port80_when_base_https():
    out = canonicalize_crawl_url(
        "http://www.westernunion.com:80/",
        base_url="https://www.westernunion.com/",
    )
    assert out == "https://www.westernunion.com/"


def test_canonicalize_strips_default_https_port():
    assert (
        canonicalize_crawl_url("https://www.example.com:443/a", base_url="https://www.example.com/")
        == "https://www.example.com/a"
    )
