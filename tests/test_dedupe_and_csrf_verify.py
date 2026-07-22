"""Secret evidence dedupe + third-party CSRF filter + safe CSRF canary."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from crawl_stats import CrawlStats
from exploit_probes import probe_csrf, scan_csrf
from finding_explain import group_findings_for_report
from security_scan import scan_secrets


def test_same_secret_value_one_finding_despite_label_drift():
    body = (
        'ript_api_key = "key_live_eoeHYdsFNAm8LodH26Sjlcxugv1Rh2";'
        'text_api_key = "key_live_eoeHYdsFNAm8LodH26Sjlcxugv1Rh2";'
    )
    hits = scan_secrets(body, "https://westernunion.com/app.js")
    values = [h[3] for h in hits]
    assert values.count("key_live_eoeHYdsFNAm8LodH26Sjlcxugv1Rh2") == 1


def test_record_finding_dedupes_secrets_by_evidence():
    stats = CrawlStats()
    ev = "key_live_eoeHYdsFNAm8LodH26Sjlcxugv1Rh2"
    stats.record_finding(
        "secrets_exposure",
        "low",
        "https://westernunion.com/a",
        "Exposed Ript API Key in response body",
        evidence=ev,
    )
    stats.record_finding(
        "secrets_exposure",
        "low",
        "https://westernunion.com/b",
        "Exposed Text API Key in response body",
        evidence=ev,
    )
    assert len(stats.findings) == 1


def test_report_groups_same_evidence_once():
    ev = "key_live_eoeHYdsFNAm8LodH26Sjlcxugv1Rh2"
    findings = [
        {
            "category": "secrets_exposure",
            "severity": "low",
            "url": "https://westernunion.com/a",
            "detail": "Exposed Ript API Key in response body",
            "evidence": ev,
        },
        {
            "category": "secrets_exposure",
            "severity": "low",
            "url": "https://westernunion.com/b",
            "detail": "Exposed Text API Key in response body",
            "evidence": ev,
        },
    ]
    groups = group_findings_for_report(findings)
    secret_groups = [g for g in groups if g["category"] == "secrets_exposure"]
    assert len(secret_groups) == 1
    assert set(secret_groups[0]["urls"]) == {
        "https://westernunion.com/a",
        "https://westernunion.com/b",
    }


def test_facebook_pixel_csrf_suppressed():
    forms = [
        {
            "method": "POST",
            "action": "https://www.facebook.com/tr/",
            "fields": ["id", "ev", "dl", "rl", "if", "ts", "sw", "sh"],
        }
    ]
    assert scan_csrf("https://www.westernunion.com/", forms, {}) == []


def test_same_origin_csrf_still_flagged():
    forms = [
        {
            "method": "POST",
            "action": "https://www.westernunion.com/profile/update",
            "fields": ["name", "email"],
        }
    ]
    hits = scan_csrf("https://www.westernunion.com/", forms, {})
    assert hits
    assert hits[0][0] == "csrf"


def test_csrf_canary_reports_acceptance():
    class Resp:
        status_code = 200
        text = '{"ok":true}'

    client = MagicMock()
    client.post = AsyncMock(return_value=Resp())
    forms = [
        {
            "method": "POST",
            "action": "https://app.example.com/settings",
            "fields": ["theme", "locale"],
        }
    ]
    hits = asyncio.run(probe_csrf(client, "https://app.example.com/", forms))
    assert hits
    assert hits[0][0] == "csrf"
    assert "canary accepted" in hits[0][2].lower()
    # Dummy payload only
    kwargs = client.post.await_args.kwargs
    assert kwargs["data"].get("vcrawl_csrf_probe") == "1"
    assert kwargs["headers"]["Origin"] == "https://evil.example"


def test_csrf_canary_skips_destructive_and_third_party():
    client = MagicMock()
    client.post = AsyncMock()
    forms = [
        {
            "method": "POST",
            "action": "https://www.facebook.com/tr/",
            "fields": ["id", "ev"],
        },
        {
            "method": "POST",
            "action": "https://app.example.com/account/delete",
            "fields": ["confirm"],
        },
        {
            "method": "POST",
            "action": "https://app.example.com/pay",
            "fields": ["amount"],
        },
    ]
    assert asyncio.run(probe_csrf(client, "https://app.example.com/", forms)) == []
    client.post.assert_not_called()


def test_csrf_canary_skips_when_server_rejects():
    class Resp:
        status_code = 403
        text = "CSRF token missing"

    client = MagicMock()
    client.post = AsyncMock(return_value=Resp())
    forms = [
        {
            "method": "POST",
            "action": "https://app.example.com/settings",
            "fields": ["theme"],
        }
    ]
    assert asyncio.run(probe_csrf(client, "https://app.example.com/", forms)) == []
