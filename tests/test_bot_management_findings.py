"""Akamai Bot Manager presence + unchallenged-gap findings (detection only)."""

from __future__ import annotations

from crawl_stats import CrawlStats
from defense_verify import (
    DefenseTracker,
    build_bot_management_findings,
    inject_bot_management_findings,
)
from finding_impact import assess_bot_management
from finding_kind import classify_finding_kind


def test_bm_cookies_from_set_cookie():
    tracker = DefenseTracker(start_url="https://www.example.com/")
    tracker.record_response(
        "https://www.example.com/",
        200,
        {
            "Server": "AkamaiGHost",
            "Set-Cookie": "_abck=xyz; Path=/; Secure, bm_sz=1; Path=/",
        },
        "<html>ok</html>",
    )
    assert tracker.akamai_bot_manager_present() is True
    assert "_abck" in tracker.bm_cookies_seen
    assert "bm_sz" in tracker.bm_cookies_seen


def test_presence_finding_when_bm_cookies():
    tracker = DefenseTracker(start_url="https://www.example.com/")
    tracker.protections_seen.add("akamai")
    tracker.bm_cookies_seen.add("_abck")
    tracker.bm_cookies_seen.add("ak_bmsc")
    # Enough unchallenged to also fire gap finding
    for i in range(10):
        tracker.unchallenged_count += 1
        from defense_verify import DefenseEvent

        tracker.sample_unchallenged.append(
            DefenseEvent(
                url=f"https://www.example.com/p{i}",
                status=200,
                outcome="unchallenged",
                signal="none",
            )
        )
    tracker.caught_count = 2
    findings = build_bot_management_findings(tracker)
    assert len(findings) == 2
    assert findings[0]["severity"] == "info"
    assert "Bot Manager" in findings[0]["detail"]
    assert findings[1]["severity"] == "medium"
    assert "gap" in findings[1]["detail"].lower() or "without a challenge" in findings[1]["detail"].lower()
    assert classify_finding_kind(
        category="bot_management",
        role="hardening",
        severity="medium",
        detail=findings[1]["detail"],
    ) == "hardening"


def test_no_finding_without_bm():
    tracker = DefenseTracker(start_url="https://plain.example/")
    tracker.record_response("https://plain.example/", 200, {"Server": "nginx"}, "ok")
    assert build_bot_management_findings(tracker) == []


def test_inject_into_stats():
    stats = CrawlStats()
    tracker = DefenseTracker(start_url="https://www.example.com/")
    tracker.protections_seen.add("akamai")
    tracker.bm_cookies_seen.add("_abck")
    stats.defense_tracker = tracker
    assert inject_bot_management_findings(stats) == 1
    assert any(f["category"] == "bot_management" for f in stats.findings)


def test_assess_bot_management_impact():
    present = assess_bot_management(
        "Akamai Bot Manager signals observed on this origin",
        "info",
        "bm_cookies: _abck",
    )
    assert present.role == "hardening"
    assert present.severity == "info"
    gap = assess_bot_management(
        "Akamai Bot Manager is present, but 50% completed without a challenge",
        "medium",
        "gap_rate=50%",
    )
    assert gap.severity == "medium"
    assert gap.validation == "confirmed"
