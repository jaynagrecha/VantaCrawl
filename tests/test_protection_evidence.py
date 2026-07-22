"""Evidence-backed protection inventory."""

from __future__ import annotations

from defense_verify import DefenseTracker
from protection_evidence import extract_response_evidence, score_detection


def test_akamai_confirmed_active_needs_two_groups():
    tracker = DefenseTracker(start_url="https://wu.example/")
    tracker.record_response(
        "https://wu.example/",
        403,
        {
            "Server": "AkamaiGHost",
            "Set-Cookie": "_abck=xyz; Path=/, bm_sz=abc; Path=/",
            "X-Akamai-Request-ID": "req-1",
        },
        "Access Denied AkamaiGHost errors.edgesuite.net Reference #18",
    )
    detail = {row["vendor"]: row for row in tracker.protections_detail()}
    assert "akamai" in detail
    ak = detail["akamai"]
    assert ak["active"] is True
    assert ak["tier"] == "confirmed_active"
    assert ak["confidence"] >= 0.85
    assert any(e.startswith("cookie:_abck") for e in ak["evidence"])
    assert any(e.startswith("challenge-behaviour") for e in ak["evidence"])


def test_recaptcha_is_page_level_not_edge_waf():
    tracker = DefenseTracker(start_url="https://wu.example/")
    tracker.record_response(
        "https://wu.example/us/en/refund-status",
        200,
        {"content-type": "text/html"},
        '<form><div class="g-recaptcha"></div><script src="https://www.google.com/recaptcha/api.js"></script></form>',
    )
    detail = {row["vendor"]: row for row in tracker.protections_detail()}
    assert "recaptcha" in detail
    rc = detail["recaptcha"]
    assert rc["category"] == "app_challenge"
    assert rc["tier"] == "page_level"
    assert rc["scope"] == "page"
    assert any("recaptcha" in e for e in rc["evidence"])


def test_datadome_js_only_is_passive():
    tracker = DefenseTracker(start_url="https://shop.example/")
    tracker.record_response(
        "https://shop.example/",
        200,
        {"content-type": "text/html"},
        '<script src="https://js.datadome.co/tags.js"></script>',
    )
    detail = {row["vendor"]: row for row in tracker.protections_detail()}
    assert "datadome" in detail
    dd = detail["datadome"]
    assert dd["active"] is False
    assert dd["tier"] == "passive"
    assert dd["confidence"] < 0.55


def test_extract_cloudflare_header_identity():
    ev = extract_response_evidence(
        {"cf-ray": "abc", "server": "cloudflare"},
        "",
        status_code=200,
    )
    assert "cloudflare" in ev
    assert "response-header:cf-ray" in ev["cloudflare"]


def test_score_requires_identity_and_behavior_for_confirmed():
    conf, active, tier = score_detection(
        vendor="akamai",
        category="edge_waf",
        groups={"identity", "behavior"},
        challenge_count=2,
        evidence=["cookie:_abck", "challenge-behaviour:akamai"],
    )
    assert active and tier == "confirmed_active" and conf >= 0.85
    conf2, active2, tier2 = score_detection(
        vendor="perimeterx",
        category="edge_waf",
        groups={"passive"},
        challenge_count=0,
        evidence=["js-reference:px-cdn"],
    )
    assert not active2 and tier2 == "passive"


def test_protections_detail_sorts_confirmed_first():
    tracker = DefenseTracker(start_url="https://lab.example/")
    tracker.record_response(
        "https://lab.example/",
        200,
        {},
        '<script src="https://js.datadome.co/tags.js"></script>',
    )
    tracker.record_response(
        "https://lab.example/x",
        403,
        {"Server": "AkamaiGHost", "Set-Cookie": "_abck=1; Path=/"},
        "AkamaiGHost Access Denied errors.edgesuite.net",
    )
    rows = tracker.protections_detail()
    assert rows[0]["vendor"] == "akamai"
    assert rows[0]["tier"] == "confirmed_active"
    vendors = [r["vendor"] for r in rows]
    assert "datadome" in vendors


def test_to_dict_includes_protections_detail():
    tracker = DefenseTracker(start_url="https://lab.example/")
    tracker.record_response(
        "https://lab.example/",
        429,
        {"Retry-After": "10", "server": "cloudflare", "cf-ray": "xyz"},
        "rate limited",
    )
    data = tracker.to_dict()
    assert data["protections_detail"]
    assert data["protections_label"] != "none"
    assert any(r["vendor"] in ("cloudflare", "rate_limit") for r in data["protections_detail"])


def test_akamai_rate_burst_in_inventory_and_journal():
    tracker = DefenseTracker(start_url="https://wu.example/")
    body = (
        "Access Denied — traffic classified as DoS under rule: Rate-Burst. "
        "Reference #18.abc AkamaiGHost errors.edgesuite.net"
    )
    tracker.record_response(
        "https://wu.example/send",
        403,
        {"Server": "AkamaiGHost", "Set-Cookie": "_abck=tok; Path=/"},
        body,
    )
    assert tracker.signal_counts.get("akamai_rate_burst") == 1
    assert tracker.rate_limit_count == 1
    event = tracker.block_events[-1]
    assert event.signal == "akamai_rate_burst"
    assert "Rate-Burst" in event.reason
    detail = {row["vendor"]: row for row in tracker.protections_detail()}
    assert "akamai" in detail
    assert any("rate" in e.lower() or "burst" in e.lower() for e in detail["akamai"]["evidence"])
    assert "rate_limit" in detail
    assert detail["rate_limit"]["active"] is True
