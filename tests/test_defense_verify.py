from defense_verify import DefenseTracker


def test_tracker_counts_caught_and_unchallenged():
    tracker = DefenseTracker(start_url="https://lab.local")
    tracker.record_response(
        "https://lab.local/",
        403,
        {"server": "cloudflare", "cf-ray": "abc"},
        "attention required",
    )
    tracker.record_response("https://lab.local/about", 200, {"server": "nginx"}, "<html>ok</html>")
    tracker.record_response("https://lab.local/api", 429, {}, "")
    assert tracker.caught_count == 2
    assert tracker.unchallenged_count == 1
    assert "cloudflare" in tracker.protections_seen
    assert tracker.catch_rate_pct() > 0
    data = tracker.to_dict()
    assert data["completed_without_challenge"] == 1
    assert "not that a CAPTCHA" in data["note"].lower() or "not that" in data["note"].lower()


def test_plain_report_mentions_gaps_not_bypass():
    tracker = DefenseTracker(start_url="https://lab.local")
    tracker.record_response("https://lab.local/", 200, {}, "ok")
    text = tracker.format_plain_report()
    assert "DEFENSE VERIFICATION" in text
    assert "without challenge" in text.lower()
    assert "bypass" in text.lower() or "GAP" in text or "gap" in text.lower()


def test_netlify_403_is_access_deny_not_waf_block():
    """Bare Netlify 403s must not inflate WAF Blocks, but still record HTTP deny status."""
    tracker = DefenseTracker(start_url="https://app.netlify.app")
    tracker.record_response(
        "https://app.netlify.app/missing.aspx",
        403,
        {"Server": "Netlify"},
        "Access denied",
    )
    tracker.record_response(
        "https://app.netlify.app/secret.bak",
        403,
        {"server": "Netlify"},
        "Not Found",
    )
    assert tracker.caught_count == 0
    assert tracker.access_deny_count == 2
    assert tracker.access_deny_status_counts.get("403") == 2
    data = tracker.to_dict()
    assert data["caught_by_protection"] == 0
    assert data["access_deny_count"] == 2
    assert data["access_deny_status_counts"]["403"] == 2
    assert data["access_deny_journal"]
    assert data["access_deny_journal"][0]["status"] == 403
    assert data["access_deny_journal"][0]["signal"] == "access_deny"


def test_cloudflare_403_still_counts_as_waf_block():
    tracker = DefenseTracker(start_url="https://lab.local")
    tracker.record_response(
        "https://lab.local/",
        403,
        {"server": "cloudflare", "cf-ray": "abc"},
        "attention required",
    )
    assert tracker.caught_count == 1
    assert tracker.access_deny_count == 0
    assert tracker.block_status_counts.get("403") == 1


def test_captcha_widget_on_200_is_not_caught():
    """A login page embedding reCAPTCHA is not a bot-wall block."""
    tracker = DefenseTracker(start_url="https://lab.local")
    tracker.record_response(
        "https://lab.local/login",
        200,
        {},
        '<div class="g-recaptcha" data-sitekey="x"></div>',
    )
    assert tracker.caught_count == 0
    assert tracker.unchallenged_count == 1


def test_cdn_headers_on_200_are_not_caught():
    tracker = DefenseTracker(start_url="https://lab.local")
    tracker.record_response(
        "https://lab.local/",
        200,
        {"server": "cloudflare", "cf-ray": "abc123"},
        "<html>ok</html>",
    )
    assert tracker.caught_count == 0
    assert tracker.unchallenged_count == 1
