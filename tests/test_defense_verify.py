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


def test_captcha_signal_in_body():
    tracker = DefenseTracker(start_url="https://lab.local")
    tracker.record_response(
        "https://lab.local/login",
        200,
        {},
        '<div class="g-recaptcha" data-sitekey="x"></div>',
    )
    assert tracker.caught_count == 1
    assert tracker.captcha_signal_count >= 1
