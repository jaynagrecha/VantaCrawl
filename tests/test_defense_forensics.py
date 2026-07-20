from defense_verify import DefenseTracker


def test_block_journal_and_forensic_capture():
    tracker = DefenseTracker(start_url="https://example.com")
    tracker.record_response(
        "https://example.com/api/users",
        403,
        {
            "Server": "AkamaiGHost",
            "x-amzn-waf": "blocked",
            "x-amzn-RequestId": "abc-123",
            "Content-Type": "text/html",
        },
        "<html>Access Denied by Akamai</html>",
    )
    data = tracker.to_dict()
    assert data["caught_by_protection"] == 1
    assert "akamai" in data["protections_detected"] or "aws_waf" in data["protections_detected"]
    assert data["block_status_counts"].get("403") == 1
    assert data["block_journal"]
    journal = data["block_journal"][0]
    assert journal["status"] == 403
    assert journal["url"].endswith("/api/users")
    assert journal["reason"]
    assert str(journal.get("time") or "").endswith("IST")
    forensic = data["block_events_forensic"][0]
    assert "Server" in forensic["headers"] or "server" in {k.lower() for k in forensic["headers"]}
    assert "Akamai" in forensic["body_snippet"] or "akamai" in forensic["body_snippet"].lower()
    assert str(forensic.get("time_ist") or "").endswith("IST")
    plain = tracker.format_plain_report()
    assert "FORENSIC BLOCK" in plain
    assert "HTTP 403" in plain


def test_rate_limit_reason():
    tracker = DefenseTracker(start_url="https://example.com")
    tracker.record_response(
        "https://example.com/slow",
        429,
        {"Retry-After": "30", "Server": "cloudflare"},
        "rate limited",
    )
    event = tracker.block_events[0]
    assert event.status == 429
    assert event.signal == "rate_limit"
    assert "429" in event.reason
