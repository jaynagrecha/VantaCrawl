"""Browser RUM / data-* attribute keys: demote or drop like Google client keys."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from finding_impact import assess_secrets_live, assess_secrets_static
from secret_classify import is_client_public_key, severity_for_kind
from security_scan import scan_secrets


def test_boomr_is_client_public_key():
    assert is_client_public_key("Boomr API Key", "Fc8f46b5abcdef0123456789abcdef01")
    assert is_client_public_key(
        "Exposed Boomr API Key in response body (assigned to `window.BOOMR_API_key`)",
        "x" * 32,
    )
    assert severity_for_kind("Boomr API Key", "high", "x" * 32) == "low"


def test_boomr_static_limited_impact():
    static = assess_secrets_static(
        "Exposed Boomr API Key in response body",
        "high",
        "Fc8f46b5abcdef0123456789abcdef01",
    )
    assert static.role == "client_public_key"
    assert static.impact == "limited_impact"
    assert static.severity == "low"


def test_boomr_live_skipped_not_possible_credential():
    result = asyncio.run(
        assess_secrets_live(
            label="Boomr API Key",
            detail="Exposed Boomr API Key in response body (assigned to `window.BOOMR_API_key`)",
            severity="high",
            evidence="Fc8f46b5abcdef0123456789abcdef01",
            client=MagicMock(),
        )
    )
    assert result.role == "client_public_key"
    assert result.impact == "limited_impact"
    assert result.severity in ("info", "low")
    assert result.validation == "skipped"


def test_data_api_key_attribute_is_fp_even_outside_input():
    bodies = [
        '<div data-api-key="4aec879ef8b1f1823486c4338537ec441" class="x"></div>',
        '<span data-api-key="4aec879ef8b1f1823486c4338537ec441"></span>',
        'data-api-key="4aec879ef8b1f1823486c4338537ec441" data-foo="1"',
    ]
    for body in bodies:
        assert scan_secrets(body, "https://westernunion.com/") == [], body


def test_boomr_js_assignment_still_detected_as_low_client_key():
    body = 'window.BOOMR_API_key = "Fc8f46b5abcdef0123456789abcdef01";'
    hits = scan_secrets(body, "https://westernunion.com/app.js")
    assert hits
    assert hits[0][0] == "Boomr API Key"
    assert hits[0][1] in ("info", "low")
