"""Google/Firebase AIza keys: stable labels + restriction-aware severity."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from finding_impact import assess_secrets_live, assess_secrets_static
from secret_classify import severity_for_kind
from security_scan import refine_secret_label, scan_secrets


AIZA = "AIzaSyAQmcbet1FYuca30mB23_Z_z91Sdt1PsCE"


def test_aiza_near_setitem_is_not_set_item_api_key():
    """Restaurant-app FP: localStorage.setItem next to apiKey must not rename the key."""
    body = (
        'localStorage.setItem("email",e);localStorage.setItem("uid",t);'
        f'Jj={{apiKey:"{AIZA}"}};'
        "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
    )
    hits = scan_secrets(body, "https://restaurant-user-app.vercel.app/assets/index.js")
    assert hits
    labels = {h[0] for h in hits}
    assert "Set Item API Key" not in labels
    assert "Storage API Key" not in labels
    assert any(l in ("Firebase API Key", "Google Cloud / Maps API Key") for l in labels)
    assert all(h[1] in ("info", "low") for h in hits if h[3] and h[3].startswith("AIza"))


def test_firebase_context_labels_firebase_api_key():
    body = f'const cfg={{apiKey:"{AIZA}"}}; fetch("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=")'
    label = refine_secret_label(
        "Google Cloud / Maps API Key",
        f'apiKey:"{AIZA}"',
        body,
        body.index(AIZA),
        body.index(AIZA) + len(AIZA),
    )
    assert label == "Firebase API Key"


def test_aiza_static_severity_is_low():
    assert severity_for_kind("Google Cloud / Maps API Key", "high", AIZA) == "low"
    static = assess_secrets_static(
        "Exposed Firebase API Key in response body",
        "medium",
        AIZA,
    )
    assert static.role == "client_public_key"
    assert static.impact == "limited_impact"
    assert static.severity == "low"


def test_aiza_live_restricted_is_info_not_possible_credential():
    class FakeResp:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    http = MagicMock()
    http.get = AsyncMock(
        side_effect=[
            FakeResp(400),
            FakeResp(400, {"status": "REQUEST_DENIED", "error_message": "API keys are restricted"}),
        ]
    )

    result = asyncio.run(
        assess_secrets_live(
            label="Firebase API Key",
            detail="Exposed Firebase API Key in response body",
            severity="medium",
            evidence=AIZA,
            client=http,
        )
    )
    assert result.role == "client_public_key"
    assert result.impact == "limited_impact"
    assert result.severity == "info"
    assert result.validation == "unverified"


def test_aiza_live_active_stays_medium():
    class FakeResp:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    http = MagicMock()
    http.get = AsyncMock(
        side_effect=[
            FakeResp(400),
            FakeResp(200, {"status": "OK", "results": []}),
            FakeResp(200, {"status": "OK", "results": []}),  # Places abuse probe
        ]
    )

    result = asyncio.run(
        assess_secrets_live(
            label="Google Maps API Key",
            detail="Exposed Google Maps API Key in response body",
            severity="low",
            evidence=AIZA,
            client=http,
        )
    )
    assert result.role == "client_public_key"
    assert result.impact == "limited_impact"
    assert result.severity == "medium"
    assert result.validation == "active"
    assert "Places" in result.summary or "Maps" in result.summary
