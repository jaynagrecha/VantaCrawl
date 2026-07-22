"""Finding quality pass: less inventory noise, probed env hosts, Maps suppress, CORS dedupe."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from crawl_stats import CrawlStats
from finding_impact import assess_cors, assess_secrets_live, assess_secrets_static, assess_tier_category
from secret_classify import is_google_browser_api_key, severity_for_kind
from tier_security import (
    _collect_env_host_candidates,
    probe_js_env_hosts,
    scan_business_logic_hints,
    scan_hidden_params_in_js,
    scan_js_frontend_intel,
)


AIZA = "AIzaSyAQmcbet1FYuca30mB23_Z_z91Sdt1PsCE"


def test_device_width_is_not_env_host():
    body = 'meta content="width=device-width, initial-scale=1"; const d="device";'
    assert _collect_env_host_candidates(body) == []
    assert scan_js_frontend_intel("https://app.example/a.js", body) == []


def test_staging_host_is_collected():
    body = 'const API="https://staging.internal.example/v1";'
    assert any("staging.internal.example" in x for x in _collect_env_host_candidates(body))


def test_no_lone_fetch_or_graphql_intel():
    body = 'fetch("/api"); axios.get("/x"); const q = gql`{ user { id } }`;'
    assert scan_js_frontend_intel("https://app.example/bundle.js", body) == []


def test_hidden_params_ignores_enabled():
    body = 'const cfg = { enabled: true, theme: "dark" };'
    assert scan_hidden_params_in_js("https://app.example/app.js", body) == []


def test_hidden_params_keeps_is_admin():
    body = 'const cfg = { "isAdmin": false, "debug": true };'
    findings = scan_hidden_params_in_js("https://app.example/app.js", body)
    assert findings and "isAdmin" in findings[0][2]


def test_transfer_requires_path_context():
    # Marketing copy mentioning "recipient" without a transfer path → no finding
    body = 'Thank you recipient for your transfer of goodwill.'
    assert scan_business_logic_hints("https://app.example/about", body) == []
    body2 = 'POST /api/transfer { "recipient": "alice", "amount": 10 }'
    findings = scan_business_logic_hints("https://app.example/wallet/transfer", body2)
    assert findings and findings[0][0] == "business_logic"


def test_env_probe_403_is_denied_not_exposed():
    class Resp:
        status_code = 403

    client = AsyncMock()
    client.get = AsyncMock(return_value=Resp())
    body = 'const h="https://staging.evil-lab.example/admin";'
    findings = asyncio.run(probe_js_env_hosts(client, "https://app.example/", body))
    assert findings
    assert findings[0][0] == "js_intel"
    assert findings[0][1] == "info"
    assert "denied" in findings[0][2].lower() or "403" in findings[0][2]


def test_env_probe_200_stays_low():
    class Resp:
        status_code = 200

    client = AsyncMock()
    client.get = AsyncMock(return_value=Resp())
    body = 'const h="https://dev-api.evil-lab.example/";'
    findings = asyncio.run(probe_js_env_hosts(client, "https://app.example/", body))
    assert findings
    assert "reachable" in findings[0][2].lower() or findings[0][1] == "low"


def test_maps_static_suppressed():
    assert is_google_browser_api_key("Google Cloud / Maps API Key", AIZA)
    assert severity_for_kind("Google Cloud / Maps API Key", "high", AIZA) == "info"
    static = assess_secrets_static(
        "Exposed Google Cloud / Maps API Key in response body",
        "low",
        AIZA,
    )
    assert static.suppress is True


def test_maps_live_restricted_suppressed():
    class FakeResp:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    from unittest.mock import MagicMock

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
    assert result.suppress is True


def test_maps_live_active_not_suppressed():
    class FakeResp:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}

        def json(self):
            return self._payload

    from unittest.mock import MagicMock

    http = MagicMock()
    http.get = AsyncMock(
        side_effect=[
            FakeResp(400),
            FakeResp(200, {"status": "OK", "results": []}),
            FakeResp(200, {"status": "OK", "results": []}),
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
    assert result.suppress is False
    assert result.validation == "active"
    assert result.severity == "medium"


def test_cors_credentialed_always_confirmed():
    result = assess_cors(
        "CORS reflects arbitrary Origin (https://evil.example) with credentials — high risk",
        "high",
        url="https://example.com/",
    )
    assert result.validation == "confirmed"
    assert result.severity == "medium"


def test_cors_host_dedupe():
    stats = CrawlStats()
    detail = "CORS reflects arbitrary Origin (https://evil.example) with credentials — high risk"
    stats.record_finding("cors", "high", "https://app.example/", detail)
    stats.record_finding("cors", "high", "https://app.example/login", detail)
    stats.record_finding("cors", "high", "https://app.example/api/v1", detail)
    assert len([f for f in stats.findings if f["category"] == "cors"]) == 1
    assert stats.finding_repeat_suppressed == 2


def test_js_intel_host_dedupe():
    stats = CrawlStats()
    ev = "js_env_leak: `staging.example (HTTP 403)`"
    stats.record_finding(
        "js_intel",
        "info",
        "https://cdn.example/a.js",
        "Non-prod/internal hosts referenced but access denied",
        evidence=ev,
    )
    stats.record_finding(
        "js_intel",
        "info",
        "https://cdn.example/b.js",
        "Non-prod/internal hosts referenced but access denied",
        evidence=ev,
    )
    assert len([f for f in stats.findings if f["category"] == "js_intel"]) == 1


def test_fetch_network_helpers_suppressed_in_impact():
    result = assess_tier_category(
        "js_intel",
        "Client bundle uses network helpers: fetch(), graphql",
        "info",
        "js_network: `fetch(), graphql`",
    )
    assert result.suppress is True
