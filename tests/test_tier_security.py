"""Tier 2–6 probes: OAuth/JWT/GraphQL/mass-assignment/proof gating."""

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import AsyncMock

from finding_kind import classify_finding_kind
from finding_proof import gate_severity
from tier_security import (
    run_tier_passive,
    scan_hidden_params_in_js,
    scan_jwt_flaws,
    scan_oauth_sso,
    scan_js_frontend_intel,
    probe_graphql_schema,
    probe_mass_assignment,
)


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_gate_severity_detected_caps_at_low():
    assert gate_severity("high", verification="detected") == "low"
    assert gate_severity("info", verification="detected") == "info"


def test_gate_severity_verified_caps_at_medium():
    assert gate_severity("high", verification="verified") == "medium"
    assert gate_severity("medium", verification="verified") == "medium"


def test_gate_severity_confirmed_allows_high():
    assert gate_severity("high", verification="confirmed") == "high"
    assert gate_severity("critical", verification="exploitable") == "critical"


def test_oauth_missing_state():
    url = "https://idp.example/oauth/authorize?client_id=abc&response_type=code&redirect_uri=https://app.example/cb"
    findings = scan_oauth_sso(url, "")
    assert any("missing state" in f[2].lower() for f in findings)
    assert any(f[0] == "oauth" and f[1] == "medium" for f in findings)


def test_oauth_token_leak_in_url():
    url = "https://app.example/callback?access_token=ya29.secretvalue1234567890"
    findings = scan_oauth_sso(url, "")
    assert any("token leakage" in f[2].lower() for f in findings)


def test_jwt_none_algorithm():
    token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1'})}."
    findings = scan_jwt_flaws("https://app.example/", f"auth={token}")
    assert any("alg=none" in f[2].lower() for f in findings)


def test_hidden_params_from_js():
    body = 'const cfg = { "isAdmin": false, "debug": true, role: "user" };'
    findings = scan_hidden_params_in_js("https://app.example/app.js", body)
    assert findings and findings[0][0] == "mass_assignment"
    assert "isAdmin" in findings[0][2] or "debug" in findings[0][2]


def test_js_intel_mines_fetch_and_env():
    body = 'fetch("/api/v1"); const h = "https://staging.internal.example/admin";'
    findings = scan_js_frontend_intel("https://app.example/bundle.js", body)
    cats = {f[0] for f in findings}
    assert "js_intel" in cats
    assert any("fetch()" in f[2] for f in findings)
    assert any("staging" in f[2].lower() for f in findings)


def test_passive_tier_wired():
    url = "https://app.example/oauth/authorize?client_id=x&response_type=code"
    out = run_tier_passive(url, "accounts.google.com oauth", forms=[], headers={})
    assert any(f[0] == "oauth" for f in out)


def test_graphql_introspection_confirmed():
    class Resp:
        status_code = 200
        text = '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"User"}]}}}'

    client = AsyncMock()
    client.post = AsyncMock(return_value=Resp())
    findings = asyncio.run(probe_graphql_schema(client, "https://api.example/graphql"))
    assert findings and findings[0][0] == "graphql"
    assert findings[0][1] in ("medium", "high")
    assert len(findings[0]) >= 5
    assert findings[0][4]["verification"] == "confirmed"


def test_mass_assignment_reflection():
    class Resp:
        status_code = 200
        text = '{"ok":true,"role":"admin","isAdmin":true}'

    client = AsyncMock()
    client.post = AsyncMock(return_value=Resp())
    findings = asyncio.run(probe_mass_assignment(client, "https://api.example/api/users/1"))
    assert findings and findings[0][0] == "mass_assignment"
    assert findings[0][1] == "high"


def test_info_oauth_is_hardening_kind():
    kind = classify_finding_kind(
        category="oauth",
        severity="info",
        detail="SSO/OAuth providers referenced: Google Login",
    )
    assert kind == "hardening"


def test_verified_oauth_is_vulnerability_kind():
    kind = classify_finding_kind(
        category="oauth",
        severity="medium",
        detail="OAuth authorize flow missing state parameter",
    )
    assert kind == "vulnerability"
