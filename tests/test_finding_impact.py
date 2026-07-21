"""Finding impact checkers cover all verifiable finding categories."""

from __future__ import annotations

import asyncio

from crawl_stats import CrawlStats
from finding_impact import assess_finding, impact_badge


def _assess(**kwargs):
    return asyncio.run(assess_finding(**kwargs))


def test_header_hardening_vs_info():
    hsts = _assess(category="header_audit", severity="medium", detail="missing HSTS")
    assert hsts.impact == "informational"
    assert hsts.role == "hardening"
    assert hsts.severity == "medium"

    ref = _assess(category="header_audit", severity="info", detail="missing Referrer-Policy")
    assert ref.severity == "info"
    assert ref.role == "hygiene"


def test_cookie_stealable_and_analytics_suppress():
    steal = _assess(
        category="authentication",
        severity="high",
        detail="Cookie `sessionid` Impact: stealable_credential. Missing HttpOnly",
    )
    assert steal.impact == "stealable_credential"

    analytics = _assess(
        category="authentication",
        severity="info",
        detail="Cookie `_ga` Impact: no_credential_impact. analytics cookie",
    )
    assert analytics.suppress is True
    assert analytics.impact == "no_impact"


def test_active_vs_passive_xss():
    active = _assess(
        category="xss",
        severity="high",
        detail="Active XSS confirmed: marker reflected in body",
    )
    assert active.impact == "confirmed"
    assert active.validation == "confirmed"

    passive = _assess(
        category="xss",
        severity="medium",
        detail="Parameter value reflected in HTML without encoding",
    )
    assert passive.impact == "possible"
    assert passive.validation == "unverified"


def test_cors_credentials_confirmed():
    result = _assess(
        category="cors",
        severity="high",
        detail="CORS reflects Origin with Access-Control-Allow-Credentials",
    )
    assert result.impact == "confirmed"
    assert result.severity == "high"


def test_sensitive_path_with_proof():
    result = _assess(
        category="sensitive_path",
        severity="high",
        detail="Sensitive path pattern matched: /.env",
        evidence="KEY=value line present",
    )
    assert result.impact == "confirmed"
    assert result.validation == "confirmed"


def test_mixed_content_script_vs_image():
    script = _assess(
        category="mixed_content",
        severity="medium",
        detail="HTTPS page loads http://cdn.example/app.js",
    )
    assert script.impact == "possible"

    img = _assess(
        category="mixed_content",
        severity="medium",
        detail="HTTPS page loads 2 HTTP resource(s); e.g. http://x/a.png",
    )
    assert img.impact == "limited_impact"


def test_secrets_static_unverified():
    result = _assess(
        category="secrets_exposure",
        severity="high",
        detail="Exposed Boomr API Key in response body",
        evidence="Fc8f46b5abcdef0123456789abcdef01",
        validate_secrets_live=False,
    )
    assert result.impact == "possible_credential"
    assert result.validation == "unverified"


def test_record_finding_stores_impact_fields():
    stats = CrawlStats()
    stats.record_finding(
        "cors",
        "high",
        "https://example.com/",
        "CORS credentials misconfig",
        impact="confirmed",
        role="cors",
        validation="confirmed",
        impact_summary="credentialed CORS",
    )
    assert stats.findings
    row = stats.findings[0]
    assert row["impact"] == "confirmed"
    assert row["validation"] == "confirmed"
    assert row["role"] == "cors"


def test_impact_badge():
    assert impact_badge("confirmed", "confirmed") == "confirmed / confirmed"
    assert impact_badge("possible", "n/a") == "possible"
