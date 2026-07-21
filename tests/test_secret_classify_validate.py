"""Dynamic credential typing + read-only live validation."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from secret_classify import classify_credential, parse_ident_kind
from secret_validate import format_validation_suffix, validate_secret
from security_scan import refine_secret_label, scan_secrets


def test_parse_ident_kind_product_api_key():
    product, kind = parse_ident_kind("paypal_api_key")
    assert product == "PayPal"
    assert kind == "API Key"


def test_parse_ident_kind_activation():
    product, kind = parse_ident_kind("ACME_ACTIVATION_KEY")
    assert product == "Acme"
    assert kind == "Activation Key"


def test_classify_paypal_api_key():
    body = 'const paypal_api_key = "abcdefghijklmnopqrstuvwxyz0123456789";'
    label = classify_credential(
        base_label="Named Credential",
        raw='paypal_api_key = "abcdefghijklmnopqrstuvwxyz0123456789"',
        body_text=body,
        start=0,
        end=len(body),
        value="abcdefghijklmnopqrstuvwxyz0123456789",
    )
    assert label == "PayPal API Key"


def test_scan_paypal_and_activation():
    body = (
        'paypal_api_key = "abcdefghijklmnopqrstuvwxyz0123456789";\n'
        'ACME_ACTIVATION_KEY = "ACT-9f8e7d6c5b4a3210deadbeef";\n'
    )
    hits = scan_secrets(body, "https://x/cfg.js")
    types = {h[0] for h in hits}
    assert "PayPal API Key" in types
    assert "Acme Activation Key" in types


def test_scan_id_and_password():
    body = 'username = "admin";\ndb_password = "S3curePassw0rd!";\n'
    hits = scan_secrets(body, "https://x/cfg.js")
    assert hits
    assert any(h[0] == "Db ID and Password" for h in hits)
    assert any("assigned to `db_password`" in h[2] for h in hits)


def test_related_provider_variable():
    """Bare api_key classified via nearby provider/service assignment."""
    body = (
        'const creds = {\n'
        '  provider: "paypal",\n'
        '  api_key: "abcdefghijklmnopqrstuvwxyz0123456789"\n'
        '};\n'
    )
    hits = scan_secrets(body, "https://x/cfg.js")
    assert hits
    assert hits[0][0] == "PayPal API Key"
    assert "assigned to" in hits[0][2]


def test_dotted_path_assignment():
    body = 'config.sendgrid.apiKey = "SG.' + ("a" * 22) + "." + ("b" * 43) + '";\n'
    hits = scan_secrets(body, "https://x/cfg.js")
    assert hits
    # Prefix lock keeps SendGrid API Key for SG. shape
    assert hits[0][0] == "SendGrid API Key"
    assert "config.sendgrid.apiKey" in hits[0][2]


def test_sibling_brand_in_related_idents():
    body = (
        'const paypalClientId = "AeAAAAclientidvalue012345";\n'
        'const api_key = "abcdefghijklmnopqrstuvwxyz0123456789";\n'
    )
    hits = scan_secrets(body, "https://x/cfg.js")
    types = {h[0] for h in hits}
    assert "PayPal API Key" in types


def test_refine_shodan_still_works():
    label = refine_secret_label(
        "Generic API Key",
        'api_key="abcdefghijklmnopqrstuvwxyz012345"',
        'const shodan_api_key = "abcdefghijklmnopqrstuvwxyz012345";',
        6,
        50,
    )
    assert label == "Shodan API Key"


def test_format_validation_suffix():
    from secret_validate import ValidationResult

    s = format_validation_suffix(ValidationResult(status="active", summary="ok"))
    assert "[live: ACTIVE" in s
    assert "ok" in s


def test_validate_stripe_active():
    http = AsyncMock()
    resp = MagicMock()
    resp.status_code = 200
    http.get = AsyncMock(return_value=resp)

    result = asyncio.run(
        validate_secret("Stripe Live Secret Key", "sk_live_" + ("a" * 24), client=http)
    )
    assert result.status == "active"
    assert "Stripe" in result.summary


def test_validate_unknown_vendor_skipped():
    result = asyncio.run(
        validate_secret("Acme Activation Key", "ACT-9f8e7d6c5b4a3210deadbeef")
    )
    assert result.status == "skipped"
