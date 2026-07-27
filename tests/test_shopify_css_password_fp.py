"""Shopify CSS-module password-variant class maps must not raise secret findings."""

from __future__ import annotations

from security_scan import (
    classify_secret_candidate,
    scan_secrets,
    _should_skip_secret_match,
)

# Exact hydrate.BZfJPGDU.js false-positive snippet (Shopify checkout asset).
SHOPIFY_FIELD_TYPE_VARIANT = """
fieldTypeVariant: {
  number: "_7ozb2u19",
  tel: "_7ozb2u1a",
  text: "_7ozb2u1b",
  email: "_7ozb2u1c",
  url: "_7ozb2u1d",
  password: "_7ozb2u1e"
}
"""


def test_shopify_field_type_variant_password_class_not_secret():
    url = "https://cdn.shopify.com/s/files/1/checkout/hydrate.BZfJPGDU.js"
    assert scan_secrets(SHOPIFY_FIELD_TYPE_VARIANT, url) == []

    role = classify_secret_candidate(
        "password",
        "_7ozb2u1e",
        SHOPIFY_FIELD_TYPE_VARIANT,
        raw='password: "_7ozb2u1e"',
    )
    assert role == "css_class_mapping_not_secret"

    assert _should_skip_secret_match(
        label="Hardcoded Password",
        raw='password: "_7ozb2u1e"',
        body_text=SHOPIFY_FIELD_TYPE_VARIANT,
        start=SHOPIFY_FIELD_TYPE_VARIANT.find('password:'),
        end=SHOPIFY_FIELD_TYPE_VARIANT.find('password:') + len('password: "_7ozb2u1e"'),
        value="_7ozb2u1e",
    )


def test_styles_map_password_class_not_secret():
    body = """
    const styles = {
      number: "_abc123xy",
      text: "_abc123zz",
      password: "_abc123pw"
    };
    """
    assert scan_secrets(body, "https://example.com/bundle.js") == []
    assert (
        classify_secret_candidate("password", "_abc123pw", body, raw='password: "_abc123pw"')
        == "css_class_mapping_not_secret"
    )


def test_css_modules_double_underscore_class_not_secret():
    body = 'fieldTypeVariant.password = "Input_password__7ozb2u";'
    assert scan_secrets(body, "https://example.com/app.js") == []
    assert (
        classify_secret_candidate(
            "fieldTypeVariant.password",
            "Input_password__7ozb2u",
            body,
            raw=body,
        )
        == "css_class_mapping_not_secret"
    )


def test_genuine_password_assignments_still_fire():
    cases = [
        'password = "P@ssw0rd123!"',
        'credentials: {password: "hunter2secret!"}',
        'authPassword: "MyR3alPass!"',
        'const db_password = "S3curePassw0rd!";',
    ]
    for body in cases:
        hits = scan_secrets(body, "https://example.com/cfg.js")
        assert hits, body
        assert any("password" in (h[0] or "").lower() for h in hits), (body, hits)
        # Must not be classified as CSS class mapping
        for h in hits:
            val = h[3] or ""
            assert (
                classify_secret_candidate("password", val, body, raw=body)
                != "css_class_mapping_not_secret"
            )
