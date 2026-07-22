"""R3ResetPass / password-reset deep-link classification — not secrets."""

from __future__ import annotations

from finding_impact import assess_secrets_static
from report_status import assessment_state_for_finding, include_in_remediation
from security_scan import (
    classify_secret_candidate,
    scan_password_reset_deep_links,
    scan_secrets,
    _should_skip_secret_match,
)


def test_r3resetpass_never_secret():
    body = (
        'const FORGOT_PASSWORD = "R3ResetPass";'
        'const RESET_PASSWORD = "R3ResetPass";'
        'switch (query.src.toLowerCase()) {'
        '  case "r3resetpass": navigateToResetPassword(); break;'
        "}"
    )
    findings = scan_secrets(body, "https://lab.example/app.js")
    assert not any(
        "R3ResetPass" in (f[2] or "") or "R3ResetPass" in (f[3] or "") for f in findings
    )
    assert _should_skip_secret_match(
        label="Hardcoded Password",
        raw='password="R3ResetPass"',
        body_text='FORGOT_PASSWORD="R3ResetPass"',
        start=0,
        end=20,
        value="R3ResetPass",
    )
    assert classify_secret_candidate("FORGOT_PASSWORD", "R3ResetPass") == "flow_or_route_identifier"
    assert classify_secret_candidate("src", "R3ResetPass") == "flow_or_route_identifier"
    assert (
        classify_secret_candidate("", "R3ResetPass")
        == "known_non_secret_flow_identifier"
    )


def test_password_lhs_with_flow_value_not_secret():
    """Do not treat strings as passwords merely because LHS contains PASSWORD."""
    body = 'RESET_PASSWORD = "R3Reset-Pass"; FORGOT_PASSWORD="R3ResetPass";'
    findings = scan_secrets(body, "https://lab.example/bundle.js")
    assert findings == []


def test_deep_link_surface_not_credential():
    body = (
        'const FORGOT_PASSWORD = "R3ResetPass";\n'
        "function go(query) {\n"
        '  if (query.src.toLowerCase() === "r3resetpass") navigateToResetPassword();\n'
        "  const token = query.token;\n"
        "  delete props.query.token;\n"
        "  delete props.query.src;\n"
        "}\n"
    )
    findings = scan_password_reset_deep_links("https://lab.example/app.js", body)
    assert findings
    assert any("deep-link" in f[2].lower() for f in findings)
    assert all(f[1] in ("info", "low") for f in findings)
    # Should note address-bar hygiene when delete-without-replaceState is present
    assert any("token" in f[2].lower() for f in findings)


def test_r3resetpass_impact_suppressed_from_secrets():
    result = assess_secrets_static(
        "Exposed Reset Password in response body",
        "high",
        evidence="R3ResetPass",
    )
    assert result.suppress is True
    assert result.validation == "invalid"
    assert result.role == "flow_identifier"
    assert include_in_remediation(
        {
            "validation": "invalid",
            "verification": "detected",
            "assessment_state": "False positive / invalidated",
            "title": "Exposed Reset Password",
        }
    ) is False


def test_deep_link_assessment_state():
    state = assessment_state_for_finding(
        category="authentication",
        severity="info",
        validation="unverified",
        detail="Password-reset deep-link flow discovered (src=R3ResetPass)",
    )
    assert state == "Attack-surface observation"


def test_localization_labels_skipped():
    for label in ("Vérifier", "Réinitialiser", "verifier"):
        assert classify_secret_candidate("btn", label) in {
            "localization_or_ui_label",
            "known_non_secret_flow_identifier",
        }
