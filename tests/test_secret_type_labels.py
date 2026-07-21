"""Vendor-specific secret type labeling."""

from __future__ import annotations

from finding_explain import explain_finding
from security_scan import refine_secret_label, scan_secrets, secret_reveal_html


def test_aws_access_key_typed():
    hits = scan_secrets('const k = "AKIAPRODKEY9X7M2Q4R8";', "https://x/a.js")
    assert hits
    assert hits[0][0] == "AWS Access Key ID"


def test_virustotal_from_assignment_name():
    body = 'virustotal_api_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";'
    hits = scan_secrets(body, "https://x/config.js")
    assert hits
    assert hits[0][0] == "VirusTotal API Key"
    assert "VirusTotal" in hits[0][2]


def test_generic_refined_by_context():
    label = refine_secret_label(
        "Generic API Key",
        'api_key="abcdefghijklmnopqrstuvwxyz012345"',
        'const shodan_api_key = "abcdefghijklmnopqrstuvwxyz012345";',
        6,
        50,
    )
    assert label == "Shodan API Key"


def test_explain_title_uses_secret_type():
    expl = explain_finding("secrets_exposure", "Exposed VirusTotal API Key in response body")
    assert expl["title"] == "Exposed VirusTotal API Key"
    assert "VirusTotal" in expl["what"]


def test_secret_reveal_html_includes_type():
    html = secret_reveal_html("AIzaSyD-RealKeyValue0123456789AbCdEfGhI", secret_type="Google Cloud / Maps API Key")
    assert "Google Cloud / Maps API Key" in html
    assert "secret-type" in html
