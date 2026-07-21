"""Form-field / UI-keyword false positives must not raise secret findings."""

from __future__ import annotations

from security_scan import scan_secrets


def test_form_input_keywords_are_not_secrets():
    html = """
    <form action="/login" method="post">
      <label for="api_key">API Key</label>
      <input type="text" name="api_key" id="api_key" placeholder="Enter your API key">
      <input type="password" name="password" id="password" placeholder="Password"
             autocomplete="current-password">
      <input type="hidden" name="csrf_token" value="abcdefghijklmnopqrstuvwxyz012345">
    </form>
    """
    assert scan_secrets(html, "https://example.com/login") == []


def test_echoed_field_name_as_value_is_fp():
    bodies = [
        'password: "password"',
        'const password = "password";',
        'apiKey: "apiKey"',
        'api_key = "api_key"',
        'secret: "secretsecret12"',
        'user_password = "formFieldKeyword"',
    ]
    for body in bodies:
        assert scan_secrets(body, "https://example.com/app.js") == [], body


def test_data_api_key_on_input_is_fp():
    html = '<input data-api-key="Fc8f46b5abcdef0123456789abcdef01" name="token" />'
    assert scan_secrets(html, "https://example.com/") == []


def test_real_js_assignment_still_fires():
    body = 'const boomr_api_key = "Fc8f46b5abcdef0123456789abcdef01";'
    hits = scan_secrets(body, "https://example.com/app.js")
    assert hits
    assert hits[0][0] == "Boomr API Key"
    assert hits[0][3] == "Fc8f46b5abcdef0123456789abcdef01"


def test_real_password_still_fires():
    body = 'username = "admin";\ndb_password = "S3curePassw0rd!";\n'
    hits = scan_secrets(body, "https://example.com/cfg.js")
    assert hits
    assert any(h[0] == "Db ID and Password" for h in hits)


def test_html_tag_not_used_as_product_name():
    # If a non-form tag attribute still matches, never title it "Div/Input …"
    body = '<div class="cfg">const api_key = "abcdefghijklmnopqrstuvwxyz012345";</div>'
    hits = scan_secrets(body, "https://example.com/")
    assert hits
    assert not any(h[0].startswith(("Div ", "Input ", "Script ")) for h in hits)
    assert hits[0][0] in {"API Key", "Generic API Key"} or "API Key" in hits[0][0]


def test_aws_prefix_still_detected_in_html():
    html = '<html><body>key=AKIAPRODKEY9X7M2Q4R8</body></html>'
    hits = scan_secrets(html, "https://example.com/")
    assert hits
    assert hits[0][0] == "AWS Access Key ID"
