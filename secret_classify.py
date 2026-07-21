"""Classify discovered credentials by product + kind from surrounding context.

Examples:
  paypal_api_key=...     → PayPal API Key
  ACME_ACTIVATION_KEY=…  → Acme Activation Key
  db_password=… (+ user) → Db ID and Password
  AKIA…                  → AWS Access Key ID (prefix wins over context)
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# Ordered: longer / more specific kinds first.
_KIND_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"secret[_-]?access[_-]?keys?", "Secret Access Key"),
    (r"access[_-]?keys?", "Access Key"),
    (r"activation[_-]?keys?", "Activation Key"),
    (r"license[_-]?keys?", "License Key"),
    (r"private[_-]?keys?", "Private Key"),
    (r"api[_-]?keys?", "API Key"),
    (r"api[_-]?secrets?", "API Secret"),
    (r"api[_-]?tokens?", "API Token"),
    (r"client[_-]?secrets?", "Client Secret"),
    (r"client[_-]?ids?", "Client ID"),
    (r"auth[_-]?tokens?", "Auth Token"),
    (r"access[_-]?tokens?", "Access Token"),
    (r"refresh[_-]?tokens?", "Refresh Token"),
    (r"bearer[_-]?tokens?", "Bearer Token"),
    (r"session[_-]?tokens?", "Session Token"),
    (r"app[_-]?secrets?", "App Secret"),
    (r"app[_-]?keys?", "App Key"),
    (r"consumer[_-]?secrets?", "Consumer Secret"),
    (r"consumer[_-]?keys?", "Consumer Key"),
    (r"passwords?", "Password"),
    (r"passwds?", "Password"),
    (r"passphrases?", "Passphrase"),
    (r"secrets?", "Secret"),
    (r"tokens?", "Token"),
    (r"credentials?", "Credential"),
    (r"keys?", "Key"),
)

_IDENT_ASSIGN_RE = re.compile(
    r"(?i)(?:[\"'](?P<qident>[A-Za-z][\w.\-]{1,80})[\"']|(?P<ident>[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z0-9]+)*))"
    r"\s*[:=]\s*[\"']?(?P<value>[^\"'\s]{6,})"
)

_STOP_PRODUCTS = {
    "const",
    "let",
    "var",
    "export",
    "import",
    "return",
    "this",
    "self",
    "process",
    "env",
    "config",
    "options",
    "headers",
    "data",
    "body",
    "json",
    "string",
    "true",
    "false",
    "null",
    "undefined",
    "window",
    "document",
    "module",
    "exports",
    "require",
    "function",
    "class",
    "async",
    "await",
}


def _split_ident(ident: str) -> list[str]:
    text = (ident or "").replace(".", "_").replace("-", "_")
    # camelCase / PascalCase → snake
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    return [p for p in text.split("_") if p]


_BRAND_TITLES = {
    "paypal": "PayPal",
    "github": "GitHub",
    "gitlab": "GitLab",
    "openai": "OpenAI",
    "virustotal": "VirusTotal",
    "sendgrid": "SendGrid",
    "mailgun": "MailGun",
    "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean",
    "hashicorp": "HashiCorp",
    "datadog": "Datadog",
    "pagerduty": "PagerDuty",
    "shopify": "Shopify",
    "twilio": "Twilio",
    "stripe": "Stripe",
    "shodan": "Shodan",
    "censys": "Censys",
    "abuseipdb": "AbuseIPDB",
    "urlscan": "urlscan.io",
    "alienvault": "AlienVault",
    "mongodb": "MongoDB",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "redis": "Redis",
    "aws": "AWS",
    "gcp": "GCP",
    "azure": "Azure",
    "npm": "npm",
}


def _title_product(parts: list[str]) -> str:
    if not parts:
        return ""
    # Keep short acronyms upper (AWS, VT, API already stripped as kind)
    out = []
    for p in parts:
        key = p.lower()
        if key in _BRAND_TITLES:
            out.append(_BRAND_TITLES[key])
        elif p.isupper() and 2 <= len(p) <= 3:
            # Short acronyms (AWS, GCP) — longer ALLCAPS like ACME → title case
            out.append(p.upper())
        elif key in ("id", "ids"):
            out.append("ID")
        else:
            out.append(p[:1].upper() + p[1:].lower())
    return " ".join(out)


def parse_ident_kind(ident: str) -> Tuple[str, str]:
    """Return (product, kind) from an identifier like paypal_api_key."""
    parts = _split_ident(ident)
    if not parts:
        return "", ""
    joined = "_".join(parts)
    for pat, kind in _KIND_PATTERNS:
        m = re.search(rf"(?i)(?:^|_)({pat})$", joined)
        if not m:
            continue
        kind_start = m.start(1)
        product_joined = joined[:kind_start].rstrip("_")
        product_parts = [p for p in product_joined.split("_") if p and p.lower() not in _STOP_PRODUCTS]
        return _title_product(product_parts), kind
    # No kind suffix — treat whole ident as product, unknown kind
    filtered = [p for p in parts if p.lower() not in _STOP_PRODUCTS]
    return _title_product(filtered), ""


def classify_credential(
    *,
    base_label: str,
    raw: str,
    body_text: str,
    start: int,
    end: int,
    value: str = "",
) -> str:
    """Build a human label: '{Product} {Kind}' when context allows, else base_label."""
    window = body_text[max(0, start - 120) : min(len(body_text), end + 80)]
    val = (value or "").strip() or raw

    # Prefer identifier immediately before this assignment
    product, kind = "", ""
    for m in _IDENT_ASSIGN_RE.finditer(window):
        cand = m.group("value") or ""
        if not cand:
            continue
        # Match this secret's value (prefix enough for long tokens)
        if val.startswith(cand[:12]) or cand.startswith(val[:12]) or cand == val:
            ident = m.group("ident") or m.group("qident") or ""
            product, kind = parse_ident_kind(ident)
            break

    # Nearby username/id for password findings
    if (kind == "Password" or "password" in (base_label or "").lower()) and re.search(
        r"(?i)\b(user(name)?|login|email|account[_-]?id|user[_-]?id)\b\s*[:=]",
        window,
    ):
        if product:
            return f"{product} ID and Password"
        return "ID and Password"

    _GENERIC_BASES = {
        "Generic API Key",
        "Hardcoded Password",
        "Hardcoded Client Secret",
        "Hardcoded Secret",
        "Named Credential",
        "Activation / License Key",
    }

    if product and kind:
        return f"{product} {kind}"
    if kind and not product:
        # e.g. bare api_key=
        return kind if kind != "Key" else (base_label or "API Key")
    if product and not kind:
        # product-only with a generic base
        if base_label and base_label not in _GENERIC_BASES:
            return base_label
        return f"{product} Credential"

    return base_label or "Credential"


def severity_for_kind(label: str, default: str = "high") -> str:
    low = (label or "").lower()
    if any(x in low for x in ("password", "private key", "secret access", "client secret", "auth token")):
        return "critical" if "publishable" not in low else "medium"
    if "publishable" in low or "client id" in low:
        return "medium"
    return default
