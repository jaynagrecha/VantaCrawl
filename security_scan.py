"""Security testing helpers — authorized targets only."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

SECRET_PATTERNS = [
    # Cloud / infra (specific prefixes first)
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?<![A-Za-z0-9])ASIA[0-9A-Z]{16}", "AWS Temporary Access Key ID", "critical"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}", "AWS Secret Access Key", "critical"),
    (r"(?i)aws[_-]?session[_-]?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{80,}", "AWS Session Token", "critical"),
    # Source control / CI
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "critical"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub Fine-grained PAT", "critical"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "critical"),
    (r"ghu_[A-Za-z0-9]{36}", "GitHub User-to-Server Token", "critical"),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab Personal Access Token", "critical"),
    # Payments / SaaS
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "critical"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Live Key", "critical"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", "medium"),
    (r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI API Key", "critical"),
    # Browser-embeddable Maps keys are client/public by design — start medium, escalate only with evidence
    (r"AIza[0-9A-Za-z\-_]{35}", "Google Cloud / Maps API Key", "medium"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,48}-[0-9A-Za-z-]{10,48}(?:-[0-9A-Za-z-]{10,48})?", "Slack API Token", "critical"),
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", "critical"),
    # Mailgun keys are key-<32 hex>. Exclude hyphen before "key-" so webpack
    # chunk names like chunk-key-<hex>.js do not match.
    (r"(?<![A-Za-z0-9_-])key-[0-9a-f]{32}(?![A-Za-z0-9_.])", "Mailgun API Key", "high"),
    # Twilio API Key SIDs need SK + 32 hex AND nearby twilio/account context (checked in scan_secrets)
    (r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])", "Twilio API Key SID", "high"),
    (r"(?i)twilio[_-]?(?:auth[_-]?)?token['\"]?\s*[:=]\s*['\"][0-9a-fA-F]{32}", "Twilio Auth Token", "critical"),
    (r"shpat_[a-fA-F0-9]{32}", "Shopify Admin API Access Token", "critical"),
    (r"npm_[A-Za-z0-9]{36}", "npm Access Token", "critical"),
    (r"dop_v1_[a-f0-9]{64}", "DigitalOcean Personal Access Token", "critical"),
    (r"hvs\.[A-Za-z0-9_-]{20,}", "HashiCorp Vault Token", "critical"),
    # Threat intel / security vendors
    (r"(?i)virus\s*total[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{32,}", "VirusTotal API Key", "high"),
    (r"(?i)vt[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"][A-Fa-f0-9]{64}", "VirusTotal API Key", "high"),
    (r"(?i)shodan[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{32}", "Shodan API Key", "high"),
    (r"(?i)censys[_-]?(?:api[_-]?)?(?:id|secret|key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}", "Censys API Credential", "high"),
    (r"(?i)abuseipdb[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{20,}", "AbuseIPDB API Key", "high"),
    (r"(?i)alienvault[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{20,}", "AlienVault OTX API Key", "high"),
    (r"(?i)urlscan[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-]{20,}", "urlscan.io API Key", "high"),
    # Private keys / passwords
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key (PEM)", "critical"),
    (r"(?i)(?:^|[^\w])(?:[A-Za-z][\w]*)[_-]passwords?['\"]?\s*[:=]\s*['\"][^\s'\"]{8,}", "Hardcoded Password", "high"),
    (r"(?i)password['\"]?\s*[:=]\s*['\"][^\s'\"]{8,}", "Hardcoded Password", "high"),
    (r"(?i)(?:client_)?secret['\"]?\s*[:=]\s*['\"][^\s'\"]{12,}", "Hardcoded Client Secret", "medium"),
    # Product-named credentials (paypal_api_key, ACME_ACTIVATION_KEY, …)
    (
        r"(?i)(?:^|[^\w])(?:[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z0-9]+){0,8})[_-]"
        r"(?:api[_-]?keys?|api[_-]?secrets?|api[_-]?tokens?|access[_-]?keys?|secret[_-]?keys?|"
        r"activation[_-]?keys?|license[_-]?keys?|auth[_-]?tokens?|access[_-]?tokens?|"
        r"refresh[_-]?tokens?|client[_-]?secrets?|app[_-]?secrets?|app[_-]?keys?|"
        r"consumer[_-]?secrets?|consumer[_-]?keys?|session[_-]?tokens?|bearer[_-]?tokens?)"
        r"['\"]?\s*[:=]\s*['\"][^\s'\"]{10,}",
        "Named Credential",
        "high",
    ),
    (r"(?i)(?:activation|license|product|serial)[_-]?keys?['\"]?\s*[:=]\s*['\"][^\s'\"]{8,}", "Activation / License Key", "high"),
    # Generic last — refined via nearby variable names when possible
    (r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}", "Generic API Key", "high"),
]

# When a generic pattern matches, upgrade the label from nearby assignment context.
SECRET_CONTEXT_LABELS = [
    (r"(?i)virus\s*total|\bvt[_-]?(?:api)?", "VirusTotal API Key"),
    (r"(?i)\baws\b|amazon[_-]?web|secret[_-]?access[_-]?key", "AWS Credential"),
    (r"(?i)google|gcp|firebase|maps[_-]?api", "Google API Key"),
    (r"(?i)openai|chatgpt", "OpenAI API Key"),
    (r"(?i)anthropic|claude", "Anthropic API Key"),
    (r"(?i)slack", "Slack API Token"),
    (r"(?i)stripe", "Stripe API Key"),
    (r"(?i)twilio", "Twilio API Credential"),
    (r"(?i)sendgrid", "SendGrid API Key"),
    (r"(?i)mailgun", "Mailgun API Key"),
    (r"(?i)shodan", "Shodan API Key"),
    (r"(?i)github|gh[_-]?token|ghp_", "GitHub Token"),
    (r"(?i)gitlab|glpat", "GitLab Token"),
    (r"(?i)azure|microsoft", "Azure / Microsoft API Key"),
    (r"(?i)cloudflare|cf[_-]?api", "Cloudflare API Token"),
    (r"(?i)datadog", "Datadog API Key"),
    (r"(?i)new[_-]?relic", "New Relic License / API Key"),
    (r"(?i)pagerduty", "PagerDuty API Key"),
    (r"(?i)sentry", "Sentry Auth / DSN Token"),
    (r"(?i)heroku", "Heroku API Key"),
    (r"(?i)digitalocean|do[_-]?token", "DigitalOcean Token"),
    (r"(?i)npm[_-]?token", "npm Access Token"),
    (r"(?i)shopify", "Shopify API Token"),
    (r"(?i)abuseipdb", "AbuseIPDB API Key"),
    (r"(?i)urlscan", "urlscan.io API Key"),
    (r"(?i)censys", "Censys API Credential"),
]

# Placeholder / documentation values that must not raise secret findings
SECRET_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?api[_-]?key|example[_-]?key|sample[_-]?key|\bdummy\b|"
    r"\bplaceholder\b|changeme|\bxxx{2,}\b|\btest[_-]?key\b|not[_-]?a[_-]?real|"
    r"replace[_-]?me|\bpassword123\b|sk_test_|pk_test_|akiaiosfodnn7example|"
    r"enter\s+(?:your\s+)?(?:api\s*)?key|enter\s+(?:your\s+)?password)"
)

# Form / UI field keywords — often appear as both the LHS and the echoed value
# (password:"password", apiKey:"apiKey") or as HTML control labels. Not secrets.
_FORM_FIELD_KEYWORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "secrets",
        "token",
        "tokens",
        "api_key",
        "api-key",
        "apikey",
        "api_keys",
        "access_token",
        "accesstoken",
        "access-token",
        "refresh_token",
        "refreshtoken",
        "client_secret",
        "clientsecret",
        "client_id",
        "clientid",
        "username",
        "user",
        "userid",
        "user_id",
        "email",
        "login",
        "auth",
        "authorization",
        "bearer",
        "key",
        "keys",
        "private_key",
        "privatekey",
        "public_key",
        "publickey",
        "csrf",
        "csrftoken",
        "csrf_token",
        "session",
        "sessionid",
        "session_id",
        "otp",
        "pin",
        "ssn",
        "cvv",
        "cvc",
        "card",
        "cardnumber",
        "card_number",
        "activation_key",
        "activationkey",
        "license_key",
        "licensekey",
        "new_password",
        "newpassword",
        "current_password",
        "currentpassword",
        "confirm_password",
        "confirmpassword",
        "old_password",
        "oldpassword",
    }
)

_FORM_CONTROL_TAGS = (
    "input",
    "textarea",
    "select",
    "option",
    "button",
    "label",
    "fieldset",
    "legend",
    "datalist",
    "output",
    "form",
)

# Generic assignment patterns are noisy in HTML/UI; prefix-shaped vendor keys stay allowed.
_GENERIC_SECRET_LABELS_FOR_FP = frozenset(
    {
        "Generic API Key",
        "Hardcoded Client Secret",
        "Hardcoded Password",
        "Hardcoded Secret",
        "Named Credential",
        "Activation / License Key",
    }
)

_IDENT_LIKE_VALUE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{2,47}$")
_LHS_ASSIGN_RE = re.compile(
    r"(?i)(?P<lhs>[A-Za-z_][\w.\-]*?)\s*['\"]?\s*[:=]\s*['\"]?(?P<rhs>[^\s'\"]{3,})\s*$"
)

# Exact sensitive segments / known filenames — avoid matching prose paths like backup-restore-policy
SENSITIVE_PATH_RE = re.compile(
    r"(?i)/(?:"
    r"\.env(?:\.[a-z0-9_-]+)?|"
    r"web\.config|"
    r"\.git(?:/[^?\s]*)?|"
    r"phpinfo(?:\.php)?|"
    r"\.aws(?:/[^?\s]*)?|"
    r"id_rsa|"
    r"\.htpasswd|"
    r"config\.php|"
    r"wp-config(?:\.php)?|"
    # Require archive/db extension — bare /backup|/dump pages are common CMS FPs
    r"(?:backup|dump|site-backup|db-backup|www-backup)\.(?:zip|tar|gz|tgz|sql|bak|7z|rar)"
    r")(?:/|$|\?)",
)

SECURITY_HEADERS = {
    # Hardening observations — not standalone Medium vulnerabilities.
    # CSP may be elevated later when XSS is co-observed on the same host.
    "strict-transport-security": ("missing HSTS", "info"),
    "content-security-policy": ("missing CSP", "info"),
    "x-frame-options": ("missing X-Frame-Options (clickjacking)", "info"),
    "x-content-type-options": ("missing X-Content-Type-Options", "info"),
    "referrer-policy": ("missing Referrer-Policy", "info"),
    "permissions-policy": ("missing Permissions-Policy", "info"),
}

PARAM_NAME_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-\[\]]*)=")


def extract_secret_value(raw: str) -> str:
    """Pull the assigned token/value from a pattern match (or return the raw match)."""
    value = (raw or "").strip()
    if not value:
        return ""
    assign = re.search(r"[:=]\s*['\"]?([^\s'\"]{6,})", value)
    if assign:
        return assign.group(1)
    return value


def mask_secret_value(raw: str, *, keep_start: int = 4, keep_end: int = 4) -> str:
    """Display mask for an accessible secret (full value is stored separately for reveal)."""
    value = extract_secret_value(raw)
    if not value:
        return ""
    if len(value) <= keep_start + keep_end + 2:
        return value[:2] + "***" + (value[-1:] if len(value) > 3 else "")
    return f"{value[:keep_start]}…{value[-keep_end:]}"


def secret_reveal_html(full: str, *, secret_type: str = "") -> str:
    """HTML chip: type label + masked value, <details> to reveal the full secret."""
    from html import escape

    value = extract_secret_value(full) or (full or "").strip()
    if not value:
        return ""
    masked = mask_secret_value(value)
    type_html = (
        f"<span class='secret-type'>{escape(secret_type)}</span> "
        if (secret_type or "").strip()
        else ""
    )
    return (
        "<li class='secret-reveal'>"
        f"{type_html}"
        f"<code class='secret-masked'>{escape(masked)}</code> "
        "<details class='secret-details'>"
        "<summary>Show full</summary>"
        f"<code class='secret-full'>{escape(value)}</code>"
        "</details>"
        "</li>"
    )


_GENERIC_SECRET_LABELS = frozenset(
    {
        "Generic API Key",
        "Hardcoded Client Secret",
        "Hardcoded Password",
        "Hardcoded Secret",
        "Named Credential",
        "Activation / License Key",
    }
)

# Prefix/shape labels that already name the vendor — keep unless variables
# give a clear product+kind that is at least as specific.
_PREFIX_LOCKED_LABELS = frozenset(
    {
        "AWS Access Key ID",
        "AWS Temporary Access Key ID",
        "AWS Secret Access Key",
        "AWS Session Token",
        "GitHub Personal Access Token",
        "GitHub Fine-grained PAT",
        "GitHub OAuth Token",
        "GitHub User-to-Server Token",
        "GitLab Personal Access Token",
        "Stripe Live Secret Key",
        "Stripe Restricted Live Key",
        "Stripe Live Publishable Key",
        "OpenAI API Key",
        "Slack API Token",
        "SendGrid API Key",
        "Mailgun API Key",
        "Twilio API Key SID",
        "Twilio Auth Token",
        "Shopify Admin API Access Token",
        "npm Access Token",
        "DigitalOcean Personal Access Token",
        "HashiCorp Vault Token",
        "Private Key (PEM)",
        # AIza… shape is unambiguous — never rename from nearby setItem/storage noise
        "Google Cloud / Maps API Key",
        "Google Maps API Key",
        "Firebase API Key",
    }
)


def _google_browser_key_label(value: str, body_text: str, start: int, end: int) -> Optional[str]:
    """Stable label for AIza browser keys (Firebase / Maps / generic Google)."""
    if not (value or "").startswith("AIza"):
        return None
    window = body_text[max(0, start - 500) : min(len(body_text), end + 500)]
    if re.search(
        r"(?i)(firebase|identitytoolkit\.googleapis|securetoken\.googleapis|"
        r"firestore\.googleapis|firebaseio\.com)",
        window,
    ):
        return "Firebase API Key"
    if re.search(r"(?i)(maps\.googleapis|maps\.google|places\.googleapis|geocode)", window):
        return "Google Maps API Key"
    return "Google Cloud / Maps API Key"


def refine_secret_label(
    label: str,
    raw: str,
    body_text: str,
    start: int,
    end: int,
    *,
    org_context=None,
) -> str:
    """Classify WHAT we found from assigned + related variables + org context."""
    from secret_classify import classify_credential

    value = extract_secret_value(raw)
    google_label = _google_browser_key_label(value or "", body_text, start, end)
    if google_label:
        return google_label

    classified = classify_credential(
        base_label=label,
        raw=raw,
        body_text=body_text,
        start=start,
        end=end,
        value=value,
        org_context=org_context,
    )

    # Always prefer variable-derived product+kind over generic bases
    if classified and classified not in _GENERIC_SECRET_LABELS and classified != label:
        # Prefix-locked labels win only when classification didn't add a product
        # from the assignment (e.g. bare AKIA with no variable stays AWS).
        if label in _PREFIX_LOCKED_LABELS:
            # If variables named a different product (unlikely for AKIA), keep prefix
            # but allow enrichment when classify equals/extends the same vendor.
            return label
        return classified

    if label not in _GENERIC_SECRET_LABELS:
        return label

    window = body_text[max(0, start - 280) : min(len(body_text), end + 160)]
    blob = f"{window}\n{raw}"
    for pattern, refined in SECRET_CONTEXT_LABELS:
        if re.search(pattern, blob):
            return refined
    return classified or label


def _normalize_field_token(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def _lhs_from_raw(raw: str) -> str:
    m = _LHS_ASSIGN_RE.search((raw or "").strip())
    return (m.group("lhs") if m else "") or ""


def _in_html_form_control_tag(body_text: str, start: int) -> bool:
    """True when the match sits inside an open <input|textarea|…> tag."""
    if start <= 0 or not body_text:
        return False
    lt = body_text.rfind("<", max(0, start - 600), start)
    if lt < 0:
        return False
    gt = body_text.find(">", lt)
    if gt != -1 and gt < start:
        return False
    head = body_text[lt : min(len(body_text), lt + 48)]
    return bool(
        re.match(
            rf"(?is)<(?:{'|'.join(_FORM_CONTROL_TAGS)})\b",
            head,
        )
    )


def _value_is_form_field_noise(value: str, raw: str = "") -> bool:
    """True for echoed form keywords / self-describing UI field values."""
    val = (value or "").strip()
    if not val:
        return True
    low = val.lower()
    norm = _normalize_field_token(val)
    keyword_norms = {_normalize_field_token(k) for k in _FORM_FIELD_KEYWORDS}
    if low in _FORM_FIELD_KEYWORDS or norm in keyword_norms:
        return True

    lhs = _lhs_from_raw(raw)
    lhs_tail = ""
    if lhs:
        lhs_low = lhs.lower().rsplit(".", 1)[-1]
        lhs_tail = lhs_low
        if low == lhs_low or norm == _normalize_field_token(lhs_low):
            return True
        if lhs_low.startswith("data-") or lhs_low.startswith("aria-"):
            attr_tail = lhs_low.split("-", 1)[-1]
            if norm == _normalize_field_token(attr_tail) or low in _FORM_FIELD_KEYWORDS:
                return True
        # Bare password/secret/token/api_key LHS with a word-like value → form/schema noise
        lhs_norm = _normalize_field_token(lhs_low)
        if lhs_norm in keyword_norms and _IDENT_LIKE_VALUE_RE.match(val):
            letters = sum(1 for ch in val if ch.isalpha())
            if letters >= max(6, int(len(val) * 0.7)) and len(set(val.lower())) <= 12:
                return True

    # Identifier-shaped values with no digits (password, formFieldKeyword, SERIALNUMBER)
    # are almost always UI/schema noise for generic assignment patterns.
    if _IDENT_LIKE_VALUE_RE.match(val) and not re.search(r"\d", val):
        if any(ch.isupper() for ch in val[1:]) or "_" in val or "-" in val:
            return True
        if low in _FORM_FIELD_KEYWORDS or len(val) <= 16:
            return True
    return False


def _secret_looks_real(raw: str) -> bool:
    """Filter obvious placeholders / low-entropy demo values."""
    if not raw or SECRET_PLACEHOLDER_RE.search(raw):
        return False
    value = extract_secret_value(raw)
    if not value or SECRET_PLACEHOLDER_RE.search(value):
        return False
    if _value_is_form_field_noise(value, raw):
        return False
    # Require some character diversity for generic key/password patterns
    charset = len(set(value))
    if len(value) >= 12 and charset < 5:
        return False
    return True


def _lhs_is_html_data_or_aria_attr(raw: str) -> bool:
    """True for HTML data-* / aria-* attributes mistaken for credential assignments."""
    lhs = _lhs_from_raw(raw).lower().rsplit(".", 1)[-1]
    if not lhs:
        return False
    return lhs.startswith("data-") or lhs.startswith("aria-") or lhs.startswith("data_")


def _should_skip_secret_match(
    *,
    label: str,
    raw: str,
    body_text: str,
    start: int,
    end: int,
    value: str,
) -> bool:
    """Drop form-control / UI-schema false positives for generic assignment patterns."""
    if label not in _GENERIC_SECRET_LABELS_FOR_FP:
        return False
    if _value_is_form_field_noise(value, raw):
        return True
    # data-api-key="…" / aria-* attributes are markup metadata, not credentials.
    if _lhs_is_html_data_or_aria_attr(raw):
        return True
    # Generic pattern often matches *inside* data-api-key=… (match starts at "api-key").
    pre = body_text[max(0, start - 8) : start]
    if re.search(r"(?i)(?:data|aria)-$", pre):
        return True
    # Assignments living inside <input|textarea|select|label|…> are form markup, not secrets.
    if _in_html_form_control_tag(body_text, start):
        return True
    # name=/id=/placeholder=/autocomplete= values are field metadata, not credentials.
    before = body_text[max(0, start - 96) : start]
    if re.search(
        r"(?i)\b(?:name|id|for|placeholder|autocomplete|aria-[\w-]+|data-testid|data-cy)\s*=\s*['\"][^'\"]*$",
        before,
    ):
        return True
    return False


def scan_secrets(
    body_text: str,
    url: str,
    *,
    org_context=None,
    org_hints: str = "",
    start_url: str = "",
) -> List[Tuple[str, str, str, Optional[str]]]:
    """Return (label, severity, detail, evidence).

    ``label`` is the credential type derived from the assigned variable,
    related nearby identifiers, and optional custom org context (scan domain +
    ``secret_org_hints``).
    Evidence is the full accessible value (UI/reports mask with tap-to-reveal).
    """
    from secret_classify import assignment_note, build_org_context, severity_for_kind

    if org_context is None:
        org_context = build_org_context(
            hints=org_hints,
            urls=[u for u in (start_url, url) if u],
        )

    findings: List[Tuple[str, str, str, Optional[str]]] = []
    if not body_text:
        return findings
    seen = set()
    for pattern, label, severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, body_text):
            raw = match.group(0)
            if not _secret_looks_real(raw):
                continue
            value = extract_secret_value(raw)
            if _should_skip_secret_match(
                label=label,
                raw=raw,
                body_text=body_text,
                start=match.start(),
                end=match.end(),
                value=value,
            ):
                continue
            # Twilio SK… SIDs collide with random hex — require nearby Twilio context
            if label == "Twilio API Key SID":
                window = body_text[max(0, match.start() - 96) : match.end() + 96]
                if not re.search(
                    r"(?i)(?:twilio|account[_-]?sid|AC[0-9a-fA-F]{32}|auth[_-]?token)",
                    window,
                ):
                    continue
            typed = refine_secret_label(
                label,
                raw,
                body_text,
                match.start(),
                match.end(),
                org_context=org_context,
            )
            key = (typed, value[:80] if value else raw[:80])
            if key in seen:
                continue
            seen.add(key)
            note = assignment_note(body_text, match.start(), match.end(), value)
            detail = f"Exposed {typed} in response body{note}"
            findings.append(
                (typed, severity_for_kind(typed, severity, value or ""), detail, value or None)
            )
    return findings


def scan_sensitive_path(url: str) -> Optional[str]:
    path = urlparse(url).path or ""
    if SENSITIVE_PATH_RE.search(path):
        return f"Sensitive path pattern matched: {path}"
    return None


def audit_security_headers(headers: dict, url: str) -> List[Tuple[str, str, str]]:
    findings = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for header, (detail, severity) in SECURITY_HEADERS.items():
        if header not in lowered:
            findings.append(("header_audit", severity, detail))
    server = lowered.get("server", "")
    if server and any(old in server.lower() for old in ("apache/2.2", "iis/6", "nginx/1.0")):
        findings.append(("header_audit", "medium", f"Potentially outdated server banner: {server}"))
    powered = lowered.get("x-powered-by", "")
    if powered:
        findings.append(("header_audit", "info", f"X-Powered-By exposed: {powered}"))
    return findings


def discover_parameters(url: str, body_text: str = "", forms: Optional[List[dict]] = None) -> List[Dict[str, Any]]:
    params = []
    parsed = urlparse(url)
    for name, values in parse_qs(parsed.query).items():
        params.append({"url": url, "name": name, "source": "query", "sample": values[:3]})
    for match in PARAM_NAME_RE.findall(url):
        if match not in {p["name"] for p in params}:
            params.append({"url": url, "name": match, "source": "url_pattern", "sample": []})
    if body_text:
        for match in re.findall(r'name=["\']([^"\']+)["\']', body_text):
            params.append({"url": url, "name": match, "source": "html_input", "sample": []})
    if forms:
        for form in forms:
            for field in form.get("fields", []):
                params.append({"url": form.get("action", url), "name": field, "source": "form", "sample": []})
    return params


async def check_cors(client, url: str, origin: str = "https://evil.example") -> Optional[str]:
    """Report only high-confidence CORS misconfigurations (credentials + open origin)."""
    try:
        response = await client.get(
            url,
            headers={"Origin": origin},
            timeout=10,
        )
        acao = (response.headers.get("access-control-allow-origin") or "").strip()
        acac = (response.headers.get("access-control-allow-credentials") or "").lower()
        creds = acac == "true"
        if acao == "*" and creds:
            return "CORS allows any origin (*) with credentials — high risk"
        if acao == origin and creds:
            return f"CORS reflects arbitrary Origin ({origin}) with credentials — high risk"
        # Reflection without credentials is common for public assets; keep as low-noise info only
        if acao == origin and not creds:
            return None
        if acao == "*" and not creds:
            return None
    except Exception:
        return None
    return None


def extract_forms(html: str, page_url: str, content_type: str = "") -> List[Dict[str, Any]]:
    forms = []
    if not html:
        return forms

    from crawler_common import is_html_content

    path = urlparse(page_url).path
    if not is_html_content(content_type, path, html):
        return forms

    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        fields = []
        file_fields = []
        file_accepts: List[str] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                fields.append(name)
            if (inp.name or "").lower() == "input" and (inp.get("type") or "").lower() == "file":
                file_fields.append(name or "(unnamed-file)")
                accept = (inp.get("accept") or "").strip()
                if accept:
                    file_accepts.append(accept)
        forms.append(
            {
                "action": action,
                "method": method,
                "fields": fields,
                "file_fields": file_fields,
                "file_accepts": file_accepts,
                "has_file_input": bool(file_fields),
                "page": page_url,
            }
        )
    return forms


def fingerprint_technology(headers: dict, body_text: str) -> List[str]:
    tech = []
    lowered = {k.lower(): v for k, v in headers.items()}
    if "x-drupal-cache" in lowered or "Drupal" in (body_text or ""):
        tech.append("Drupal")
    if "x-generator" in lowered and "WordPress" in lowered["x-generator"]:
        tech.append("WordPress")
    if "wp-content" in (body_text or ""):
        tech.append("WordPress")
    server = lowered.get("server", "")
    if "nginx" in server.lower():
        tech.append("nginx")
    if "apache" in server.lower():
        tech.append("Apache")
    if "cloudflare" in lowered.get("server", "").lower() or "cf-ray" in lowered:
        tech.append("Cloudflare")
    if "asp.net" in lowered.get("x-powered-by", "").lower():
        tech.append("ASP.NET")
    if "php" in lowered.get("x-powered-by", "").lower():
        tech.append("PHP")
    return tech


# --- Vulnerability indicators (authorized targets only) ---

# Finding tuple: (category, severity, detail, evidence) — evidence is the exact
# matched pattern + short context snippet whenever a regex/heuristic fired.
Finding = Tuple[str, str, str, Optional[str]]

SQL_ERROR_RE = re.compile(
    r"(?i)(sql syntax|mysql_fetch|mysqli_|ORA-\d{5}|SQLite/JDBCDriver|"
    r"PostgreSQL.*ERROR|unclosed quotation mark|quoted string not properly terminated|"
    r"Microsoft OLE DB Provider for SQL Server|SQLServer JDBC Driver)"
)

RCE_BODY_RE = re.compile(
    r"(?i)(eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|"
    r"popen\s*\(|proc_open\s*\(|Runtime\.getRuntime\s*\(\)\.exec|os\.system\s*\()"
)
RCE_SHELL_EVIDENCE_RE = re.compile(
    r"(?i)(sh:|bash:|command not found|permission denied|\buid=\d+\b)"
)
_STATIC_ASSET_PATH_RE = re.compile(
    r"(?i)\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif)(?:$|\?)"
)


def _match_evidence(
    match: re.Match,
    text: str,
    *,
    pad: int = 56,
    label: str = "",
) -> str:
    """Exact matched token + surrounding context for reports/UI evidence."""
    raw = (match.group(0) or "").strip()
    start = max(0, match.start() - pad)
    end = min(len(text or ""), match.end() + pad)
    snippet = (text or "")[start:end].replace("\n", " ").replace("\r", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(text or ""):
        snippet = snippet + "…"
    prefix = f"{label}: " if label else ""
    return f"{prefix}matched `{raw}` @ offset {match.start()}: {snippet}"


def _text_evidence(value: str, *, label: str = "matched") -> str:
    text = re.sub(r"\s+", " ", (value or "").strip())
    if len(text) > 220:
        text = text[:200] + "…"
    return f"{label}: `{text}`"

TRAVERSAL_RE = re.compile(r"(?i)(\.\./|\.\.%2f|%2e%2e%2f|\.\.\\|%252e%252e/)")

SSRF_PARAM_RE = re.compile(
    r"(?i)^(url|uri|link|src|source|dest|destination|redirect|redirect_uri|"
    r"callback|feed|path|site|domain|host|target|fetch|proxy|next|continue|return)$"
)

SQL_PARAM_RE = re.compile(r"(?i)^(id|uid|user_id|cat|category|item|page|pid|order|sort|query|q|search|filter)$")

API_LEAK_RE = re.compile(
    r"(?i)(__schema|introspectionQuery|swagger-ui|openapi\.json|swagger\.json|"
    r"graphql playground|debug=true|actuator/health|\.well-known/openid-configuration)"
)

OPEN_REDIRECT_PARAM_RE = re.compile(
    r"(?i)^(redirect|redirect_uri|redirect_url|return|return_url|returnurl|next|url|"
    r"dest|destination|continue|goto|target|rurl|out|link)$"
)

GRAPHQL_PATH_RE = re.compile(r"(?i)/(?:graphql|graphiql|playground)(?:$|/|\?)")

_URL_CRED_PARAM_RE = re.compile(
    r"(?i)^(password|passwd|pwd|pass|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|secret|client[_-]?secret|sessionid|session_id|auth[_-]?token)$"
)


def _query_params(url: str) -> dict:
    return parse_qs(urlparse(url).query)


def _looks_like_code_listing(body_text: str) -> bool:
    """Avoid treating documentation / source listings as live RCE/XSS evidence."""
    if not body_text:
        return False
    markers = ("```", "<pre", "<code", "syntax highlighting", "example.com", "tutorial")
    lowered = body_text[:4000].lower()
    return sum(1 for m in markers if m in lowered) >= 2


# Fetch-style params for precise SSRF (not next/redirect/return — those are open-redirect)
_SSRF_FETCH_PARAM_RE = re.compile(
    r"(?i)^(url|uri|src|source|dest|destination|fetch|proxy|target|path|feed|host|site|domain)$"
)
_SSRF_METADATA_RE = re.compile(
    r"(?i)(169\.254\.169\.254|metadata\.google(?:\.internal)?|metadata\.goog|"
    r"fd00:ec2::|\[::ffff:169\.254\.169\.254\])"
)
_SSRF_LOOPBACK_RE = re.compile(r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])")
_SSRF_RFC1918_RE = re.compile(
    r"(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
)
_TRAVERSAL_FILE_PARAM_RE = re.compile(
    r"(?i)^(file|path|folder|dir|document|template|include|doc|page|view|load)$"
)
_XSS_PAYLOAD_RE = re.compile(
    r"(?i)(<\s*script|<\s*img|<\s*svg|<\s*iframe|onerror\s*=|onload\s*=|javascript:)"
)
_SQL_PAYLOAD_RE = re.compile(r"[\"'`;]|--|/\*|\bunion\b|\bselect\b", re.I)
_ANALYTICS_SCRIPT_RE = re.compile(
    r"(?i)(google-analytics|googletagmanager|gtag\(|fbq\(|analytics\.js|"
    r"hotjar|segment\.com|mixpanel|clarity\.ms|newrelic|datadoghq|"
    r"cdn\.segment|static\.hotjar|_gaq|_gat)"
)
_PARTNER_REDIRECT_HOST_RE = re.compile(
    r"(?i)(?:^|\.)("
    r"facebook\.com|fb\.com|twitter\.com|x\.com|t\.co|linkedin\.com|lnkd\.in|"
    r"google\.com|accounts\.google\.com|youtube\.com|youtu\.be|"
    r"apple\.com|microsoft\.com|live\.com|paypal\.com|stripe\.com|"
    r"shopify\.com|amazon\.com|okta\.com|auth0\.com|cloudflare\.com|"
    r"github\.com|gitlab\.com|bitbucket\.org|slack\.com|zoom\.us"
    r")$"
)
_PROFILE_UPLOAD_RE = re.compile(
    r"(?i)/(?:avatar|profile|account|settings|user|me|photo|picture|image)(?:/|$)"
)
# Bare */* or * is risky; image/* / .pdf are normal. Executable extensions in accept are risky.
_UPLOAD_RISKY_ACCEPT_RE = re.compile(
    r"(?i)(?:^|,)\s*(?:\*/\*|\*)(?:\s|,|$)|application/octet-stream|"
    r"\.(?:php|phtml|aspx?|jsp|exe|sh|cgi)\b"
)


def scan_sql_injection(url: str, body_text: str, forms: Optional[List[dict]] = None) -> List[Finding]:
    """Tiered passive SQLi: SQL error + request signal (payload-shaped → high, name-only → medium)."""
    err = SQL_ERROR_RE.search(body_text or "")
    if not body_text or not err:
        return []
    if _looks_like_code_listing(body_text):
        return []
    err_ev = _match_evidence(err, body_text, label="sql_error")
    params = _query_params(url)
    payload_bits: List[str] = []
    for name, values in params.items():
        for v in values:
            pm = _SQL_PAYLOAD_RE.search(v or "")
            if pm:
                payload_bits.append(f"{name}={pm.group(0)}")
    named_params = [name for name in params if SQL_PARAM_RE.match(name)]
    form_named = False
    if forms:
        for form in forms:
            for field in form.get("fields") or []:
                if SQL_PARAM_RE.match(str(field)):
                    form_named = True
                    break
    if payload_bits:
        return [
            (
                "sql_injection",
                "high",
                f"SQL error with payload-shaped value in parameter(s) "
                f"{', '.join(list(dict.fromkeys(p.split('=', 1)[0] for p in payload_bits))[:5])} "
                f"(precise passive SQLi)",
                f"{err_ev} | param_payload: {', '.join(payload_bits[:4])}",
            )
        ]
    if named_params or form_named:
        who = ", ".join((named_params or ["form field"])[:5])
        return [
            (
                "sql_injection",
                "medium",
                f"SQL error near SQL-named parameter(s) {who} without payload chars (precise passive SQLi)",
                f"{err_ev} | params: {who}",
            )
        ]
    return []


def scan_xss(url: str, body_text: str, forms: Optional[List[dict]] = None) -> List[Finding]:
    """Precise passive XSS with second-signal gating for inline cookie/eval scripts."""
    findings: List[Finding] = []
    if not body_text:
        return findings
    params = _query_params(url)
    if not _looks_like_code_listing(body_text):
        for match in re.finditer(
            r"(?is)<script[^>]*>(.*?)</script>",
            body_text[:200000],
        ):
            block = match.group(1) or ""
            sink = re.search(r"(?i)(document\.cookie\s*=|eval\s*\()", block)
            if not sink:
                continue
            sink_ev = _match_evidence(sink, block, label="xss_sink")
            reflected_name = ""
            for name, values in params.items():
                for v in values:
                    if v and len(v) >= 3 and v in block:
                        reflected_name = name
                        break
                if reflected_name:
                    break
            analytics = bool(
                _ANALYTICS_SCRIPT_RE.search(block) or _ANALYTICS_SCRIPT_RE.search(match.group(0))
            )
            if reflected_name:
                findings.append(
                    (
                        "xss",
                        "high",
                        "Inline script with cookie/eval sink and reflected parameter (precise passive XSS)",
                        f"{sink_ev} | reflected_param: {reflected_name}",
                    )
                )
            elif not analytics:
                findings.append(
                    (
                        "xss",
                        "low",
                        "Inline script with cookie/eval sink (no reflected input; verify ownership)",
                        sink_ev,
                    )
                )
            break
    for name, values in params.items():
        for value in values:
            if len(value) < 3 or len(value) > 200:
                continue
            payload_m = _XSS_PAYLOAD_RE.search(value) or re.search(
                r"<\s*[a-zA-Z][^>]{0,80}>", value
            )
            if not payload_m:
                continue
            if value not in body_text:
                continue
            findings.append(
                (
                    "xss",
                    "medium",
                    f"Parameter '{name}' HTML/JS payload reflected unescaped (precise passive XSS)",
                    _text_evidence(value, label=f"reflected_param[{name}]"),
                )
            )
            break
    return findings


def scan_rce(url: str, body_text: str, forms: Optional[List[dict]] = None) -> List[Finding]:
    """Precise passive RCE: command-style param + shell execution evidence (not docs).

    Static JS/CSS bundles are never treated as RCE from body tokens alone — ``eval(`` in
    webpack output is expected client-side noise.
    """
    path = urlparse(url).path or ""
    if _STATIC_ASSET_PATH_RE.search(path):
        return []
    if _looks_like_code_listing(body_text or ""):
        return []
    params = _query_params(url)
    cmd_params = [
        n
        for n in params
        if re.match(r"(?i)^(cmd|command|exec|execute|run|shell)$", n)
    ]
    if not cmd_params:
        return []
    shellish_vals = []
    for n in cmd_params:
        for v in params.get(n) or []:
            if re.search(r"[;&|`$]|^\s*(id|whoami|ls|cat|ping|uname)\b", v or ""):
                shellish_vals.append(f"{n}={v[:80]}")
    if not shellish_vals:
        return []
    body = body_text or ""
    shell_m = RCE_SHELL_EVIDENCE_RE.search(body)
    if shell_m:
        return [
            (
                "rce",
                "high",
                f"Command param(s) {', '.join(cmd_params[:3])} with shell execution evidence (precise passive RCE)",
                f"{_match_evidence(shell_m, body, label='shell_evidence')} | {'; '.join(shellish_vals[:3])}",
            )
        ]
    rce_m = RCE_BODY_RE.search(body)
    if rce_m and re.search(r"(?i)(sh:|bash:|uid=)", body):
        return [
            (
                "rce",
                "high",
                f"Command param(s) {', '.join(cmd_params[:3])} with code-exec evidence (precise passive RCE)",
                f"{_match_evidence(rce_m, body, label='rce_pattern')} | {'; '.join(shellish_vals[:3])}",
            )
        ]
    return []


def scan_file_upload(forms: Optional[List[dict]], url: str) -> List[Finding]:
    """Precise type=file surfaces with severity by accept/path risk (not blind medium)."""
    findings: List[Finding] = []
    if not forms:
        return findings
    seen_actions: set = set()
    for form in forms:
        action = form.get("action") or url
        has_file = bool(form.get("has_file_input")) or bool(form.get("file_fields"))
        if not has_file:
            continue
        action_key = str(action)
        if action_key in seen_actions:
            continue
        seen_actions.add(action_key)
        method = (form.get("method") or "GET").upper()
        accepts = [str(a) for a in (form.get("file_accepts") or []) if a]
        accept_blob = ",".join(accepts)
        path = urlparse(action).path or urlparse(url).path or ""
        risky_accept = bool(accepts) and bool(_UPLOAD_RISKY_ACCEPT_RE.search(accept_blob))
        missing_accept = not accepts
        adminish = bool(
            re.search(r"(?i)/(?:admin(?:/|$)|import(?:/|$)|api/[^?\s]*upload)", path)
        )
        profileish = bool(_PROFILE_UPLOAD_RE.search(path))
        if risky_accept or adminish:
            sev = "medium" if method == "POST" else "high"
            why = "risky accept/admin upload path"
        elif profileish and not missing_accept:
            sev = "info"
            why = "profile/avatar-style upload"
        elif missing_accept:
            sev = "low"
            why = "type=file without accept restriction"
        else:
            sev = "info"
            why = "type=file upload surface"
        fields = ",".join(form.get("file_fields") or []) or "type=file"
        evidence = _text_evidence(
            f"action={action}; method={method}; fields={fields}; accept={accept_blob or '(none)'}",
            label="file_upload",
        )
        findings.append(
            (
                "file_upload",
                sev,
                f"File upload form at {action} via {method} ({why})",
                evidence,
            )
        )
    return findings


def scan_ssrf(url: str, body_text: str = "") -> List[Finding]:
    """Precise passive SSRF with severity ladder: metadata > loopback > RFC1918."""
    findings: List[Finding] = []
    params = _query_params(url)
    for name, values in params.items():
        if not _SSRF_FETCH_PARAM_RE.match(name):
            continue
        for value in values:
            decoded = unquote(value or "")
            if not re.match(r"(?i)^https?://", decoded) and not decoded.startswith("//"):
                continue
            if _SSRF_METADATA_RE.search(decoded):
                findings.append(
                    (
                        "ssrf",
                        "high",
                        f"Parameter '{name}' points at cloud metadata URL (precise passive SSRF)",
                        _text_evidence(f"{name}={decoded}", label="ssrf_target"),
                    )
                )
            elif _SSRF_LOOPBACK_RE.search(decoded):
                findings.append(
                    (
                        "ssrf",
                        "medium",
                        f"Parameter '{name}' points at loopback URL (precise passive SSRF)",
                        _text_evidence(f"{name}={decoded}", label="ssrf_target"),
                    )
                )
            elif _SSRF_RFC1918_RE.search(decoded):
                findings.append(
                    (
                        "ssrf",
                        "low",
                        f"Parameter '{name}' points at private-network URL (precise passive SSRF)",
                        _text_evidence(f"{name}={decoded}", label="ssrf_target"),
                    )
                )
    return findings


def scan_directory_traversal(url: str) -> List[Finding]:
    """Precise: traversal + sensitive file target in file/path-style params only.

    Bare ``../`` in URL paths is normal relative resolution — never a finding.
    """
    findings: List[Finding] = []
    for name, values in _query_params(url).items():
        if not _TRAVERSAL_FILE_PARAM_RE.match(name):
            continue
        for value in values:
            decoded = unquote(value or "")
            trav = TRAVERSAL_RE.search(decoded)
            if not trav:
                continue
            if not re.search(
                r"(?i)(etc/passwd|windows[/\\]win\.ini|/proc/self|\.git/config|boot\.ini)",
                decoded,
            ):
                continue
            findings.append(
                (
                    "directory_traversal",
                    "medium",
                    f"Traversal + sensitive file target in parameter '{name}' (precise passive)",
                    _text_evidence(f"{name}={decoded}", label="traversal_payload"),
                )
            )
    return findings


def scan_authentication_flaws(url: str, headers: dict, body_text: str = "") -> List[Finding]:
    """HTTP auth findings require a real login surface — not path keywords like /author."""
    findings: List[Finding] = []
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    for name, values in _query_params(url).items():
        if not _URL_CRED_PARAM_RE.match(name):
            continue
        for value in values:
            if not value or len(value) < 8:
                continue
            if not _secret_looks_real(f"{name}={value}"):
                continue
            if len(set(value)) < 5:
                continue
            if value.startswith(("pk_live_", "pk_test_", "AIza")) or re.fullmatch(
                r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value
            ):
                sev = "low" if scheme == "https" else "medium"
                findings.append(
                    (
                        "authentication",
                        sev,
                        f"Client/public-style credential in URL query parameter '{name}'",
                        _text_evidence(f"{name}={mask_secret_value(value)}", label="url_credential"),
                    )
                )
                break
            sev = "high" if scheme == "https" else "critical"
            findings.append(
                (
                    "authentication",
                    sev,
                    f"Credential-like value in URL query parameter '{name}'",
                    _text_evidence(f"{name}={mask_secret_value(value)}", label="url_credential"),
                )
            )
            break
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    pw = re.search(r"(?i)(type=['\"]password['\"]|name=['\"]password['\"])", body_text or "")
    www_auth = lowered.get("www-authenticate", "")
    if scheme == "http" and pw:
        findings.append(
            (
                "authentication",
                "high",
                "Password form on HTTP connection",
                _match_evidence(pw, body_text or "", label="password_field"),
            )
        )
    if www_auth and scheme == "http":
        findings.append(
            (
                "authentication",
                "medium",
                f"Basic/digest auth over HTTP ({www_auth[:40]})",
                _text_evidence(www_auth[:120], label="www-authenticate"),
            )
        )
    return findings


def scan_open_redirect(url: str) -> List[Finding]:
    """Precise passive open redirect: absolute off-site URL in redirect-style params.

    Suppress OAuth ``redirect_uri`` (with /oauth|/authorize or client_id). Active probes
    still confirm via Location.
    """
    findings: List[Finding] = []
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    params = _query_params(url)
    oauthish = bool(re.search(r"(?i)/(?:oauth|oidc|authorize|sso|connect)(?:/|$)", path))
    has_client_id = any(n.lower() == "client_id" for n in params)
    for name, values in params.items():
        if not OPEN_REDIRECT_PARAM_RE.match(name):
            continue
        name_l = (name or "").lower()
        if (oauthish or has_client_id) and name_l in (
            "redirect_uri",
            "redirect_url",
            "return_to",
            "return",
            "callback",
        ):
            continue
        for value in values:
            decoded = unquote(value or "")
            if not re.match(r"(?i)^https?://", decoded) and not decoded.startswith("//"):
                continue
            if re.match(r"(?i)^(javascript|data):", decoded):
                continue
            target_host = urlparse(
                decoded if "://" in decoded else f"https:{decoded}"
            ).netloc.lower()
            if not target_host or target_host == host or target_host.endswith("." + host):
                continue
            # Known partner/share hosts are usually intentional outbound links
            if _PARTNER_REDIRECT_HOST_RE.search(target_host):
                sev = "info"
                note = "partner/share host"
            else:
                sev = "low"
                note = "unfamiliar off-site host"
            findings.append(
                (
                    "open_redirect",
                    sev,
                    f"Parameter '{name}' points off-site to {target_host} ({note}; precise passive open redirect)",
                    _text_evidence(f"{name}={decoded}", label="redirect_target"),
                )
            )
    return findings


def scan_mixed_content(url: str, body_text: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        from recon_extract import extract_mixed_content

        resources = extract_mixed_content(url, body_text or "")
    except Exception:
        resources = []
    if resources:
        sample = ", ".join(resources[:3])
        findings.append(
            (
                "mixed_content",
                "medium",
                f"HTTPS page loads {len(resources)} HTTP resource(s); e.g. {sample}",
                _text_evidence(sample, label="http_resources"),
            )
        )
    return findings


def _api_debug_body_proof(path: str, body_text: str, content_type: str = "") -> Optional[Tuple[str, str]]:
    """Return (proof_label, evidence) when a sensitive API/debug path has real content."""
    if not body_text:
        return None
    text = body_text[:12000]
    checks = (
        (r"(?i)/phpinfo(?:\.php)?(?:/|$)", r"(?i)(?:phpinfo\s*\(|PHP Version\s*\d|PHP Credits)", "phpinfo() body proof"),
        (r"(?i)/actuator", r"(?i)(\"status\"\s*:\s*\"UP\"|\"_links\"|actuator)", "actuator JSON/body proof"),
        (r"(?i)/server-status(?:/|$)", r"(?i)Apache Server Status|Server uptime|Current Time:", "Apache server-status proof"),
        (r"(?i)openid-configuration", r"(?i)\"issuer\"\s*:|\"jwks_uri\"\s*:", "OIDC discovery document proof"),
        (r"(?i)/(?:debug)(?:/|$)", r"(?i)(traceback|stack trace|DEBUG\s*=\s*True|django\.debug|Werkzeug)", "debug/traceback body proof"),
    )
    for path_pat, body_pat, label in checks:
        if not re.search(path_pat, path):
            continue
        m = re.search(body_pat, text[:6000] if "debug" in label else text[:4000])
        if m:
            return label, _match_evidence(m, text, label="api_leak_proof")
        return None
    return None


def scan_api_leaks(url: str, body_text: str, headers: dict, content_type: str = "") -> List[Finding]:
    findings: List[Finding] = []
    path = urlparse(url).path.lower()
    sensitive_segments = (
        r"(?:^|/)(?:debug|actuator|phpinfo(?:\.php)?|server-status)(?:/|$)",
        r"(?:^|/)\.well-known/openid-configuration(?:/|$)",
    )
    if any(re.search(pat, path) for pat in sensitive_segments):
        proved = _api_debug_body_proof(path, body_text or "", content_type)
        if proved:
            proof, evidence = proved
            findings.append(
                (
                    "api_leak",
                    "medium",
                    f"Sensitive API/debug path confirmed: {path} ({proof})",
                    evidence,
                )
            )
    elif re.search(r"(?:^|/)(?:swagger|api-docs|openapi)(?:/|$)", path) and body_text:
        m = re.search(r"(?i)(\"swagger\"|openapi|paths\s*:)", body_text[:2000])
        if m:
            findings.append(
                (
                    "api_leak",
                    "low",
                    f"API documentation exposed at {path}",
                    _match_evidence(m, body_text[:2000], label="openapi"),
                )
            )
    if body_text and not _looks_like_code_listing(body_text):
        if GRAPHQL_PATH_RE.search(path):
            schema_m = re.search(
                r"(?i)(\"__schema\"\s*:|\"queryType\"\s*:|\"mutationType\"\s*:)",
                body_text[:8000],
            )
            playground_m = re.search(
                r"(?i)(GraphiQL|graphql playground|introspectionQuery)", body_text[:8000]
            )
            if schema_m:
                findings.append(
                    (
                        "api_leak",
                        "high",
                        "GraphQL schema JSON disclosed (__schema/queryType) on GraphQL path",
                        _match_evidence(schema_m, body_text[:8000], label="graphql_schema"),
                    )
                )
            elif playground_m:
                findings.append(
                    (
                        "api_leak",
                        "medium",
                        "GraphQL playground/UI indicators on GraphQL path (unverified introspection)",
                        _match_evidence(playground_m, body_text[:8000], label="graphql_ui"),
                    )
                )
        elif "/actuator" in path and (
            re.search(r"(?i)actuator/health", path)
            or (
                "json" in (content_type or "").lower()
                and re.search(r"(?i)\"status\"\s*:\s*\"UP\"", body_text[:2000])
            )
        ):
            m = re.search(r"(?i)\"status\"\s*:\s*\"UP\"", body_text[:2000])
            findings.append(
                (
                    "api_leak",
                    "high",
                    "Actuator/health-style JSON exposed",
                    _match_evidence(m, body_text[:2000], label="actuator") if m else _text_evidence(path, label="actuator_path"),
                )
            )
        else:
            debug_m = re.search(r"(?i)[?&]debug=true(?:&|$)", url)
            body_dbg = re.search(
                r"(?i)(traceback|stack trace|DEBUG\s*=\s*True|exception)",
                body_text[:6000],
            )
            if debug_m and body_dbg:
                findings.append(
                    (
                        "api_leak",
                        "medium",
                        "debug=true with debug/error body content",
                        f"{_text_evidence('debug=true', label='query')} | {_match_evidence(body_dbg, body_text[:6000], label='debug_body')}",
                    )
                )
    ct = (content_type or "").lower()
    path_l = path
    oauthish = bool(re.search(r"(?i)(oauth|/token|/auth/|/login|/session)", path_l))
    if "json" in ct and body_text and not oauthish:
        try:
            data = json.loads(body_text)
            if isinstance(data, dict):
                for key, value in data.items():
                    if not re.match(r"(?i)^(api_key|secret|password|private_key)$", str(key)):
                        continue
                    if isinstance(value, str) and len(value) >= 8 and _secret_looks_real(f"{key}={value}"):
                        findings.append(
                            (
                                "api_leak",
                                "high",
                                f"JSON field '{key}' may expose a secret value",
                                _text_evidence(f"{key}={mask_secret_value(value)}", label="json_secret_field"),
                            )
                        )
        except json.JSONDecodeError:
            pass
    return findings


def scan_secrets_exposure(body_text: str, url: str) -> List[Tuple[str, str, str]]:
    findings = []
    for label, severity, detail, evidence in scan_secrets(body_text, url):
        # Detail keeps a mask only — full value lives on the evidence field when emitted via scan_secrets.
        suffix = f" [value={mask_secret_value(evidence)}]" if evidence else ""
        findings.append(("secrets_exposure", severity, f"{label}: {detail}{suffix}"))
    return findings


def run_passive_vuln_scan(
    url: str,
    body_text: str,
    forms: Optional[List[dict]],
    headers: dict,
    content_type: str = "",
    *,
    cookies: Optional[List[dict]] = None,
) -> List[Finding]:
    """Run passive scanners. Each finding includes exact matched-pattern evidence."""
    from exploit_probes import scan_csrf, scan_idor_passive, scan_js_sensitive_routes

    findings: List[Finding] = []
    findings.extend(scan_sql_injection(url, body_text, forms))
    findings.extend(scan_xss(url, body_text, forms))
    findings.extend(scan_rce(url, body_text, forms))
    findings.extend(scan_file_upload(forms, url))
    findings.extend(scan_ssrf(url, body_text))
    findings.extend(scan_directory_traversal(url))
    findings.extend(scan_open_redirect(url))
    findings.extend(scan_authentication_flaws(url, headers, body_text))
    findings.extend(scan_api_leaks(url, body_text, headers, content_type))
    findings.extend(scan_mixed_content(url, body_text))
    findings.extend(scan_csrf(url, forms, headers, cookies=cookies))
    findings.extend(scan_idor_passive(url))
    ct = (content_type or "").lower()
    path = (urlparse(url).path or "").lower()
    if (
        "javascript" in ct
        or path.endswith((".js", ".mjs", ".cjs"))
        or (body_text and ("fetch(" in body_text or "axios." in body_text or "firebase" in body_text.lower()))
    ):
        findings.extend(scan_js_sensitive_routes(url, body_text))
    try:
        from tier_security import run_tier_passive

        findings.extend(run_tier_passive(url, body_text or "", forms, headers))
    except Exception:
        pass
    # Secrets are handled once via config.secret_scan → scan_secrets (avoid double-fire)
    return findings


def _active_match_evidence(category: str, body: str, payload: str, marker: str, baseline: str = "") -> Optional[str]:
    """Build exact matched-pattern evidence for an active probe hit."""
    text = body or ""
    if category == "sql_injection":
        m = SQL_ERROR_RE.search(text)
        return _match_evidence(m, text, label="sql_error") if m else _text_evidence(payload, label="sql_payload")
    if category == "xss":
        idx = text.find(marker)
        if idx >= 0:
            return _text_evidence(marker, label=f"reflected_marker@offset_{idx}")
        return _text_evidence(marker, label="reflected_marker")
    if category == "directory_traversal":
        m = re.search(r"(?i)(root:x:0:0:|/bin/(?:ba)?sh\b)", text)
        return (
            _match_evidence(m, text, label="passwd_proof")
            if m
            else _text_evidence(payload, label="traversal_payload")
        )
    if category == "rce":
        idx = text.find(marker)
        if idx >= 0:
            return _text_evidence(marker, label=f"rce_echo@offset_{idx}")
        return _text_evidence(marker, label="rce_echo")
    if category == "ssrf":
        m = re.search(
            r"(?i)(ami-[0-9a-f]{8,}|instance-id|meta-data/|computeMetadata|"
            r"metadata\.google|169\.254\.169\.254)",
            text,
        )
        if m:
            return _match_evidence(m, text, label="ssrf_body")
        return _text_evidence(payload, label="ssrf_payload")
    return _text_evidence(payload or marker, label="probe")


async def run_active_vuln_probes(
    client,
    url: str,
    forms: Optional[List[dict]] = None,
    *,
    max_params: int = 8,
    max_forms: int = 3,
    body_text: str = "",
) -> List[Finding]:
    """Send minimal safe payloads on GET params and forms (authorized testing only).

    Compares probe responses against a baseline request to cut WAF/generic-error FPs.
    Each finding includes the exact matched pattern / marker as evidence.
    """
    from urllib.parse import parse_qsl, urlparse

    findings: List[Finding] = []
    seen: set = set()
    xss_marker = "<crawler-xss-probe>"
    rce_marker = "crawler-rce-probe-9f3a"

    def add(category: str, severity: str, detail: str, evidence: Optional[str] = None):
        key = (category, detail, evidence or "")
        if key not in seen:
            seen.add(key)
            findings.append((category, severity, detail, evidence))

    sql_names = re.compile(r"(?i)^(id|uid|user_id|cat|category|item|pid|order|sort|query|q|search|filter|name)$")

    probe_defs = (
        (
            "sql_injection",
            "'",
            "high",
            lambda body, _payload, _marker: bool(SQL_ERROR_RE.search(body)),
            lambda name: bool(sql_names.match(name)),
        ),
        (
            "xss",
            xss_marker,
            "high",
            lambda body, _payload, marker: marker in body,
            lambda name: bool(
                re.match(
                    r"(?i)^(q|query|search|s|keyword|term|name|title|message|comment|text|content|input)$",
                    name,
                )
            ),
        ),
        (
            "directory_traversal",
            "../../../../etc/passwd",
            "critical",
            lambda body, _payload, _marker: bool(re.search(r"(?i)(root:x:0:0:|/bin/(?:ba)?sh\b)", body)),
            lambda name: bool(re.match(r"(?i)^(file|path|folder|dir|document|template|include|doc)$", name)),
        ),
        (
            "rce",
            f";echo {rce_marker}",
            "critical",
            lambda body, _payload, marker: marker in body and "echo" not in body.lower()[:40],
            lambda name: bool(re.match(r"(?i)^(cmd|command|exec|execute|run|shell)$", name)),
        ),
        (
            "ssrf",
            # Metadata URL — connection-refused alone is a common app error FP
            "http://169.254.169.254/latest/meta-data/",
            "high",
            lambda body, baseline, _marker: bool(
                re.search(
                    r"(?i)(ami-[0-9a-f]{8,}|instance-id|meta-data/|computeMetadata|"
                    r"metadata\.google|169\.254\.169\.254)",
                    body or "",
                )
            )
            and not re.search(
                r"(?i)(ami-[0-9a-f]{8,}|instance-id|computeMetadata)",
                baseline or "",
            ),
            lambda name: bool(SSRF_PARAM_RE.match(name)),
        ),
    )

    redirect_probe = "https://crawler-open-redirect-probe.invalid/confirm"

    async def _send_get(target: str, params: dict):
        return await client.get(target, params=params, timeout=8, follow_redirects=True)

    async def _send_post(target: str, data: dict):
        return await client.post(target, data=data, timeout=8, follow_redirects=True)

    async def _run_probes_on_field(
        method: str, target: str, field_name: str, values: dict, source: str, baseline_body: str
    ):
        for category, payload, severity, detector, name_ok in probe_defs:
            if not name_ok(field_name):
                continue
            trial = dict(values)
            trial[field_name] = str(trial.get(field_name) or "1") + payload
            try:
                if method == "POST":
                    response = await _send_post(target, trial)
                else:
                    response = await _send_get(target, trial)
                body = response.text or ""
                # Require response to differ from baseline (length or content) for non-XSS
                if category != "xss" and baseline_body:
                    if body.strip() == baseline_body.strip():
                        continue
                    if abs(len(body) - len(baseline_body)) < 8 and category in ("sql_injection", "ssrf"):
                        # Tiny delta often means generic soft-error — still allow SQL_ERROR_RE hit
                        if category == "sql_injection" and not SQL_ERROR_RE.search(body):
                            continue
                marker = rce_marker if category == "rce" else (xss_marker if category == "xss" else payload)
                if category == "ssrf":
                    hit = detector(body, baseline_body, marker)
                else:
                    hit = detector(body, payload, marker)
                if hit:
                    # XSS must not already be in baseline
                    if category == "xss" and marker in (baseline_body or ""):
                        continue
                    evidence = _active_match_evidence(
                        category, body, payload, marker, baseline_body
                    )
                    add(
                        category,
                        severity,
                        f"Active {category} probe confirmed on {source} '{field_name}' at {target}",
                        evidence,
                    )
            except Exception:
                continue

    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if pairs:
        values = {name: value for name, value in pairs}
        try:
            baseline_resp = await _send_get(url, values)
            baseline_body = baseline_resp.text or ""
        except Exception:
            baseline_body = ""
        # Prioritize interesting param names first
        ordered = sorted(
            pairs,
            key=lambda item: (
                0
                if sql_names.match(item[0]) or SSRF_PARAM_RE.match(item[0])
                or OPEN_REDIRECT_PARAM_RE.match(item[0])
                or re.match(r"(?i)^(file|path|cmd|q|search)$", item[0])
                else 1
            ),
        )
        for name, _value in ordered[:max_params]:
            await _run_probes_on_field("GET", url, name, values, "query param", baseline_body)
            # Active open-redirect: confirm Location / refresh points at probe host
            if OPEN_REDIRECT_PARAM_RE.match(name):
                trial = dict(values)
                trial[name] = redirect_probe
                try:
                    response = await client.get(
                        url.split("?", 1)[0],
                        params=trial,
                        timeout=8,
                        follow_redirects=False,
                    )
                    location = response.headers.get("location") or ""
                    if "crawler-open-redirect-probe.invalid" in location.lower():
                        add(
                            "open_redirect",
                            "high",
                            f"Active open redirect confirmed via Location on param '{name}' at {url.split('?', 1)[0]}",
                            _text_evidence(f"Location: {location}", label="redirect_location"),
                        )
                except Exception:
                    pass

    if forms:
        for form in forms[:max_forms]:
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            fields = [field for field in form.get("fields", []) if field][:max_params]
            if not fields:
                continue
            values = {field: "test" for field in form.get("fields", []) if field}
            try:
                if method == "POST":
                    baseline_resp = await _send_post(action, values)
                else:
                    baseline_resp = await _send_get(action, values)
                baseline_body = baseline_resp.text or ""
            except Exception:
                baseline_body = ""
            for field in fields:
                await _run_probes_on_field(method, action, field, values, "form field", baseline_body)

    # GraphQL introspection confirmation (POST)
    findings.extend(await confirm_graphql_introspection(client, url))
    # IDOR object-id mutation (multi-signal)
    try:
        from exploit_probes import probe_idor

        findings.extend(await probe_idor(client, url, max_params=min(4, max_params)))
    except Exception:
        pass
    try:
        from tier_security import run_tier_active

        findings.extend(await run_tier_active(client, url, body_text=body_text or ""))
    except Exception:
        pass
    return findings


async def confirm_graphql_introspection(client, url: str) -> List[Finding]:
    """POST a minimal introspection probe when the URL looks like GraphQL."""
    path = urlparse(url).path or ""
    if not GRAPHQL_PATH_RE.search(path):
        return []
    query = {"query": "{ __schema { queryType { name } } }"}
    try:
        response = await client.post(url, json=query, timeout=10, follow_redirects=True)
        body = response.text or ""
        m = re.search(
            r'(?i)"__schema"\s*:|"queryType"\s*:\s*\{\s*"name"', body
        )
        if response.status_code < 500 and m:
            return [
                (
                    "api_leak",
                    "high",
                    f"GraphQL introspection confirmed via POST at {url}",
                    _match_evidence(m, body, label="graphql_introspection"),
                )
            ]
    except Exception:
        return []
    return []


async def probe_http_methods(client, url: str) -> List[Finding]:
    """Once-per-host OPTIONS/TRACE — emit only risky methods or TRACE echo proof."""
    findings: List[Finding] = []
    allow = ""
    try:
        opt = await client.request("OPTIONS", url, timeout=8, follow_redirects=True)
        allow = opt.headers.get("allow") or opt.headers.get("Access-Control-Allow-Methods") or ""
        dangerous = [m for m in ("TRACE", "TRACK", "DEBUG") if m in allow.upper()]
        if dangerous:
            findings.append(
                (
                    "http_methods",
                    "medium",
                    f"Potentially risky methods advertised: {', '.join(dangerous)} (Allow/ACAM: {allow[:120]})",
                    _text_evidence(allow[:160], label="Allow/ACAM"),
                )
            )
        # Benign Allow lists stay out of findings (inventory via caller if needed)
    except Exception:
        pass
    try:
        trace = await client.request("TRACE", url, timeout=8, follow_redirects=False)
        body = trace.text or ""
        # Require echo of TRACE method or request target — bare HTTP 200 is weak
        echo_m = re.search(r"(?i)^\s*TRACE\s+", body)
        path = urlparse(url).path or ""
        echoed = bool(
            echo_m
            or "TRACE" in body[:200]
            or (path and path in body)
        )
        if trace.status_code < 400 and echoed:
            if echo_m:
                evidence = _match_evidence(echo_m, body, label="trace_echo")
            elif path and path in body:
                evidence = _text_evidence(path, label="trace_echo_path")
            else:
                evidence = _text_evidence(body[:120], label="trace_body")
            findings.append(
                (
                    "http_methods",
                    "high",
                    f"TRACE enabled with request echo (HTTP {trace.status_code})",
                    evidence,
                )
            )
        elif trace.status_code == 200 and "TRACE" in (allow or "").upper():
            findings.append(
                (
                    "http_methods",
                    "medium",
                    f"TRACE advertised and returned HTTP {trace.status_code}",
                    _text_evidence(allow[:160], label="Allow/ACAM"),
                )
            )
    except Exception:
        pass
    return findings


async def probe_active_injection(client, url: str, max_params: int = 3) -> List[Finding]:
    """Backward-compatible wrapper."""
    return await run_active_vuln_probes(client, url, forms=None, max_params=max_params, max_forms=0)
