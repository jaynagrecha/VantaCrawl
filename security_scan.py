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
    (r"sk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "OpenAI API Key", "critical"),
    (r"sk-proj-[A-Za-z0-9_\-]{40,}", "OpenAI API Key", "critical"),
    # Legacy OpenAI sk- keys: require high entropy and exclude hyphenated natural-language tokens
    (r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{48,}(?![A-Za-z0-9_-])", "OpenAI API Key", "critical"),
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
        "contraseña",
        "contrasena",
        "senha",
        "motdepasse",
        "passwort",
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
        "forgot_password",
        "forgotpassword",
        "reset_password",
        "resetpassword",
    }
)

# LHS names that mean route/flow identifiers, not credentials — even when the
# value contains PASSWORD (FORGOT_PASSWORD = "R3ResetPass").
_NON_SECRET_LHS_KEYWORDS = frozenset(
    {
        "route",
        "src",
        "source",
        "flow",
        "action",
        "event",
        "page",
        "screen",
        "deeplink",
        "deep_link",
        "deep-link",
        "forgot_password",
        "forgotpassword",
        "reset_password",
        "resetpassword",
        "changepassword",
        "change_password",
        "navigateto",
        "navigate_to",
        "screenname",
        "screen_name",
        "flowid",
        "flow_id",
        "flowkey",
        "flow_key",
        "deepLinkSrc",
        "deeplinksrc",
    }
)

# Known frontend deep-link / flow identifiers mistaken for passwords
_KNOWN_FLOW_IDENTIFIERS = frozenset(
    {
        "r3resetpass",
        "r3reset-pass",
        "r3reset_pass",
        "r3forgotpass",
        "r3forgot-pass",
        "verifier",
        "vérifier",
        "reinitialiser",
        "réinitialiser",
        "resetpass",
        "forgotpass",
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


def classify_secret_candidate(
    name: str,
    value: str,
    surrounding_code: str = "",
    *,
    raw: str = "",
) -> Optional[str]:
    """Return a non-secret role when the candidate is a flow/route identifier.

    Do not treat strings as passwords merely because their identifier contains PASSWORD.
    """
    name_l = _normalize_field_token(name or "")
    # Also accept dotted / camelCase LHS tails
    name_tail = (name or "").strip().rsplit(".", 1)[-1]
    name_tail_l = name_tail.lower().replace("-", "_")
    value_l = (value or "").strip().lower()
    value_norm = re.sub(r"[^a-z0-9]+", "", value_l)
    ctx = (surrounding_code or "") + "\n" + (raw or "")
    ctx_l = ctx.lower()

    non_secret_norms = {_normalize_field_token(k) for k in _NON_SECRET_LHS_KEYWORDS}
    if name_l in non_secret_norms or name_tail_l.replace("_", "") in {
        _normalize_field_token(k) for k in _NON_SECRET_LHS_KEYWORDS
    }:
        return "flow_or_route_identifier"
    # FORGOT_PASSWORD / RESET_PASSWORD LHS assigned to a short identifier
    if re.search(r"(?i)(?:forgot|reset|change)[_-]?pass(?:word)?$", name_tail):
        if value_norm in _KNOWN_FLOW_IDENTIFIERS or (
            _IDENT_LIKE_VALUE_RE.match(value or "") and len(value or "") <= 32
        ):
            return "flow_or_route_identifier"
    if "switch" in ctx_l and re.search(r"(?i)query\.src|props\.query\.src|\.src\b", ctx):
        if value_norm in _KNOWN_FLOW_IDENTIFIERS or re.search(
            r"(?i)reset.?pass|forgot.?pass", value_l
        ):
            return "deep_link_identifier"
    if value_norm in _KNOWN_FLOW_IDENTIFIERS or value_l in _KNOWN_FLOW_IDENTIFIERS:
        return "known_non_secret_flow_identifier"
    # Localization / UI verbs used as button labels
    if value_l in {
        "contraseña",
        "contrasena",
        "senha",
        "mot de passe",
        "passwort",
        "password",
        "passwd",
        "default.password",
        "verifier",
        "vérifier",
        "réinitialiser",
        "reinitialiser",
    }:
        return "localization_or_ui_label"
    return None


def _should_skip_secret_match(
    *,
    label: str,
    raw: str,
    body_text: str,
    start: int,
    end: int,
    value: str,
) -> bool:
    """Drop form-control / UI-schema / route-label / deep-link false positives."""
    value_l = (value or "").strip().lower()
    lhs = _lhs_from_raw(raw)
    window = body_text[max(0, start - 220) : min(len(body_text), end + 220)]
    role = classify_secret_candidate(lhs, value, window, raw=raw)
    if role:
        return True
    # Localization / UI labels are never passwords
    if value_l in {
        "contraseña",
        "contrasena",
        "senha",
        "mot de passe",
        "passwort",
        "password",
        "passwd",
        "default.password",
    }:
        return True
    # A route containing forgot-password / reset-password is never a password secret
    if re.search(
        r"(?i)forgot[-_/]?password|reset[-_/]?password|change[-_/]?password|"
        r"save[-_/]?password|default\.password|gwp.?save.?password",
        value_l,
    ):
        return True
    if value_l.startswith("/") and re.search(r"(?i)password|contraseñ|senha", value_l):
        return True
    # Entire match is a URL path containing password wording
    if re.search(
        r"(?i)(?:^|[\"'`=\s])/[^\s\"']*(?:forgot|reset|change|save)[-_/]?password",
        raw or "",
    ):
        return True
    # OpenAI: reject hyphenated natural-language after sk- (sk-karlek-och-…)
    if label == "OpenAI API Key":
        rest = (value or "")[3:]
        if rest.startswith("proj-") or rest.startswith("svcacct-"):
            return False
        if "-" in rest[:32]:
            return True
        return False
    # JWT-shaped values: skip when exp is already past
    if re.match(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", (value or "").strip()):
        try:
            import base64
            import json
            import time

            mid = (value or "").split(".")[1]
            pad = "=" * (-len(mid) % 4)
            payload = json.loads(base64.urlsafe_b64decode(mid + pad))
            exp = payload.get("exp")
            if isinstance(exp, (int, float)) and exp < time.time() - 60:
                return True
        except Exception:
            pass
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
            # Unstable nearby-identifier product names must not rename public client keys
            try:
                from enum_validation import is_public_client_key_value

                if is_public_client_key_value(value or ""):
                    typed = "Public client-key-like value"
            except Exception:
                if (value or "").lower().startswith("pubkey-"):
                    typed = "Public client-key-like value"
            # Same secret value under different product labels ("Ript" vs "Text") = one finding
            value_key = (value or "").strip()
            dedupe = value_key[:120] if len(value_key) >= 8 else (typed, value_key or raw[:80])
            if dedupe in seen:
                continue
            # HTML/JS data-* attributes are markup, not credentials (even if product label refined)
            try:
                from secret_classify import find_assignment_ident

                assign = find_assignment_ident(body_text, match.start(), match.end(), value or "")
                assign_l = (assign or "").lower().rsplit(".", 1)[-1]
                if assign_l.startswith("data-") or assign_l.startswith("data_") or assign_l.startswith("aria-"):
                    continue
            except Exception:
                pass
            seen.add(dedupe)
            note = assignment_note(body_text, match.start(), match.end(), value)
            detail = f"Exposed {typed} in response body{note}"
            sev = severity_for_kind(typed, severity, value or "")
            # Public client keys: never export the full value in JSON/CSV/Burp/ZAP
            evidence_out = value or None
            if typed == "Public client-key-like value" or (value or "").lower().startswith("pubkey-"):
                evidence_out = mask_secret_value(value or "")
                detail = (
                    f"Exposed Public client-key-like value in response body{note} "
                    "(provider unknown — unstable product inference suppressed)"
                )
                sev = "info"
            findings.append(
                (typed, sev, detail, evidence_out)
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
    # HTML <meta name="…"> values are document metadata, not request parameters
    _META_NOT_PARAMS = frozenset(
        {
            "viewport",
            "description",
            "theme-color",
            "keywords",
            "author",
            "robots",
            "googlebot",
            "referrer",
            "color-scheme",
            "format-detection",
            "apple-mobile-web-app-capable",
            "apple-mobile-web-app-status-bar-style",
            "msapplication-tilecolor",
            "twitter:card",
            "twitter:title",
            "og:title",
            "og:description",
            "og:image",
            "og:type",
            "og:url",
        }
    )
    params = []
    parsed = urlparse(url)
    for name, values in parse_qs(parsed.query).items():
        params.append({"url": url, "name": name, "source": "query", "sample": values[:3]})
    for match in PARAM_NAME_RE.findall(url):
        if match not in {p["name"] for p in params}:
            params.append({"url": url, "name": match, "source": "url_pattern", "sample": []})
    if body_text:
        # Prefer real form controls over bare name= attributes (which include <meta>)
        for match in re.findall(
            r'(?is)<(?:input|select|textarea)\b[^>]*\bname=["\']([^"\']+)["\']',
            body_text,
        ):
            if match.casefold() in _META_NOT_PARAMS:
                continue
            if match not in {p["name"] for p in params}:
                params.append({"url": url, "name": match, "source": "html_input", "sample": []})
    if forms:
        for form in forms:
            for field in form.get("fields", []):
                if str(field).casefold() in _META_NOT_PARAMS:
                    continue
                params.append({"url": form.get("action", url), "name": field, "source": "form", "sample": []})
    return params


async def check_cors(
    client, url: str, origin: str = "https://evil.example"
) -> Optional[tuple]:
    """Probe CORS; return (detail, proof_dict) only for credentialed open/reflected Origin.

    Proof always includes raw request/response header lines so confirmation is evidence-backed.
    """
    try:
        from finding_proof import FindingProof

        response = await client.get(
            url,
            headers={"Origin": origin},
            timeout=10,
        )
        acao = (response.headers.get("access-control-allow-origin") or "").strip()
        acac = (response.headers.get("access-control-allow-credentials") or "").strip()
        acac_l = acac.lower()
        creds = acac_l == "true"
        detail = None
        if acao == "*" and creds:
            detail = "CORS allows any origin (*) with credentials — high risk"
        elif acao == origin and creds:
            detail = f"CORS reflects arbitrary Origin ({origin}) with credentials — high risk"
        else:
            # Reflection without credentials is common for public assets; keep quiet
            return None

        host = ""
        try:
            from urllib.parse import urlparse

            host = urlparse(url).netloc or ""
        except Exception:
            host = ""
        cookie_hdr = ""
        try:
            cookie_hdr = (response.request.headers.get("cookie") or "")[:120]
        except Exception:
            cookie_hdr = ""
        req_lines = [
            f"GET {url} HTTP/1.1",
            f"Host: {host}" if host else "",
            f"Origin: {origin}",
        ]
        if cookie_hdr:
            req_lines.append(f"Cookie: {cookie_hdr}")
        resp_lines = [
            f"HTTP/1.1 {int(getattr(response, 'status_code', 0) or 0)}",
            f"Access-Control-Allow-Origin: {acao}",
            f"Access-Control-Allow-Credentials: {acac or 'true'}",
        ]
        vary = (response.headers.get("vary") or "").strip()
        if vary:
            resp_lines.append(f"Vary: {vary}")
        proof = FindingProof(
            request="\n".join(x for x in req_lines if x),
            response="\n".join(resp_lines),
            evidence=f"ACAO={acao}; ACAC={acac or 'true'}",
            impact="Cross-origin credentialed reads possible if session cookies are present",
        )
        return detail, proof.as_dict()
    except Exception:
        return None


def extract_forms(html: str, page_url: str, content_type: str = "") -> List[Dict[str, Any]]:
    forms = []
    if not html:
        return forms

    from crawler_common import is_html_content
    from crawl_url_policy import form_fingerprint, resolve_http_target

    path = urlparse(page_url).path
    if not is_html_content(content_type, path, html):
        return forms

    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        raw_action = (form.get("action") or "").strip()
        if not raw_action or raw_action.startswith("#"):
            action = page_url
        else:
            action = resolve_http_target(raw_action, page_url)
            if not action:
                # javascript: / mailto: / empty — not a curl target
                continue
        method = (form.get("method") or "GET").upper()
        enctype = (form.get("enctype") or "").strip()
        fields = []
        field_pairs = []
        file_fields = []
        file_accepts: List[str] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                fields.append(name)
                typ = (inp.get("type") or inp.name or "text").lower()
                field_pairs.append((name, typ))
            if (inp.name or "").lower() == "input" and (inp.get("type") or "").lower() == "file":
                file_fields.append(name or "(unnamed-file)")
                accept = (inp.get("accept") or "").strip()
                if accept:
                    file_accepts.append(accept)
        form_key = form_fingerprint(
            method=method, action=action, fields=field_pairs, enctype=enctype
        )
        forms.append(
            {
                "action": action,
                "method": method,
                "fields": fields,
                "field_types": field_pairs,
                "enctype": enctype,
                "form_key": form_key,
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
_SQL_PAYLOAD_RE = re.compile(
    r"[\"'`;]|--(?:\s|$)|/\*|"
    r"\bunion\s+select\b|"
    r"\bselect\b.+\bfrom\b|"
    r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    re.I,
)

# Active SSRF: require cloud-metadata *proof tokens*, not mere reflection of the probe IP/URL.
_SSRF_METADATA_PROOF_RE = re.compile(
    r"(?i)(ami-[0-9a-f]{8,}|\"?instance-id\"?\s*[:=]|computeMetadata|"
    r"metadata\.google\.internal|project-id\"?\s*[:=])"
)
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
    """Precise passive XSS — only dangerous executable sinks (not document.cookie assignment)."""
    findings: List[Finding] = []
    if not body_text:
        return findings
    params = _query_params(url)
    # document.cookie = is standard browser API usage; report as cookie manipulation only,
    # never as XSS and never as a reason to elevate CSP.
    if not _looks_like_code_listing(body_text):
        cookie_assign = re.search(
            r"(?is)<script[^>]*>.*?document\.cookie\s*=.*?</script>",
            body_text[:200000],
        )
        if cookie_assign and not re.search(
            r"(?i)(eval\s*\(|new\s+Function\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|"
            r"document\.write\s*\(|insertAdjacentHTML\s*\()",
            cookie_assign.group(0),
        ):
            # Observation only — do not create an XSS finding from cookie assignment alone
            pass
        for match in re.finditer(
            r"(?is)<script[^>]*>(.*?)</script>",
            body_text[:200000],
        ):
            block = match.group(1) or ""
            sink = re.search(
                r"(?i)(eval\s*\(|new\s+Function\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|"
                r"document\.write\s*\(|insertAdjacentHTML\s*\()",
                block,
            )
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
                        "Inline script with executable sink and reflected parameter (precise passive XSS)",
                        f"{sink_ev} | reflected_param: {reflected_name}",
                    )
                )
            elif not analytics:
                findings.append(
                    (
                        "xss",
                        "info",
                        "Potential DOM execution sink — source-to-sink flow not established",
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
                "info",
                f"File-upload surface discovered at {action} via {method} "
                f"({why}); server-side validation not assessed",
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


def scan_password_reset_deep_links(url: str, body_text: str) -> List[Finding]:
    """Report password-reset deep-link flows as attack-surface — not secrets.

    Distinguishes ``src=R3ResetPass`` (flow id) from ``query.token`` (real sensitive
    value that should leave the address bar via replaceState).
    """
    findings: List[Finding] = []
    text = body_text or ""
    if not text:
        return findings
    # Detect known flow constants / switch(src) deep-link routing
    flow_hit = None
    for m in re.finditer(
        r"""(?i)(?:FORGOT_PASSWORD|RESET_PASSWORD)\s*=\s*['"]([^'"]{3,48})['"]""",
        text[:250000],
    ):
        val = m.group(1)
        role = classify_secret_candidate("RESET_PASSWORD", val, text[m.start() : m.end() + 80])
        if role or re.sub(r"[^a-z0-9]+", "", val.lower()) in _KNOWN_FLOW_IDENTIFIERS:
            flow_hit = val
            break
    if not flow_hit:
        m = re.search(
            r"""(?i)(?:query\.src|props\.query\.src)\s*(?:\.toLowerCase\(\))?\s*(?:===|==)\s*['"]([^'"]{3,48})['"]""",
            text[:250000],
        )
        if m and (
            "reset" in m.group(1).lower()
            or "forgot" in m.group(1).lower()
            or re.sub(r"[^a-z0-9]+", "", m.group(1).lower()) in _KNOWN_FLOW_IDENTIFIERS
        ):
            flow_hit = m.group(1)
    if flow_hit:
        findings.append(
            (
                "authentication",
                "info",
                (
                    f"Password-reset deep-link flow discovered (src={flow_hit}). "
                    "Client uses this as a flow identifier; a separate token query parameter "
                    "is required — attack-surface observation, not an exposed credential."
                ),
                _text_evidence(flow_hit, label="password_reset_deep_link"),
            )
        )
    # Real security direction: reset token arrives via query and may linger in the URL bar
    token_query = re.search(
        r"(?i)(?:query|props\.query|searchParams)\.(?:token|resetToken|reset_token)\b",
        text[:250000],
    )
    if token_query and (
        flow_hit
        or re.search(r"(?i)reset.?pass|forgot.?pass|navigateToReset", text[:250000])
    ):
        sanitizes = bool(
            re.search(
                r"(?i)history\.replaceState|router\.(?:replace|push)|replaceState\s*\(",
                text[:250000],
            )
        )
        deletes_only = bool(
            re.search(
                r"(?i)delete\s+(?:props\.)?query\.(?:token|src)|delete\s+[a-zA-Z_][\w.]*\.token",
                text[:250000],
            )
        )
        if deletes_only and not sanitizes:
            findings.append(
                (
                    "authentication",
                    "low",
                    (
                        "Reset token arrives via URL query parameter; client deletes the JS "
                        "property but no history.replaceState/router.replace was observed — "
                        "token may remain in the address bar, history, and Referer."
                    ),
                    _match_evidence(token_query, text[:250000], label="reset_token_query"),
                )
            )
        elif not sanitizes:
            findings.append(
                (
                    "authentication",
                    "info",
                    (
                        "Reset token referenced from URL query — verify single-use/expiry, "
                        "address-bar sanitization (replaceState), Referrer-Policy, and that "
                        "analytics/third parties do not receive the token."
                    ),
                    _match_evidence(token_query, text[:250000], label="reset_token_query"),
                )
            )
    return findings


def scan_authentication_flaws(url: str, headers: dict, body_text: str = "") -> List[Finding]:
    """HTTP auth findings require a real login surface — not path keywords like /author."""
    findings: List[Finding] = []
    findings.extend(scan_password_reset_deep_links(url, body_text))
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
    """One finding per HTTP resource URL so reports group by evidence, not page spam."""
    findings: List[Finding] = []
    try:
        from recon_extract import extract_mixed_content

        resources = extract_mixed_content(url, body_text or "")
    except Exception:
        resources = []
    for resource in resources[:12]:
        findings.append(
            (
                "mixed_content",
                "medium",
                f"HTTPS page loads HTTP resource (mixed content): {resource}",
                _text_evidence(resource, label="http_resource"),
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


# Active-probe response classes that must never confirm SQLi/XSS/RCE/SSRF.
_ACTIVE_CONTAMINATED = frozenset(
    {
        "edge_checkpoint",
        "captcha",
        "rate_limit",
        "generic_waf_deny",
        "origin_failure",
    }
)

# State-changing form actions — POST active mutation stays off unless explicitly authorized.
_MUTATION_DENY_RE = re.compile(
    r"(?i)/(?:account/delete|checkout|payment|password/change|admin/update|message/send)(?:/|$|\?)"
)

_XSS_MARKER = "<crawler-xss-probe>"
_XSS_BREAKOUT_MARKER = "data-crawler-xss"
_XSS_BREAKOUT_PAYLOAD = '"><img data-crawler-xss="1" src=x>'
_RCE_MARKER = "crawler-rce-probe-9f3a"


def _normalize_probe_text(text: str) -> str:
    """Strip dynamic noise so baseline vs probe compares application content."""
    t = (text or "").lower()
    t = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", t)
    t = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", t)
    t = re.sub(
        r"(?i)(?:csrf(?:[_-]?token)?|_token|nonce|request[_-]?id|session(?:id)?|authenticity_token)"
        r"[\s\"'=:]+[a-z0-9_\-]{4,}",
        "#tok",
        t,
    )
    t = re.sub(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", "#", t)
    t = re.sub(r"\b[a-f0-9]{8,}\b", "#", t)
    t = re.sub(r"\b\d{10,13}\b", "#", t)  # epoch / ms timestamps
    t = re.sub(r"\b\d{4,}\b", "#", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _probe_normalized_hash(text: str) -> str:
    import hashlib

    return hashlib.sha256(_normalize_probe_text(text).encode("utf-8", errors="replace")).hexdigest()[:32]


def _bodies_meaningfully_differ(baseline: str, probe: str) -> bool:
    """True when normalized bodies differ (ignores nonce/token/timestamp churn)."""
    return _normalize_probe_text(baseline) != _normalize_probe_text(probe)


def _classify_active_response(
    status_code: int,
    body: str = "",
    headers: Optional[Dict[str, Any]] = None,
) -> str:
    """Classify probe response; contaminated classes cannot confirm vulns."""
    if int(status_code or 0) <= 0:
        return "origin_failure"
    body_l = (body or "").lower()[:12000]
    try:
        from edge_checkpoint import is_edge_checkpoint

        cp = is_edge_checkpoint(status_code, body, headers)
        if cp:
            return "edge_checkpoint"
    except Exception:
        pass
    try:
        from evasion_layer import detect_challenge

        ch = (detect_challenge(status_code, body, headers) or "").lower()
        if ch in ("rate_limit", "akamai_rate_burst") or int(status_code or 0) == 429:
            return "rate_limit"
        if any(tok in ch for tok in ("captcha", "recaptcha", "hcaptcha", "turnstile")):
            return "captcha"
        if ch in (
            "waf_block",
            "akamai_soft_deny",
            "cloudflare_soft_deny",
            "soft_deny",
        ) or any(tok in ch for tok in ("cloudflare", "akamai", "datadome", "perimeterx")):
            return "generic_waf_deny"
        if "checkpoint" in ch or "just a moment" in ch:
            return "edge_checkpoint"
        if ch:
            return "generic_waf_deny"
    except Exception:
        pass
    if int(status_code or 0) == 429:
        return "rate_limit"
    if any(tok in body_l for tok in ("captcha", "hcaptcha", "recaptcha", "cf-turnstile")):
        return "captcha"
    if any(
        tok in body_l
        for tok in (
            "vercel security checkpoint",
            "checking your browser",
            "attention required! | cloudflare",
            "cf-browser-verification",
        )
    ):
        return "edge_checkpoint"
    # WAF deny pages often echo attack keywords — never treat as app proof
    if re.search(
        r"(?i)(sql\s*injection\s*detected|xss\s*(?:attack\s*)?detected|attack\s*detected|"
        r"request\s*blocked|not\s*acceptable|web\s*application\s*firewall)",
        body_l,
    ) and re.search(
        r"(?i)(waf|cloudflare|akamai|blocked|denied|forbidden|firewall|modsecurity|imperva)",
        body_l,
    ):
        return "generic_waf_deny"
    if int(status_code or 0) in (403, 503) and re.search(
        r"(?i)(waf|blocked|access denied|firewall|security)",
        body_l,
    ):
        return "generic_waf_deny"
    return "application_response"


def _is_contaminated_response(classification: str) -> bool:
    return (classification or "") in _ACTIVE_CONTAMINATED


def _mutation_form_blocked(action: str, method: str) -> bool:
    """POST to state-changing endpoints stays passive-only."""
    if (method or "GET").upper() != "POST":
        return False
    path = urlparse(action or "").path or action or ""
    return bool(_MUTATION_DENY_RE.search(path))


def _html_entity_encode_marker(marker: str) -> str:
    return (
        (marker or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


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
        if _XSS_BREAKOUT_MARKER in text:
            return _text_evidence(_XSS_BREAKOUT_MARKER, label="xss_breakout_marker")
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
        m = _SSRF_METADATA_PROOF_RE.search(text)
        if m:
            return _match_evidence(m, text, label="ssrf_metadata_proof")
        return _text_evidence(payload, label="ssrf_payload")
    return _text_evidence(payload or marker, label="probe")


def _sql_error_new_vs_baseline(body: str, baseline: str) -> bool:
    """True only when a SQL error appears after the probe and was absent in baseline."""
    if not SQL_ERROR_RE.search(body or ""):
        return False
    if SQL_ERROR_RE.search(baseline or ""):
        return False
    return True


def _sql_new_evidence_labels(body: str) -> List[str]:
    m = SQL_ERROR_RE.search(body or "")
    if not m:
        return []
    raw = (m.group(0) or "").strip()
    return [raw[:120] or "SQL error newly introduced"]


def _ssrf_metadata_proof_new(body: str, baseline: str) -> bool:
    """True only for cloud-metadata proof tokens that were not already in baseline.

    Reflecting the probe IP/URL in an 'Invalid URL: …' error is not proof.
    """
    if not _SSRF_METADATA_PROOF_RE.search(body or ""):
        return False
    if _SSRF_METADATA_PROOF_RE.search(baseline or ""):
        return False
    return True


def _classify_xss_probe(
    body: str, marker: str, baseline: str, *, payload: str = ""
) -> Optional[Dict[str, str]]:
    """Evidence-graded XSS disposition. Encoded reflection → no finding."""
    text = body or ""
    base = baseline or ""
    encoded = _html_entity_encode_marker(marker)

    # Encoded-only reflection of the primary marker → reject as vulnerability
    if marker not in text:
        if payload == _XSS_BREAKOUT_PAYLOAD:
            if _XSS_BREAKOUT_MARKER not in text:
                return None
            if _XSS_BREAKOUT_MARKER in base:
                return None
            if re.search(r'(?is)<img\b[^>]*\bdata-crawler-xss\s*=\s*["\']?1', text):
                return {
                    "severity": "medium",
                    "detail_bit": "attribute/context breakout candidate (not browser-confirmed)",
                    "validation_state": "attribute_breakout",
                    "confidence": "medium",
                    "verification": "verified",
                }
            return None
        if encoded in text and encoded not in base:
            return None  # properly HTML-encoded — not vulnerable
        return None

    if marker in base:
        return None

    idx = text.find(marker)
    window = text[max(0, idx - 100) : idx + len(marker) + 100] if idx >= 0 else text

    # Script / event-handler context still requires browser confirmation for "confirmed XSS"
    if re.search(r"(?is)<script\b[^>]*>[^<]{0,200}" + re.escape(marker), text) or re.search(
        r"(?is)\bon\w+\s*=\s*['\"][^'\"]{0,80}" + re.escape(marker),
        text,
    ):
        return {
            "severity": "medium",
            "detail_bit": "sink-context candidate (not browser-confirmed execution)",
            "validation_state": "sink_context_candidate",
            "confidence": "medium",
            "verification": "verified",
        }

    if re.search(r'''(?is)["']\s*(?:autofocus|on\w+)\b''', window):
        return {
            "severity": "medium",
            "detail_bit": "attribute/context breakout candidate (not browser-confirmed)",
            "validation_state": "attribute_breakout",
            "confidence": "medium",
            "verification": "verified",
        }

    # Raw unencoded reflection in HTML text — unverified candidate, not Medium vuln
    return {
        "severity": "info",
        "detail_bit": "unverified reflection candidate (marker in HTML text; not proven executable)",
        "validation_state": "reflection_only",
        "confidence": "low",
        "verification": "detected",
    }


def _rce_executed_not_reflected(body: str, marker: str, payload: str, baseline: str) -> bool:
    """Marker must appear as execution output, not as a reflected shell command string."""
    text = body or ""
    if marker not in text:
        return False
    if marker in (baseline or ""):
        return False
    if payload and payload in text:
        return False
    if f"echo {marker}" in text.lower():
        return False
    # Marker only inside HTML comments is not execution proof
    if re.search(r"(?is)<!--[^>]*" + re.escape(marker), text) and text.count(marker) == 1:
        return False
    return True


def _traversal_proof_new(body: str, baseline: str) -> bool:
    proof = re.search(r"(?i)(root:x:0:0:|/bin/(?:ba)?sh\b)", body or "")
    if not proof:
        return False
    if re.search(r"(?i)(root:x:0:0:|/bin/(?:ba)?sh\b)", baseline or ""):
        return False
    return True


def _build_active_proof(
    *,
    endpoint: str,
    method: str,
    parameter: str,
    baseline_status: int,
    probe_status: int,
    baseline_body: str,
    probe_body: str,
    payload_class: str,
    new_evidence: List[str],
    response_classification: str,
    confidence: str,
    validation_state: str,
    evidence_line: str = "",
) -> Dict[str, Any]:
    """Required evidence bundle for every active finding (screenshot contract)."""
    return {
        "endpoint": endpoint,
        "method": method,
        "parameter": parameter,
        "baseline_status": int(baseline_status or 0),
        "probe_status": int(probe_status or 0),
        "baseline_normalized_hash": _probe_normalized_hash(baseline_body),
        "probe_normalized_hash": _probe_normalized_hash(probe_body),
        "payload_class": payload_class,
        "new_evidence": list(new_evidence or []),
        "response_classification": response_classification,
        "waf_or_checkpoint": bool(_is_contaminated_response(response_classification)),
        "confidence": confidence,
        "validation_state": validation_state,
        "request_proof_redacted": f"{method} {endpoint} param={parameter} class={payload_class}"[:500],
        "response_proof_redacted": (evidence_line or (probe_body or "")[:240])[:500],
        "evidence": (evidence_line or "")[:2000],
        "request": f"{method} {endpoint}"[:500],
        "response": (probe_body or "")[:500],
    }


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

    Hits require differential evidence vs a successful per-endpoint baseline, reject
    WAF/checkpoint contamination, and attach a structured proof bundle. XSS uses an
    evidence ladder (encoded → reject; plain reflection → info candidate; breakout →
    medium candidate; browser execution not claimed without confirmation).
    """
    from urllib.parse import parse_qsl, urlparse as _urlparse

    findings: List[Any] = []
    seen: set = set()
    xss_marker = _XSS_MARKER
    rce_marker = _RCE_MARKER

    def add(
        category: str,
        severity: str,
        detail: str,
        evidence: Optional[str] = None,
        *,
        meta: Optional[Dict[str, Any]] = None,
    ):
        key = (category, detail, evidence or "", str((meta or {}).get("proof", {}).get("validation_state") or ""))
        if key not in seen:
            seen.add(key)
            if meta:
                findings.append((category, severity, detail, evidence, meta))
            else:
                findings.append((category, severity, detail, evidence))

    sql_names = re.compile(r"(?i)^(id|uid|user_id|cat|category|item|pid|order|sort|query|q|search|filter|name)$")
    xss_names = re.compile(
        r"(?i)^(q|query|search|s|keyword|term|name|title|message|comment|text|content|input)$"
    )

    # (category, payload, default_severity, name_ok, payload_class)
    probe_defs = (
        ("sql_injection", "'", "high", lambda name: bool(sql_names.match(name)), "sqli_quote"),
        ("xss", xss_marker, "info", lambda name: bool(xss_names.match(name)), "xss_marker"),
        (
            "xss",
            _XSS_BREAKOUT_PAYLOAD,
            "medium",
            lambda name: bool(xss_names.match(name)),
            "xss_attr_breakout",
        ),
        (
            "directory_traversal",
            "../../../../etc/passwd",
            "critical",
            lambda name: bool(re.match(r"(?i)^(file|path|folder|dir|document|template|include|doc)$", name)),
            "path_traversal",
        ),
        (
            "rce",
            f";echo {rce_marker}",
            "critical",
            lambda name: bool(re.match(r"(?i)^(cmd|command|exec|execute|run|shell)$", name)),
            "rce_echo",
        ),
        (
            "ssrf",
            "http://169.254.169.254/latest/meta-data/",
            "high",
            lambda name: bool(SSRF_PARAM_RE.match(name)),
            "ssrf_imds",
        ),
    )

    redirect_probe = "https://crawler-open-redirect-probe.invalid/confirm"

    async def _send_get(target: str, params: dict):
        return await client.get(target, params=params, timeout=8, follow_redirects=True)

    async def _send_post(target: str, data: dict):
        return await client.post(target, data=data, timeout=8, follow_redirects=True)

    def _resp_meta(response) -> Tuple[int, str, Dict[str, Any], str]:
        # Default 200 when clients omit status_code (test fakes / thin wrappers)
        status = int(getattr(response, "status_code", 200) or 200)
        body = getattr(response, "text", None) or ""
        headers = dict(getattr(response, "headers", None) or {})
        final_url = str(getattr(response, "url", "") or "")
        return status, body, headers, final_url

    async def _run_probes_on_field(
        method: str,
        target: str,
        field_name: str,
        values: dict,
        source: str,
        baseline_body: str,
        *,
        baseline_ok: bool,
        baseline_status: int = 0,
        baseline_final_url: str = "",
    ):
        for category, payload, severity, name_ok, payload_class in probe_defs:
            if not name_ok(field_name):
                continue
            if category in ("sql_injection", "ssrf", "rce", "directory_traversal") and not baseline_ok:
                continue
            trial = dict(values)
            if category == "xss" and payload == _XSS_BREAKOUT_PAYLOAD:
                trial[field_name] = payload
            else:
                trial[field_name] = str(trial.get(field_name) or "1") + payload
            try:
                if method == "POST":
                    response = await _send_post(target, trial)
                else:
                    response = await _send_get(target, trial)
                probe_status, body, headers, probe_final = _resp_meta(response)
                resp_class = _classify_active_response(probe_status, body, headers)
                if _is_contaminated_response(resp_class):
                    continue

                # Redirect-only differences are interesting but not SQLi/XSS proof
                redirect_changed = bool(
                    baseline_final_url
                    and probe_final
                    and str(baseline_final_url).split("?")[0] != str(probe_final).split("?")[0]
                )

                hit = False
                out_severity = severity
                validation_state = "differential_signal"
                confidence = "medium"
                verification = "verified"
                detail_bit = "differential signal"
                new_evidence: List[str] = []
                xss_disp: Optional[Dict[str, str]] = None

                if category == "sql_injection":
                    # Require new SQL error; nonce-only churn is not enough
                    if not _sql_error_new_vs_baseline(body, baseline_body):
                        continue
                    if not _bodies_meaningfully_differ(baseline_body, body) and not SQL_ERROR_RE.search(body or ""):
                        continue
                    hit = True
                    new_evidence = _sql_new_evidence_labels(body)
                    detail_bit = "differential signal (new database error vs baseline)"
                    validation_state = "differential_signal"
                    if redirect_changed:
                        detail_bit += "; redirect also changed (not alone SQLi proof)"
                elif category == "xss":
                    xss_disp = _classify_xss_probe(
                        body, xss_marker, baseline_body, payload=payload
                    )
                    if not xss_disp:
                        continue
                    hit = True
                    out_severity = xss_disp["severity"]
                    detail_bit = xss_disp["detail_bit"]
                    validation_state = xss_disp["validation_state"]
                    confidence = xss_disp["confidence"]
                    verification = xss_disp["verification"]
                    new_evidence = [detail_bit]
                elif category == "directory_traversal":
                    if not _bodies_meaningfully_differ(baseline_body, body):
                        continue
                    hit = _traversal_proof_new(body, baseline_body)
                    detail_bit = "confirmed server-side behavior (passwd/shell marker)"
                    validation_state = "confirmed_server_side_behavior"
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = ["passwd/shell content newly introduced"]
                elif category == "rce":
                    if not _bodies_meaningfully_differ(baseline_body, body) and rce_marker not in body:
                        continue
                    hit = _rce_executed_not_reflected(body, rce_marker, payload, baseline_body)
                    detail_bit = "confirmed server-side behavior (unique echo output)"
                    validation_state = "confirmed_server_side_behavior"
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = [f"executed marker {rce_marker}"]
                elif category == "ssrf":
                    hit = _ssrf_metadata_proof_new(body, baseline_body)
                    detail_bit = "confirmed server-side behavior (metadata proof token)"
                    validation_state = "confirmed_server_side_behavior"
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = ["cloud metadata proof token"]

                if hit:
                    marker = (
                        rce_marker
                        if category == "rce"
                        else (xss_marker if category == "xss" else payload)
                    )
                    evidence = _active_match_evidence(
                        category, body, payload, marker, baseline_body
                    )
                    proof = _build_active_proof(
                        endpoint=target,
                        method=method,
                        parameter=field_name,
                        baseline_status=baseline_status,
                        probe_status=probe_status,
                        baseline_body=baseline_body,
                        probe_body=body,
                        payload_class=payload_class,
                        new_evidence=new_evidence,
                        response_classification=resp_class,
                        confidence=confidence,
                        validation_state=validation_state,
                        evidence_line=evidence or "",
                    )
                    if redirect_changed:
                        proof["redirect_changed"] = True
                        proof["baseline_final_url"] = str(baseline_final_url)[:300]
                        proof["probe_final_url"] = str(probe_final)[:300]
                    add(
                        category,
                        out_severity,
                        f"Active {category} {detail_bit} on {source} '{field_name}' at {target}",
                        evidence,
                        meta={
                            "verification": verification,
                            "confidence": confidence,
                            "confidence_reason": validation_state,
                            "proof": proof,
                            "validation": (
                                "confirmed"
                                if validation_state == "confirmed_server_side_behavior"
                                else "unverified"
                            ),
                        },
                    )
            except Exception:
                continue

    parsed = _urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if pairs:
        values = {name: value for name, value in pairs}
        # Per-endpoint baseline (this URL + method + param set)
        baseline_ok = False
        baseline_body = ""
        baseline_status = 0
        baseline_final = ""
        try:
            baseline_resp = await _send_get(url, values)
            baseline_status, baseline_body, base_headers, baseline_final = _resp_meta(baseline_resp)
            base_class = _classify_active_response(baseline_status, baseline_body, base_headers)
            baseline_ok = not _is_contaminated_response(base_class)
        except Exception:
            baseline_body = ""
            baseline_ok = False
        ordered = sorted(
            pairs,
            key=lambda item: (
                0
                if sql_names.match(item[0])
                or SSRF_PARAM_RE.match(item[0])
                or OPEN_REDIRECT_PARAM_RE.match(item[0])
                or re.match(r"(?i)^(file|path|cmd|q|search)$", item[0])
                else 1
            ),
        )
        for name, _value in ordered[:max_params]:
            await _run_probes_on_field(
                "GET",
                url,
                name,
                values,
                "query param",
                baseline_body,
                baseline_ok=baseline_ok,
                baseline_status=baseline_status,
                baseline_final_url=baseline_final,
            )
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
                    location = (getattr(response, "headers", None) or {}).get("location") or ""
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
            if _mutation_form_blocked(action, method):
                continue
            fields = [field for field in form.get("fields", []) if field][:max_params]
            if not fields:
                continue
            values = {field: "test" for field in form.get("fields", []) if field}
            baseline_ok = False
            baseline_body = ""
            baseline_status = 0
            baseline_final = ""
            try:
                if method == "POST":
                    baseline_resp = await _send_post(action, values)
                else:
                    baseline_resp = await _send_get(action, values)
                baseline_status, baseline_body, base_headers, baseline_final = _resp_meta(baseline_resp)
                base_class = _classify_active_response(baseline_status, baseline_body, base_headers)
                baseline_ok = not _is_contaminated_response(base_class)
            except Exception:
                baseline_body = ""
                baseline_ok = False
            for field in fields:
                await _run_probes_on_field(
                    method,
                    action,
                    field,
                    values,
                    "form field",
                    baseline_body,
                    baseline_ok=baseline_ok,
                    baseline_status=baseline_status,
                    baseline_final_url=baseline_final,
                )

    # GraphQL introspection confirmation (POST)
    findings.extend(await confirm_graphql_introspection(client, url))
    try:
        from exploit_probes import probe_idor

        findings.extend(await probe_idor(client, url, max_params=min(4, max_params)))
    except Exception:
        pass
    try:
        from exploit_probes import probe_csrf

        findings.extend(await probe_csrf(client, url, forms, max_forms=min(3, max_forms)))
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
            # Storefront/schema surface without proof of private data, admin API,
            # auth bypass, cross-user data, or privileged mutation → informational.
            return [
                (
                    "api_leak",
                    "info",
                    f"GraphQL introspection confirmed via POST at {url} "
                    "(informational API-surface observation — no privileged access proven)",
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
