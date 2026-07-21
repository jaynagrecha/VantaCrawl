"""Classify credentials from assignment targets and related nearby variables.

Priority:
  1. Variable / property the value is assigned to (LHS)
  2. Related identifiers / org·company·provider fields nearby
  3. Custom org context (scan target domain + secret_org_hints)
  4. Pattern / prefix base label (AKIA → AWS, sk_live_ → Stripe, …)

Examples:
  paypal_api_key = "…"                    → PayPal API Key
  wu_api_key = "…"  (org=Western Union)   → Western Union API Key
  ACME_ACTIVATION_KEY=…                   → Acme Activation Key
  { company: "Contoso", api_key: "…" }    → Contoso API Key
  db_password=… + username=…              → Db ID and Password
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

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

# LHS = value patterns: bare ident, quoted key, dotted path, env-style
_IDENT_ASSIGN_RE = re.compile(
    r"(?ix)"
    r"(?:(?:const|let|var|export)\s+)?"
    r"(?:"
    r"[\"'](?P<qident>[A-Za-z][\w.\-]{1,100})[\"']"  # "paypal_api_key":
    r"|(?P<path>[A-Za-z][\w]*(?:\.[A-Za-z][\w]*){1,6})"  # config.paypal.apiKey
    r"|(?:process\.env\.)?(?P<ident>[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z0-9]+)*)"
    r")"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"']{6,})"
)

# Any identifier-looking token (for related-variable harvest)
_IDENT_TOKEN_RE = re.compile(
    r"(?ix)\b(?P<ident>[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z0-9]+){0,8})\b"
)

# provider / service / org / company string literals near the secret
_PROVIDER_ASSIGN_RE = re.compile(
    r"(?ix)\b(?:provider|service|vendor|product|platform|integration|source|"
    r"org(?:anization)?|company|tenant|brand|customer|client[_-]?name|business)\b"
    r"\s*[:=]\s*[\"'](?P<name>[A-Za-z][\w.\- ]{1,60})[\"']"
)

_USER_NEAR_RE = re.compile(
    r"(?ix)\b(?:user(?:name)?|login|email|account[_-]?id|user[_-]?id|uid)\b\s*[:=]"
)

_GENERIC_TLDS = frozenset(
    {
        "com",
        "net",
        "org",
        "io",
        "co",
        "app",
        "dev",
        "ai",
        "gov",
        "edu",
        "info",
        "biz",
        "me",
        "us",
        "uk",
        "au",
        "ca",
        "de",
        "fr",
        "jp",
        "in",
        "cloud",
        "local",
        "test",
        "example",
        "invalid",
        "localhost",
    }
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
    "default",
    "value",
    "values",
    "props",
    "state",
    "type",
    "types",
    "key",
    "keys",
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "passwords",
    "credential",
    "credentials",
    "auth",
    "authorization",
    "bearer",
    "basic",
    "api",
    "id",
    "ids",
    "client",
    "app",
    "user",
    "username",
    "login",
    "email",
    "account",
    "access",
    "private",
    "public",
    "production",
    "prod",
    "staging",
    "dev",
    "test",
    "demo",
    "sample",
    "example",
    "number",
    "object",
    "array",
}

_KIND_STOP = {
    "key",
    "keys",
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "passwords",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
    "api",
    "auth",
    "access",
    "refresh",
    "bearer",
    "session",
    "client",
    "app",
    "consumer",
    "private",
    "activation",
    "license",
    "id",
    "ids",
}

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
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "redis": "Redis",
    "aws": "AWS",
    "gcp": "GCP",
    "azure": "Azure",
    "npm": "npm",
    "slack": "Slack",
    "heroku": "Heroku",
    "sentry": "Sentry",
    "firebase": "Firebase",
    "anthropic": "Anthropic",
    "westernunion": "WesternUnion",
    "wu": "WU",
}

_GENERIC_BASES = frozenset(
    {
        "Generic API Key",
        "Hardcoded Password",
        "Hardcoded Client Secret",
        "Hardcoded Secret",
        "Named Credential",
        "Activation / License Key",
        "Credential",
    }
)

# Widen so sibling keys / provider fields are visible
_CONTEXT_BEFORE = 280
_CONTEXT_AFTER = 160


@dataclass(frozen=True)
class OrgContext:
    """Custom organization names/aliases for classifying org-specific secrets."""

    display_name: str = ""
    aliases: frozenset[str] = field(default_factory=frozenset)

    def __bool__(self) -> bool:
        return bool(self.display_name and self.aliases)


def _norm_alias(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _aliases_for_label(label: str) -> set[str]:
    """Build match tokens for an org label (Western Union → westernunion, wu, …)."""
    raw = (label or "").strip()
    if not raw:
        return set()
    out: set[str] = set()
    compact = _norm_alias(raw)
    if compact:
        out.add(compact)
    parts = re.split(r"[\s_\-.]+", raw)
    parts = [p for p in parts if p]
    if len(parts) >= 2:
        out.add(_norm_alias("_".join(parts)))
        initials = "".join(p[0] for p in parts if p)
        if len(initials) >= 2:
            out.add(initials.lower())
    # single-token hyphenated host pieces already covered by compact
    return {a for a in out if len(a) >= 2}


def org_from_host(host: str) -> Tuple[str, set[str]]:
    """Derive a display name + aliases from a hostname (e.g. api.westernunion.com)."""
    host = (host or "").lower().split("@")[-1].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or host in _GENERIC_TLDS:
        return "", set()
    labels = [p for p in host.split(".") if p]
    if not labels:
        return "", set()
    # example.co.uk / example.com.au → second-level before country multi-part suffix
    if (
        len(labels) >= 3
        and labels[-1] in _GENERIC_TLDS
        and labels[-2] in {"co", "com", "net", "org", "ac", "gov"}
    ):
        sld = labels[-3]
    elif len(labels) >= 2 and labels[-1] in _GENERIC_TLDS:
        sld = labels[-2]
    else:
        sld = labels[0]
    if not sld or sld in _GENERIC_TLDS or len(sld) < 2:
        return "", set()
    aliases = _aliases_for_label(sld)
    if "-" in sld:
        display = " ".join(p[:1].upper() + p[1:].lower() for p in sld.split("-") if p)
    elif sld.lower() in _BRAND_TITLES:
        display = _BRAND_TITLES[sld.lower()]
    else:
        display = sld[:1].upper() + sld[1:]
    return display, aliases


def build_org_context(
    *,
    hints: str = "",
    urls: Optional[Sequence[str]] = None,
) -> OrgContext:
    """Build org context from optional hints + scan/page URLs.

    hints: comma-separated display names / aliases
           e.g. \"Western Union, WU, westernunion, wucom\"
    First hint with a space (or the first hint) becomes the display name.
    Domain-derived aliases are always merged in.
    """
    display = ""
    aliases: set[str] = set()

    for part in re.split(r"[,;|/]+", hints or ""):
        token = part.strip()
        if not token:
            continue
        if not display:
            display = token
        elif " " in token and " " not in display:
            # Prefer a multi-word human name as display when listed later
            display = token
        aliases |= _aliases_for_label(token)
        # Keep spaced form as match against company: "Western Union"
        aliases.add(_norm_alias(token))

    for url in urls or ():
        try:
            host = urlparse(url).netloc or urlparse(url).path
        except Exception:
            host = ""
        dname, dals = org_from_host(host)
        aliases |= dals
        if dname and not display:
            display = dname
        elif dname:
            # Domain label is also an alias for the hinted display name
            aliases |= _aliases_for_label(dname)

    aliases = {a for a in aliases if len(a) >= 2}
    if not display or not aliases:
        return OrgContext()
    return OrgContext(display_name=display, aliases=frozenset(aliases))


def match_org_in_text(text: str, org: Optional[OrgContext]) -> str:
    """Return org display name if any alias appears as a token/substring in text."""
    if not org or not text:
        return ""
    compact = _norm_alias(text)
    parts = {p.lower() for p in _split_ident(text)}
    # Longer aliases first so westernunion beats wu when both match
    for alias in sorted(org.aliases, key=len, reverse=True):
        if alias in parts or (len(alias) >= 3 and alias in compact):
            return org.display_name
    return ""


def apply_org_product(product: str, org: Optional[OrgContext], *extra_texts: str) -> str:
    """Upgrade a product stem to the custom org display name when aliases match."""
    if not org:
        return product
    for text in (product, *extra_texts):
        hit = match_org_in_text(text or "", org)
        if hit:
            return hit
    return product


def _split_ident(ident: str) -> list[str]:
    text = (ident or "").replace(".", "_").replace("-", "_")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    return [p for p in text.split("_") if p]


def _title_product(parts: list[str]) -> str:
    if not parts:
        return ""
    out = []
    for p in parts:
        key = p.lower()
        if key in _BRAND_TITLES:
            out.append(_BRAND_TITLES[key])
        elif p.isupper() and 2 <= len(p) <= 3:
            out.append(p.upper())
        elif key in ("id", "ids"):
            out.append("ID")
        else:
            out.append(p[:1].upper() + p[1:].lower())
    return " ".join(out)


def parse_ident_kind(ident: str) -> Tuple[str, str]:
    """Return (product, kind) from an identifier like paypal_api_key or config.paypal.apiKey."""
    # Dotted path: keep the most specific trailing segments
    if "." in (ident or ""):
        parts = [p for p in ident.split(".") if p]
        # Prefer last 2–3 segments: paypal.apiKey / stripe.secret_key
        ident = "_".join(parts[-3:]) if len(parts) >= 2 else (parts[-1] if parts else ident)

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
        product_parts = [
            p for p in product_joined.split("_") if p and p.lower() not in _STOP_PRODUCTS
        ]
        return _title_product(product_parts), kind
    filtered = [p for p in parts if p.lower() not in _STOP_PRODUCTS]
    return _title_product(filtered), ""


def _value_matches(secret: str, candidate: str) -> bool:
    if not secret or not candidate:
        return False
    if candidate == secret or secret == candidate:
        return True
    n = min(16, len(secret), len(candidate))
    if n < 6:
        return secret == candidate
    return secret.startswith(candidate[:n]) or candidate.startswith(secret[:n])


def find_assignment_ident(
    body_text: str,
    start: int,
    end: int,
    value: str,
) -> str:
    """Find the variable/property this secret is assigned to."""
    window_start = max(0, start - _CONTEXT_BEFORE)
    window = body_text[window_start : min(len(body_text), end + _CONTEXT_AFTER)]
    val = (value or "").strip()
    best: Tuple[int, str] = (-1, "")

    for m in _IDENT_ASSIGN_RE.finditer(window):
        cand = m.group("value") or ""
        if not _value_matches(val, cand):
            continue
        ident = m.group("path") or m.group("ident") or m.group("qident") or ""
        if not ident:
            continue
        abs_pos = window_start + m.start()
        distance = abs(abs_pos - start)
        score = 10_000 - distance
        if score > best[0]:
            best = (score, ident)
    return best[1]


def collect_related_idents(window: str, *, exclude: Sequence[str] = ()) -> List[str]:
    """Harvest nearby identifier names that may describe the product/service."""
    exclude_l = {e.lower() for e in exclude if e}
    found: List[str] = []
    seen = set()
    for m in _IDENT_TOKEN_RE.finditer(window or ""):
        ident = m.group("ident") or ""
        low = ident.lower()
        if low in seen or low in exclude_l:
            continue
        if low in _STOP_PRODUCTS or low in _KIND_STOP:
            continue
        if len(ident) < 2 or ident.isdigit():
            continue
        seen.add(low)
        found.append(ident)
    return found


def infer_product_from_related(
    window: str,
    related: Iterable[str],
    org: Optional[OrgContext] = None,
) -> str:
    """Infer product name from provider/org literals and related variable stems."""
    for m in _PROVIDER_ASSIGN_RE.finditer(window or ""):
        name = (m.group("name") or "").strip()
        org_hit = match_org_in_text(name, org)
        if org_hit:
            return org_hit
        # Multi-word company names: "Western Union", "Acme Corp"
        if " " in name:
            return " ".join(p[:1].upper() + p[1:].lower() for p in name.split() if p)
        product, _ = parse_ident_kind(name.replace(" ", "_"))
        if product:
            return apply_org_product(product, org, name)
        titled = _title_product(_split_ident(name))
        if titled:
            return apply_org_product(titled, org, name)

    for ident in related:
        org_hit = match_org_in_text(ident, org)
        if org_hit:
            return org_hit
        parts = _split_ident(ident)
        for p in parts:
            key = p.lower()
            if key in _BRAND_TITLES:
                return apply_org_product(_BRAND_TITLES[key], org, ident)
        product, kind = parse_ident_kind(ident)
        if product and kind:
            return apply_org_product(product, org, ident)
        if product and product.lower() not in {x.lower() for x in _KIND_STOP}:
            if product.lower() not in {"key", "token", "password", "credential"}:
                return apply_org_product(product, org, ident)

    # Org alias anywhere in the window (comment, string, sibling)
    org_hit = match_org_in_text(window, org)
    if org_hit:
        return org_hit
    return ""


def _kind_from_base_label(base_label: str) -> str:
    low = (base_label or "").lower()
    for _, kind in _KIND_PATTERNS:
        if kind.lower() in low:
            return kind
    if "password" in low:
        return "Password"
    if "token" in low:
        return "Token"
    if "secret" in low:
        return "Secret"
    if "key" in low:
        return "API Key"
    return ""


def extract_value_fallback(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    m = re.search(r"[:=]\s*['\"]?([^\s'\"]{6,})", text)
    return m.group(1) if m else text


def classify_credential(
    *,
    base_label: str,
    raw: str,
    body_text: str,
    start: int,
    end: int,
    value: str = "",
    org_context: Optional[OrgContext] = None,
) -> str:
    """Build a human label from assignment + related variables + org context."""
    window_start = max(0, start - _CONTEXT_BEFORE)
    window = body_text[window_start : min(len(body_text), end + _CONTEXT_AFTER)]
    val = (value or "").strip() or extract_value_fallback(raw)

    assign_ident = find_assignment_ident(body_text, start, end, val)
    product, kind = parse_ident_kind(assign_ident) if assign_ident else ("", "")
    if product:
        product = apply_org_product(product, org_context, assign_ident)

    related = collect_related_idents(window, exclude=[assign_ident] if assign_ident else [])
    if not product:
        product = infer_product_from_related(window, related, org_context)
    elif not kind:
        for ident in related:
            _, rel_kind = parse_ident_kind(ident)
            if rel_kind:
                kind = rel_kind
                break

    if not kind:
        kind = _kind_from_base_label(base_label)

    # Password + nearby user/id → ID and Password
    if (kind == "Password" or "password" in (base_label or "").lower()) and _USER_NEAR_RE.search(
        window
    ):
        if product:
            return f"{product} ID and Password"
        rel_product = infer_product_from_related(window, related, org_context)
        if rel_product:
            return f"{rel_product} ID and Password"
        if org_context and org_context.display_name:
            return f"{org_context.display_name} ID and Password"
        return "ID and Password"

    if product and kind:
        return f"{product} {kind}"
    if kind and not product:
        # Bare api_key / secret with org signal in window → Org API Key
        org_hit = match_org_in_text(window, org_context) or match_org_in_text(
            assign_ident, org_context
        )
        if org_hit:
            return f"{org_hit} {kind if kind != 'Key' else 'API Key'}"
        return kind if kind != "Key" else (base_label or "API Key")
    if product and not kind:
        if base_label and base_label not in _GENERIC_BASES:
            return base_label
        return f"{product} Credential"

    return base_label or "Credential"


def assignment_note(body_text: str, start: int, end: int, value: str) -> str:
    """Short note for finding detail: which variable held the secret."""
    ident = find_assignment_ident(body_text, start, end, value)
    if not ident:
        return ""
    return f" (assigned to `{ident}`)"


def severity_for_kind(label: str, default: str = "high") -> str:
    low = (label or "").lower()
    if any(x in low for x in ("password", "private key", "secret access", "client secret", "auth token")):
        return "critical" if "publishable" not in low else "medium"
    if "publishable" in low or "client id" in low:
        return "medium"
    return default
