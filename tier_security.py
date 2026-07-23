"""Tier 2–6 security probes: OAuth/SSO, JWT, GraphQL extras, mass assignment,
hidden params, rate limits, cloud misconfig, JS intel, WebSocket, upload polish.

Findings use verification gating via finding_proof (severity rises only after verify).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, parse_qsl, quote, urljoin, urlparse

from finding_proof import FindingProof, gate_severity, proof_from_http

Finding = Tuple  # (category, severity, detail, evidence[, meta_dict])


def _meta(
    verification: str,
    proposed_severity: str,
    *,
    proof: Optional[FindingProof] = None,
    confidence: str = "",
    confidence_reason: str = "",
) -> Dict[str, Any]:
    """Optional 5th tuple element for emit/record_finding."""
    out: Dict[str, Any] = {
        "verification": (verification or "detected").lower(),
        "confidence": confidence,
        "confidence_reason": confidence_reason,
    }
    if proof is not None:
        out["proof"] = proof.as_dict()
    return out

_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"
)
_OAUTH_PATH_RE = re.compile(
    r"(?i)/(?:oauth|oidc|authorize|auth/realms|sso|saml|connect/authorize)(?:/|$|\?)"
)
_HIDDEN_PARAM_RE = re.compile(
    r"""(?i)['"`](isAdmin|is_admin|debug|role|internal|staff|isStaff|is_staff|admin)['"`]\s*:"""
)
# Strong privilege/debug names only — bare "enabled" is ubiquitous UI noise.
_HIDDEN_PARAM_NAMES = (
    "isAdmin",
    "is_admin",
    "debug",
    "role",
    "internal",
    "staff",
    "isStaff",
    "is_staff",
    "admin",
)
# Require a host-like shape with an env token as a DNS label (not substring of "device").
_ENV_HINT_RE = re.compile(
    r"""['"`](
        (?:https?://)?
        (?:[a-z0-9\-]+\.)*
        (?:staging|stg|dev|internal|admin|test|beta|qa|uat)
        (?:[.\-][a-z0-9.\-]+)+
        (?:/[^\s'"`]*)?
    )['"`]""",
    re.I | re.X,
)
_ENV_NOISE_RE = re.compile(
    r"(?i)\b(?:device|devices|developer|development|devtools?|test(?:ing)?id|testdata)\b"
)
_WS_RE = re.compile(r"""['"`](wss?://[^'"`\s]{8,200})['"`]""")
_GRAPHQL_ADMIN_RE = re.compile(
    r"(?i)\b(mutation\s+\w*(admin|deleteUser|createAdmin|drop|resetPassword)|"
    r"(adminCreate|deleteAll|grantRole|setRole)\s*[({])"
)
_AMOUNT_RE = re.compile(r"(?i)[\"'](?:amount|price|total|cost|quantity|qty)[\"']\s*:")
_AUTH_PATH_RE = re.compile(
    r"(?i)/(?:login|signin|sign-up|signup|register|otp|verify|password(?:-|_ )?reset|"
    r"forgot|coupon|redeem|auth)(?:/|$|\?)"
)
_S3_RE = re.compile(
    r"(?i)https?://([a-z0-9.\-]+)\.s3[.\-]([a-z0-9\-]+)\.amazonaws\.com(/[^\s\"']*)?"
    r"|https?://s3[.\-]([a-z0-9\-]+)\.amazonaws\.com/([a-z0-9.\-_]+)"
)
_AZURE_BLOB_RE = re.compile(
    r"(?i)https?://([a-z0-9.\-]+)\.blob\.core\.windows\.net(/[^\s\"']*)?"
)
_GCP_BUCKET_RE = re.compile(
    r"(?i)https?://storage\.googleapis\.com/([a-z0-9.\-_]+)|"
    r"https?://([a-z0-9.\-_]+)\.storage\.googleapis\.com"
)
_LAMBDA_URL_RE = re.compile(r"(?i)https?://[a-z0-9.\-]+\.lambda-url\.[a-z0-9\-]+\.on\.aws[^\s\"']*")
_CLOUDFRONT_RE = re.compile(r"(?i)https?://[a-z0-9]+\.cloudfront\.net[^\s\"']*")
_SWAGGER_PATHS = (
    "/swagger",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/openapi.json",
    "/api-docs",
    "/v3/api-docs",
)


def _ev(value: str, *, label: str = "matched") -> str:
    text = re.sub(r"\s+", " ", (value or "").strip())
    if len(text) > 220:
        text = text[:200] + "…"
    return f"{label}: `{text}`"


def _b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def _jwt_parts(token: str) -> Optional[Tuple[dict, dict, str]]:
    try:
        bits = token.split(".")
        if len(bits) < 2:
            return None
        header = json.loads(_b64url_decode(bits[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(bits[1]).decode("utf-8", errors="replace"))
        sig = bits[2] if len(bits) > 2 else ""
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        return header, payload, sig
    except Exception:
        return None


# --- OAuth / SSO -------------------------------------------------------------

def scan_oauth_sso(url: str, body_text: str = "") -> List[Finding]:
    """Passive OAuth/SSO misconfig signals (state, redirect_uri, token in URL)."""
    findings: List[Finding] = []
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    params = parse_qs(parsed.query)
    oauthish = bool(_OAUTH_PATH_RE.search(path)) or any(
        k.lower() in ("client_id", "redirect_uri", "response_type", "scope") for k in params
    )
    token_in_query = any(
        re.search(r"(?i)^(access_token|id_token|refresh_token|token)$", k) for k in params
    )
    if (
        not oauthish
        and not token_in_query
        and not re.search(r"(?i)(oauth|openid|saml|oidc|okta|azure)", body_text or "")
    ):
        return findings

    # Token leakage in URL
    for name, values in params.items():
        if re.search(r"(?i)^(access_token|id_token|refresh_token|token)$", name):
            val = (values[0] if values else "")[:40]
            findings.append(
                (
                    "oauth",
                    gate_severity("high", verification="confirmed"),
                    f"OAuth/token parameter '{name}' appears in URL query (token leakage)",
                    _ev(f"{name}={val}…", label="oauth_token_leak"),
                    _meta("confirmed", "high", confidence="high", confidence_reason="Token material in URL query"),
                )
            )

    if oauthish:
        has_state = any(k.lower() == "state" for k in params)
        has_redirect = any(k.lower() == "redirect_uri" for k in params)
        if "response_type" in {k.lower() for k in params} or "client_id" in {
            k.lower() for k in params
        }:
            if not has_state:
                findings.append(
                    (
                        "oauth",
                        gate_severity("medium", verification="verified"),
                        "OAuth authorize flow missing state parameter (CSRF/session fixation risk)",
                        _ev(url.split("?", 1)[0] + "?" + parsed.query[:160], label="oauth_no_state"),
                        _meta("verified", "medium", confidence="medium", confidence_reason="Authorize URL lacks state"),
                    )
                )
        if has_redirect:
            redir = (params.get("redirect_uri") or params.get("redirect_url") or [""])[0]
            host = (parsed.netloc or "").lower()
            rhost = urlparse(redir).netloc.lower() if redir.startswith("http") else ""
            if rhost and rhost != host and not rhost.endswith("." + host):
                # Off-site redirect_uri — verified signal, exploitability needs confirm
                findings.append(
                    (
                        "oauth",
                        gate_severity("medium", verification="verified"),
                        f"OAuth redirect_uri points off-site to {rhost} — verify allow-list",
                        _ev(redir, label="oauth_redirect_uri"),
                        _meta("verified", "medium", confidence="medium", confidence_reason="Off-site redirect_uri in authorize URL"),
                    )
                )

    # Provider fingerprints in body
    providers = []
    blob = (body_text or "")[:8000] + " " + url
    for label, pat in (
        ("Google Login", r"(?i)accounts\.google\.com|googleapis\.com/oauth"),
        ("Azure AD", r"(?i)login\.microsoftonline\.com|graph\.microsoft\.com"),
        ("Okta", r"(?i)\.okta\.com|oktacdn"),
        ("OIDC", r"(?i)openid-configuration|openid"),
        ("SAML", r"(?i)SAMLRequest|saml2|/sso/saml"),
    ):
        if re.search(pat, blob):
            providers.append(label)
    if providers and oauthish:
        findings.append(
            (
                "oauth",
                "info",
                f"SSO/OAuth providers referenced: {', '.join(list(dict.fromkeys(providers))[:5])}",
                _ev(", ".join(providers[:5]), label="sso_providers"),
            )
        )
    return findings


# --- JWT ---------------------------------------------------------------------

def scan_jwt_flaws(url: str, body_text: str, headers: Optional[dict] = None) -> List[Finding]:
    findings: List[Finding] = []
    texts = [body_text or ""]
    if headers:
        for k, v in headers.items():
            if re.search(r"(?i)authorization|cookie|set-cookie|x-auth", k):
                texts.append(str(v))
    seen = set()
    for text in texts:
        for m in _JWT_RE.finditer(text[:120000]):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            parts = _jwt_parts(token)
            if not parts:
                continue
            header, payload, sig = parts
            alg = str(header.get("alg") or "")
            # none algorithm
            if alg.lower() == "none" or (alg == "" and not sig):
                findings.append(
                    (
                        "jwt",
                        gate_severity("high", verification="confirmed"),
                        "JWT uses alg=none or empty signature — signature bypass risk",
                        _ev(f"alg={alg or '(empty)'} token={token[:48]}…", label="jwt_none"),
                        _meta("confirmed", "high", confidence="high", confidence_reason="JWT header alg=none / empty sig"),
                    )
                )
            # alg confusion hint (public apps shipping RS256 JWTs in JS with kid)
            if alg.upper() in ("HS256", "HS384", "HS512") and len(sig) < 20:
                findings.append(
                    (
                        "jwt",
                        "low",
                        f"JWT alg={alg} with unusually short signature — weak-secret candidate",
                        _ev(f"alg={alg} sig_len={len(sig)}", label="jwt_weak_sig"),
                    )
                )
            # expired tokens are inventory/info — not a demonstrated vulnerability
            exp = payload.get("exp")
            if isinstance(exp, (int, float)):
                import time

                if exp < time.time() - 60:
                    findings.append(
                        (
                            "jwt",
                            "info",
                            "Expired JWT still present in response/headers — inventory only; verify server rejects it",
                            _ev(f"exp={exp}", label="jwt_expired"),
                            _meta(
                                "detected",
                                "info",
                                confidence="low",
                                confidence_reason="exp claim is in the past — not proof of acceptance",
                            ),
                        )
                    )
            if "aud" not in payload and "iss" not in payload:
                findings.append(
                    (
                        "jwt",
                        "info",
                        "JWT missing aud/iss claims — weaker validation surface",
                        _ev(json.dumps({k: header.get(k) for k in ("alg", "typ")}), label="jwt_claims"),
                    )
                )
            if len(findings) >= 8:
                return findings
    return findings


# --- GraphQL extras ----------------------------------------------------------

def scan_graphql_intel(url: str, body_text: str) -> List[Finding]:
    findings: List[Finding] = []
    path = (urlparse(url).path or "").lower()
    if not re.search(r"(?i)graphql|graphiql", path + " " + (body_text or "")[:2000]):
        return findings
    if _GRAPHQL_ADMIN_RE.search(body_text or ""):
        m = _GRAPHQL_ADMIN_RE.search(body_text or "")
        findings.append(
            (
                "graphql",
                gate_severity("medium", verification="verified"),
                "GraphQL admin/destructive operation names referenced in client bundle",
                _ev(m.group(0)[:120] if m else "admin mutation", label="graphql_admin_op"),
            )
        )
    # Hidden operations: fields that look internal
    for m in re.finditer(
        r"""(?i)(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*(?:internal|admin|debug|hidden)\w*)""",
        body_text or "",
    ):
        findings.append(
            (
                "graphql",
                "low",
                f"GraphQL operation name suggests hidden/internal API: {m.group(1)}",
                _ev(m.group(1), label="graphql_hidden_op"),
            )
        )
        break
    return findings


async def probe_graphql_schema(client, url: str) -> List[Finding]:
    """Active introspection — confirmed when __schema returns."""
    path = urlparse(url).path or ""
    if not re.search(r"(?i)graphql", path):
        return []
    query = {"query": "{ __schema { queryType { name } mutationType { name } types { name } } }"}
    try:
        resp = await client.post(url, json=query, timeout=12, follow_redirects=True)
        body = resp.text or ""
        if resp.status_code < 500 and re.search(r'(?i)"__schema"\s*:', body):
            # Downgrade: introspection alone is an API-surface observation unless
            # privileged admin mutations / private customer fields are proven.
            adminish = bool(
                re.search(
                    r"(?i)(mutationType|Admin|DeleteUser|customerAccessTokenCreate|"
                    r"privateMetafield|staffMember)",
                    body[:12000],
                )
            )
            # Storefront GraphQL with only queryType is informational
            storefrontish = bool(re.search(r"(?i)storefront|Shop\b|Product\b", body[:8000]))
            if adminish and not storefrontish:
                sev = gate_severity("medium", verification="confirmed")
                impact = "Schema discloses privileged operation names — review auth on mutations"
            else:
                sev = "info"
                impact = "Informational technology/API-surface observation — no private data or auth bypass proven"
            return [
                (
                    "graphql",
                    sev,
                    f"GraphQL introspection confirmed (__schema) at {url}",
                    _ev(body[:200], label="graphql_schema"),
                    _meta(
                        "confirmed",
                        sev,
                        proof=proof_from_http(
                            method="POST",
                            url=url,
                            status=resp.status_code,
                            body_snippet=body[:200],
                            evidence="Introspection __schema returned",
                            impact=impact,
                        ),
                        confidence="high" if adminish else "medium",
                        confidence_reason="Live introspection response contains __schema",
                    ),
                )
            ]
    except Exception:
        return []
    return []


# --- Mass assignment / hidden params ----------------------------------------

def scan_hidden_params_in_js(url: str, body_text: str) -> List[Finding]:
    """Flag strong privilege/debug param names in JS — never weak UI flags like ``enabled``."""
    findings: List[Finding] = []
    if not body_text:
        return findings
    found = sorted({m.group(1) for m in _HIDDEN_PARAM_RE.finditer(body_text[:200000])})
    if not found:
        for name in _HIDDEN_PARAM_NAMES:
            if re.search(
                rf"""['"`]{re.escape(name)}['"`]\s*:""",
                body_text[:200000],
                re.I,
            ):
                found.append(name)
        found = sorted(set(found))
    # Drop ubiquitous non-privilege flags if any slip through
    found = [n for n in found if n.lower() not in {"enabled", "disabled", "visible", "active"}]
    if found:
        findings.append(
            (
                "mass_assignment",
                "info",
                "Privilege/debug parameter names referenced in client code: " + ", ".join(found[:8]),
                _ev(", ".join(found[:8]), label="hidden_params"),
            )
        )
    return findings


async def probe_mass_assignment(client, url: str, *, max_tries: int = 3) -> List[Finding]:
    """POST JSON privilege fields on API-ish endpoints — confirm only with structured impact."""
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    if not re.search(r"(?i)/(?:api|v\d+|user|users|account|profile|auth)/", path):
        return []
    # Skip obvious HTML document routes
    if re.search(r"(?i)\.(?:html?|aspx?|jsp|php)(?:$|\?)", path):
        return []
    if parsed.query:
        target = url.split("?", 1)[0]
    else:
        target = url
    payloads = (
        {"role": "admin"},
        {"isAdmin": True},
        {"admin": True, "role": "admin"},
    )
    findings: List[Finding] = []
    for payload in payloads[:max_tries]:
        try:
            resp = await client.post(
                target,
                json=payload,
                timeout=10,
                follow_redirects=False,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        except Exception:
            continue
        body = resp.text or ""
        status = int(getattr(resp, "status_code", 0) or 0)
        if status >= 400 or status < 200:
            continue
        # Redirects / HTML app shells are not API mass-assignment proof
        if 300 <= status < 400:
            continue
        ctype = str(
            (getattr(resp, "headers", {}) or {}).get("content-type")
            or (getattr(resp, "headers", {}) or {}).get("Content-Type")
            or ""
        ).lower()
        body_l = body.lstrip().lower()
        if "text/html" in ctype or body_l.startswith("<!doctype") or body_l.startswith("<html"):
            continue
        if "json" not in ctype and not (body_l.startswith("{") or body_l.startswith("[")):
            continue
        try:
            parsed_json = json.loads(body)
        except Exception:
            continue
        if not isinstance(parsed_json, (dict, list)):
            continue

        def _field_present(obj, key, expected) -> bool:
            if isinstance(obj, dict):
                if key in obj and obj.get(key) == expected:
                    return True
                return any(_field_present(v, key, expected) for v in obj.values())
            if isinstance(obj, list):
                return any(_field_present(v, key, expected) for v in obj)
            return False

        persisted = False
        for key, expected in payload.items():
            if _field_present(parsed_json, key, expected):
                persisted = True
                break
        if not persisted:
            continue
        findings.append(
            (
                "mass_assignment",
                gate_severity("high", verification="exploitable"),
                f"Mass-assignment probe: privilege field persisted in JSON response on {target} (HTTP {status})",
                _ev(json.dumps(payload) + " => " + body[:120], label="mass_assignment"),
                _meta(
                    "exploitable",
                    "high",
                    proof=proof_from_http(
                        method="POST",
                        url=target,
                        status=status,
                        body_snippet=body[:200],
                        evidence=json.dumps(payload),
                        impact="Client-controlled privilege fields accepted in structured JSON response",
                        request_extra=f"json={json.dumps(payload)}",
                    ),
                    confidence="high",
                    confidence_reason="Privilege JSON fields present in structured API response",
                ),
            )
        )
        break
    return findings


# --- Rate limit --------------------------------------------------------------

async def probe_rate_limit(client, url: str, *, bursts: int = 12) -> List[Finding]:
    """Burst auth-ish endpoints; flag when no 429/challenge across rapid repeats.

    Redirect-only bursts (all 301/302) do not prove missing rate limiting — the
    auth handler / WAF counter may never have been reached.
    """
    if not _AUTH_PATH_RE.search(urlparse(url).path or ""):
        return []
    statuses = []
    for _ in range(bursts):
        try:
            resp = await client.get(url, timeout=6, follow_redirects=False)
            statuses.append(int(getattr(resp, "status_code", 0) or 0))
        except Exception:
            break
    if len(statuses) < max(6, bursts // 2):
        return []
    # Pure redirect chains never exercised the protected auth workflow
    if statuses and all(300 <= s < 400 for s in statuses):
        return []
    limited = any(s in (429, 503) for s in statuses) or len(set(statuses)) > 3
    if limited:
        return []
    # Require some non-redirect responses that actually hit an endpoint
    reached = [s for s in statuses if s < 300 or s >= 400]
    if len(reached) < max(4, bursts // 3):
        return []
    return [
        (
            "rate_limit",
            "info",
            f"Authentication surface candidate requiring rate-limit assessment "
            f"({len(statuses)} rapid requests, no 429/lockout; statuses={statuses[:8]})",
            _ev(f"statuses={statuses[:12]}", label="rate_limit"),
            _meta(
                "detected",
                "info",
                confidence="low",
                confidence_reason="Auth-path burst without 429 — candidate only, not a confirmed missing control",
            ),
        )
    ]


# --- Business logic hints (opportunistic) ------------------------------------

def scan_business_logic_hints(url: str, body_text: str) -> List[Finding]:
    findings: List[Finding] = []
    path = (urlparse(url).path or "").lower()
    blob = (body_text or "")[:50000]
    if _AMOUNT_RE.search(blob) and re.search(r"(?i)/(?:cart|checkout|order|payment|pay|transfer)/", path + blob[:2000]):
        findings.append(
            (
                "business_logic",
                "info",
                "Client references amount/price/quantity fields on commerce path — candidate for price/qty manipulation tests",
                _ev(path or "/", label="biz_amount_fields"),
            )
        )
    if re.search(r"(?i)coupon|promo[_-]?code|voucher|discount", blob) and re.search(
        r"(?i)/(?:coupon|redeem|checkout|cart)/", path + " " + blob[:1500]
    ):
        findings.append(
            (
                "business_logic",
                "info",
                "Coupon/redeem flow referenced — test reuse/stack/expired coupon abuse",
                _ev("coupon/redeem", label="biz_coupon"),
            )
        )
    if re.search(r"(?i)(transfer|recipient|send[_-]?money)", blob) and re.search(
        r"(?i)/(?:transfer|wallet|send(?:-|_ )?money|payout|wire|remit)/",
        path,
    ):
        findings.append(
            (
                "business_logic",
                "info",
                "Money-transfer style flow referenced — test recipient change / limit bypass / duplicate transfer",
                _ev("transfer/recipient", label="biz_transfer"),
            )
        )
    return findings


async def probe_price_manipulation(client, url: str) -> List[Finding]:
    """If URL looks like cart/checkout API, try amount=1 vs amount=100 reflection."""
    path = (urlparse(url).path or "").lower()
    if not re.search(r"(?i)/(?:cart|checkout|order|payment|api/.*/order)", path):
        return []
    findings: List[Finding] = []
    for payload in ({"amount": 1}, {"price": 1}, {"total": 1}, {"quantity": -1}):
        try:
            resp = await client.post(
                url.split("?", 1)[0],
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            continue
        body = (resp.text or "").lower()
        status = int(getattr(resp, "status_code", 0) or 0)
        if status >= 400:
            continue
        key = next(iter(payload))
        val = payload[key]
        if re.search(rf'"{key}"\s*:\s*{val}\b', body) or f"{key}:{val}" in body.replace(" ", ""):
            findings.append(
                (
                    "business_logic",
                    gate_severity("high", verification="exploitable"),
                    f"Price/quantity manipulation probe accepted {key}={val} on {urlparse(url).path}",
                    _ev(json.dumps(payload) + " => " + (resp.text or "")[:120], label="price_manip"),
                    _meta(
                        "exploitable",
                        "high",
                        proof=proof_from_http(
                            method="POST",
                            url=url.split("?", 1)[0],
                            status=status,
                            body_snippet=(resp.text or "")[:200],
                            evidence=json.dumps(payload),
                            impact="Server reflected attacker-controlled price/quantity",
                            request_extra=f"json={json.dumps(payload)}",
                        ),
                        confidence="high",
                        confidence_reason="Mutated amount/qty reflected on commerce path",
                    ),
                )
            )
            break
    return findings


# --- Cloud misconfig ---------------------------------------------------------

async def probe_cloud_urls(client, body_text: str, page_url: str) -> List[Finding]:
    findings: List[Finding] = []
    text = body_text or ""
    urls = set()
    for rx in (_S3_RE, _AZURE_BLOB_RE, _GCP_BUCKET_RE, _LAMBDA_URL_RE, _CLOUDFRONT_RE):
        for m in rx.finditer(text[:200000]):
            urls.add(m.group(0).rstrip(").,;'\"}"))
    # firebase/azure already mined elsewhere; still check storage.googleapis listing
    checked = 0
    for u in list(urls)[:8]:
        checked += 1
        try:
            resp = await client.get(u, timeout=10, follow_redirects=True)
        except Exception:
            continue
        status = int(getattr(resp, "status_code", 0) or 0)
        body = resp.text or ""
        ctype = (resp.headers.get("content-type") or "").lower()
        low = body[:4000].lower()
        denied = any(
            x in low
            for x in ("accessdenied", "access denied", "unauthorized", "forbidden", "bloberrorcode")
        )
        list_markers = (
            "ListBucketResult" in body
            or "EnumerationResults" in body
            or "<ListBucketResult" in body
            or ("<blobs>" in low and "blob.core.windows.net" in u)
        )
        if status == 200 and list_markers and not denied:
            findings.append(
                (
                    "cloud",
                    gate_severity("high", verification="confirmed"),
                    f"Cloud storage appears publicly listable: {u}",
                    _ev(f"HTTP {status} {body[:160]}", label="cloud_public"),
                    _meta(
                        "confirmed",
                        "high",
                        proof=proof_from_http(
                            method="GET",
                            url=u,
                            status=status,
                            body_snippet=body[:200],
                            evidence=f"Public listing markers at {u}",
                            impact="Anonymous read/list of cloud objects",
                        ),
                        confidence="high",
                        confidence_reason="Listing XML/JSON returned without auth",
                    ),
                )
            )
        elif status == 200 and not denied and "amazonaws.com" in u and "xml" in ctype:
            findings.append(
                (
                    "cloud",
                    gate_severity("medium", verification="verified"),
                    f"AWS/S3-style URL returns 200 XML without auth: {u}",
                    _ev(f"HTTP {status}", label="cloud_s3"),
                    _meta("verified", "medium", confidence="medium", confidence_reason="Unauthenticated 200 XML from S3-style URL"),
                )
            )
        elif status == 200 and not denied and "blob.core.windows.net" in u:
            findings.append(
                (
                    "cloud",
                    gate_severity("medium", verification="verified"),
                    f"Azure blob URL accessible without auth challenge: {u}",
                    _ev(f"HTTP {status}", label="cloud_azure"),
                    _meta("verified", "medium", confidence="medium", confidence_reason="Unauthenticated Azure blob response"),
                )
            )
        elif status == 200 and not denied and "lambda-url" in u:
            findings.append(
                (
                    "cloud",
                    gate_severity("medium", verification="verified"),
                    f"Lambda Function URL responds publicly: {u}",
                    _ev(f"HTTP {status}", label="cloud_lambda"),
                    _meta("verified", "medium", confidence="medium", confidence_reason="Public Lambda Function URL response"),
                )
            )
        elif status == 200 and not denied and "storage.googleapis.com" in u and (
            '"items"' in low or "listbucketresult" in low
        ):
            findings.append(
                (
                    "cloud",
                    gate_severity("high", verification="confirmed"),
                    f"GCP storage appears publicly listable: {u}",
                    _ev(f"HTTP {status} {body[:160]}", label="cloud_gcp"),
                    _meta("confirmed", "high", confidence="high", confidence_reason="GCS listing markers without auth"),
                )
            )
    # Inventory cloudfront mentions as infrastructure observation (not a misconfig by default)
    if _CLOUDFRONT_RE.search(text) and not any("cloudfront" in f[2].lower() for f in findings):
        m = _CLOUDFRONT_RE.search(text)
        findings.append(
            (
                "cloud",
                "info",
                "Cloud/CDN dependency observed (CloudFront) — security status not assessed",
                _ev(m.group(0)[:160] if m else "cloudfront", label="cloudfront"),
                _meta(
                    "detected",
                    "info",
                    confidence="low",
                    confidence_reason="Intentional third-party CDN reference; not a proven misconfiguration",
                ),
            )
        )
    return findings


# --- JS frontend intelligence ------------------------------------------------

def _collect_env_host_candidates(body_text: str, *, limit: int = 6) -> List[str]:
    """Host-like staging/dev/internal strings — excludes device/CSS false positives."""
    text = body_text or ""
    out: List[str] = []
    for m in _ENV_HINT_RE.finditer(text[:250000]):
        val = (m.group(1) or "").strip()
        if not val or _ENV_NOISE_RE.search(val):
            continue
        low = val.lower()
        # Must look like a host/URL, not a CSS/media token
        if "://" not in low and "." not in low.split("/", 1)[0]:
            continue
        if low not in {x.lower() for x in out}:
            out.append(val)
        if len(out) >= limit:
            break
    return out


def scan_js_frontend_intel(url: str, body_text: str) -> List[Finding]:
    """Frontend recon — intentionally sparse.

    Bare ``fetch()`` / ``axios`` / ``graphql`` string hits are every SPA and are
    not findings. Env/internal hosts are handled by ``probe_js_env_hosts``.
    Feature-flag SDK mentions alone are not reported (recon inventory only).
    """
    return []


async def probe_js_env_hosts(client, url: str, body_text: str, *, max_hosts: int = 3) -> List[Finding]:
    """GET referenced env/internal hosts; 401/403/400 means referenced-but-denied, not exposed."""
    findings: List[Finding] = []
    candidates = _collect_env_host_candidates(body_text or "", limit=max_hosts)
    if not candidates:
        return findings
    probed: List[str] = []
    denied: List[str] = []
    open_ok: List[str] = []
    for raw in candidates:
        target = raw.strip()
        if not target.lower().startswith(("http://", "https://")):
            target = "https://" + target.lstrip("/")
        try:
            parsed = urlparse(target)
            if not parsed.netloc or "." not in parsed.netloc:
                continue
            # Only probe the origin root — avoid hammering deep paths from minified JS
            origin = f"{parsed.scheme}://{parsed.netloc}/"
            resp = await client.get(origin, timeout=8, follow_redirects=True)
            code = int(getattr(resp, "status_code", 0) or 0)
            probed.append(f"{parsed.netloc}→{code}")
            if code in (400, 401, 403, 404):
                denied.append(f"{parsed.netloc} (HTTP {code})")
            elif 200 <= code < 400:
                open_ok.append(f"{parsed.netloc} (HTTP {code})")
        except Exception:
            denied.append(f"{urlparse(target).netloc or target} (unreachable)")
        if len(probed) >= max_hosts:
            break
    if not probed:
        return findings
    if open_ok and not denied:
        findings.append(
            (
                "js_intel",
                gate_severity("low", verification="verified"),
                "Non-prod/internal hosts referenced in bundle and reachable anonymously: "
                + ", ".join(open_ok[:5]),
                _ev(", ".join(open_ok[:5]), label="js_env_leak"),
                _meta(
                    "verified",
                    "low",
                    confidence="medium",
                    confidence_reason="anonymous GET succeeded",
                ),
            )
        )
    elif open_ok and denied:
        findings.append(
            (
                "js_intel",
                "info",
                "Non-prod/internal hosts in bundle — some reachable, some denied: "
                + ", ".join((open_ok + denied)[:6]),
                _ev(", ".join((open_ok + denied)[:6]), label="js_env_leak"),
                _meta("verified", "info", confidence="medium", confidence_reason="mixed probe results"),
            )
        )
    else:
        findings.append(
            (
                "js_intel",
                "info",
                "Non-prod/internal hosts referenced in bundle but access denied to anonymous scanners: "
                + ", ".join(denied[:5]),
                _ev(", ".join(denied[:5]), label="js_env_leak"),
                _meta(
                    "verified",
                    "info",
                    confidence="high",
                    confidence_reason="probe returned 401/403/400/unreachable",
                ),
            )
        )
    return findings


def scan_websocket_intel(url: str, body_text: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _WS_RE.finditer(body_text or ""):
        ws = m.group(1)
        sev = "medium" if ws.startswith("ws://") else "info"
        findings.append(
            (
                "websocket",
                gate_severity(sev, verification="verified" if ws.startswith("ws://") else "detected"),
                f"WebSocket endpoint referenced ({'cleartext' if ws.startswith('ws://') else 'TLS'}): {ws}",
                _ev(ws, label="websocket"),
            )
        )
        if len(findings) >= 4:
            break
    return findings


# --- File upload polish ------------------------------------------------------

def scan_upload_risk_extended(forms: Optional[List[dict]], url: str) -> List[Finding]:
    findings: List[Finding] = []
    if not forms:
        return findings
    for form in forms:
        if not (form.get("has_file_input") or form.get("file_fields")):
            continue
        accepts = " ".join(form.get("file_accepts") or []).lower()
        action = form.get("action") or url
        risky = []
        if not accepts or "*" in accepts or "image/*" in accepts:
            risky.append("broad/missing accept")
        if any(x in accepts for x in ("svg", "html", "xml", "text/")):
            risky.append("svg/html/xml allowed")
        if "octet-stream" in accepts:
            risky.append("octet-stream allowed")
        if risky:
            findings.append(
                (
                    "file_upload",
                    gate_severity("medium", verification="verified"),
                    f"Upload form may allow dangerous types ({', '.join(risky)}) at {action}",
                    _ev(f"accept={accepts or '(none)'}", label="upload_accept"),
                )
            )
    return findings


# --- Swagger path presence in JS (passive) -----------------------------------

def scan_swagger_refs(url: str, body_text: str) -> List[Finding]:
    findings: List[Finding] = []
    text = body_text or ""
    hits = []
    for path in _SWAGGER_PATHS:
        if path in text or path.strip("/") in text:
            hits.append(path)
    if hits:
        findings.append(
            (
                "api_leak",
                "low",
                "Swagger/OpenAPI paths referenced in client assets: " + ", ".join(list(dict.fromkeys(hits))[:6]),
                _ev(", ".join(list(dict.fromkeys(hits))[:6]), label="swagger_ref"),
            )
        )
    return findings


# --- SSRF param expansion (passive candidates) -------------------------------

_SSRF_EXTRA = re.compile(
    r"(?i)^(url|uri|webhook|endpoint|callback|feed|link|src|target|proxy|fetch|dest)$"
)


def scan_ssrf_param_candidates(url: str) -> List[Finding]:
    findings: List[Finding] = []
    params = parse_qs(urlparse(url).query)
    hits = [n for n in params if _SSRF_EXTRA.match(n)]
    if not hits:
        return findings
    # Only emit if value looks URL-like (stronger than bare name)
    interesting = []
    for n in hits:
        for v in params.get(n) or []:
            if re.match(r"(?i)^(https?:|//)", v or ""):
                interesting.append(f"{n}={v[:80]}")
    if interesting:
        findings.append(
            (
                "ssrf",
                "info",
                "SSRF-prone parameter with URL value (candidate): " + ", ".join(interesting[:4]),
                _ev(", ".join(interesting[:4]), label="ssrf_candidate"),
            )
        )
    return findings



# --- Auth account surfaces (Tier 1 leftovers) ---------------------------------

def scan_auth_account_surfaces(url: str, body_text: str, forms: Optional[List[dict]] = None) -> List[Finding]:
    """Flag replay/OTP/email-change surfaces for targeted abuse testing.

    Keyword hits on FAQ/marketing pages are ignored — require auth-like path,
    password/OTP form fields, or JS route constants tied to auth flows.
    """
    findings: List[Finding] = []
    path = (urlparse(url).path or "").lower()
    # Skip marketing / help / legal pages that merely mention MFA
    if re.search(
        r"(?i)/(?:faq|help|support|terms|privacy|policy|about|blog|news|fraud|"
        r"awareness|learn|education|article)(?:/|$|\.)",
        path,
    ):
        return findings

    functional_path = bool(
        _AUTH_PATH_RE.search(path)
        or re.search(
            r"(?i)/(?:otp|mfa|2fa|verify|verification|login|signin|account|auth|"
            r"password|reset|register|signup)(?:/|$|\.)",
            path,
        )
    )
    form_fields = set()
    for form in forms or []:
        for f in form.get("fields") or []:
            form_fields.add(str(f).lower())
    has_otp_field = bool(
        form_fields
        & {
            "otp",
            "mfa",
            "2fa",
            "totp",
            "verification_code",
            "verificationcode",
            "one_time_password",
            "onetimepassword",
            "auth_code",
            "authcode",
        }
    )
    has_password_field = "password" in form_fields or "passwd" in form_fields
    blob = (body_text or "")[:80000]
    # Prefer form / path evidence over bare body keywords
    if has_otp_field or (
        functional_path
        and re.search(r"(?i)\b(otp|one[_-]?time|verification[_-]?code|2fa|mfa)\b", blob + path)
    ):
        findings.append(
            (
                "authentication",
                "info",
                "OTP/MFA surface detected — test rate limits and brute-force resistance",
                _ev("otp/mfa", label="auth_otp_surface"),
                _meta(
                    "detected",
                    "info",
                    confidence="medium" if has_otp_field or functional_path else "low",
                    confidence_reason="Auth path/form references OTP/MFA (not FAQ keyword-only)",
                ),
            )
        )
    if (
        functional_path
        or has_password_field
        or re.search(r"(?i)/(?:account|profile|settings)/", path)
    ) and re.search(r"(?i)(change[_-]?email|update[_-]?email|email[_-]?change)", blob + path):
        findings.append(
            (
                "authentication",
                "info",
                "Email-change flow referenced — verify password/reauth required (ATO path)",
                _ev("change-email", label="auth_email_change"),
                _meta("detected", "info", confidence="low", confidence_reason="Email-change wording on auth-like surface"),
            )
        )
    if re.search(r"(?i)(refresh[_-]?token|token[_-]?reuse|revoke)", blob) and (
        _AUTH_PATH_RE.search(path) or re.search(r"(?i)/(?:oauth|token|session)/", path)
    ):
        findings.append(
            (
                "authentication",
                "info",
                "Token lifecycle endpoints referenced — test replay after logout/revoke",
                _ev("token lifecycle", label="auth_token_reuse"),
                _meta("detected", "info", confidence="low", confidence_reason="Token revoke/reuse wording present"),
            )
        )
    # Form: passwordless email change
    for form in forms or []:
        fields = {str(f).lower() for f in (form.get("fields") or [])}
        if "email" in fields and "password" not in fields and re.search(
            r"(?i)email|account|profile|settings", form.get("action") or url
        ):
            findings.append(
                (
                    "authentication",
                    gate_severity("medium", verification="verified"),
                    "Account email field form without password field — possible passwordless email change",
                    _ev(form.get("action") or url, label="auth_email_no_password"),
                    _meta(
                        "verified",
                        "medium",
                        confidence="medium",
                        confidence_reason="Email form lacks password/reauth field in HTML",
                    ),
                )
            )
            break
    return findings


def scan_sso_lookfors(url: str, body_text: str) -> List[Finding]:
    """When SSO is present, remind high-value look-fors (bypass, role confusion, assertion reuse)."""
    blob = (body_text or "")[:12000] + " " + url
    if not re.search(r"(?i)(saml|oidc|openid|okta|microsoftonline|accounts\.google)", blob):
        return []
    return [
        (
            "oauth",
            "info",
            "SSO present — prioritize checks: authentication bypass, role confusion, assertion reuse",
            _ev("sso look-fors", label="sso_lookfors"),
            _meta("detected", "info", confidence="low", confidence_reason="SSO provider fingerprint only"),
        )
    ]


# --- Race conditions (limited parallel burst) --------------------------------

async def probe_race_conditions(client, url: str, *, parallelism: int = 10) -> List[Finding]:
    """Fire parallel requests at redeem/pay/transfer paths; flag identical success bodies.

    Static HTML shells (terms pages, marketing .html) are never race candidates.
    """
    import asyncio

    path = (urlparse(url).path or "").lower()
    if re.search(r"(?i)\.(?:html?|css|js|mjs)(?:$|\?)", path):
        return []
    if re.search(r"(?i)terms|conditions|policy|privacy|about|help|faq", path):
        return []
    if not re.search(r"(?i)/(?:coupon|redeem|checkout|pay|payment|transfer|wallet)/", path):
        return []
    # Prefer API-ish handlers over document routes
    if not re.search(r"(?i)/(?:api|v\d+|action|submit|graphql)/", path) and path.endswith("/"):
        pass
    target = url.split("?", 1)[0]

    async def _one():
        try:
            resp = await client.post(
                target,
                json={"amount": 1, "coupon": "TEST", "quantity": 1},
                timeout=8,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                follow_redirects=False,
            )
            ctype = str(
                (getattr(resp, "headers", {}) or {}).get("content-type")
                or (getattr(resp, "headers", {}) or {}).get("Content-Type")
                or ""
            ).lower()
            return int(getattr(resp, "status_code", 0) or 0), (resp.text or "")[:240], ctype
        except Exception:
            return 0, "", ""

    results = await asyncio.gather(*[_one() for _ in range(max(5, min(parallelism, 20)))])
    ok = []
    for s, b, ctype in results:
        if not (200 <= s < 300 and b):
            continue
        bl = b.lstrip().lower()
        if "text/html" in ctype or bl.startswith("<!doctype") or bl.startswith("<html"):
            continue
        if "json" not in ctype and not (bl.startswith("{") or bl.startswith("[")):
            continue
        ok.append((s, b))
    if len(ok) < 5:
        return []
    bodies = [b for _, b in ok]
    if len(set(bodies)) == 1 and not re.search(
        r"(?i)(already|used|limit|insufficient|error|invalid)", bodies[0]
    ):
        return [
            (
                "business_logic",
                gate_severity("medium", verification="verified"),
                f"Race burst: {len(ok)} parallel POSTs returned identical JSON success bodies on {path}",
                _ev(f"n={len(ok)} status={ok[0][0]} body={bodies[0][:100]}", label="race_identical"),
                _meta(
                    "verified",
                    "medium",
                    confidence="medium",
                    confidence_reason="Identical mutating JSON responses under parallel burst",
                ),
            )
        ]
    return []


# --- Orchestrator entrypoints ------------------------------------------------

def run_tier_passive(
    url: str,
    body_text: str,
    forms: Optional[List[dict]],
    headers: Optional[dict] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(scan_oauth_sso(url, body_text))
    findings.extend(scan_sso_lookfors(url, body_text))
    findings.extend(scan_jwt_flaws(url, body_text, headers))
    findings.extend(scan_graphql_intel(url, body_text))
    findings.extend(scan_hidden_params_in_js(url, body_text))
    findings.extend(scan_business_logic_hints(url, body_text))
    findings.extend(scan_auth_account_surfaces(url, body_text, forms))
    findings.extend(scan_js_frontend_intel(url, body_text))
    findings.extend(scan_websocket_intel(url, body_text))
    findings.extend(scan_upload_risk_extended(forms, url))
    findings.extend(scan_swagger_refs(url, body_text))
    findings.extend(scan_ssrf_param_candidates(url))
    return findings


async def run_tier_active(client, url: str, body_text: str = "") -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(await probe_graphql_schema(client, url))
    findings.extend(await probe_mass_assignment(client, url))
    findings.extend(await probe_rate_limit(client, url))
    findings.extend(await probe_price_manipulation(client, url))
    findings.extend(await probe_race_conditions(client, url, parallelism=10))
    findings.extend(await probe_cloud_urls(client, body_text or "", url))
    findings.extend(await probe_js_env_hosts(client, url, body_text or ""))
    return findings
