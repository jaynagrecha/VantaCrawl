"""Plain-language explanations for security findings (awareness + patch guidance)."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# Keys matched against category and/or detail text (lowercase substring)
EXPLAINERS: List[Tuple[tuple, Dict[str, str]]] = [
    (
        ("missing hsts", "strict-transport-security"),
        {
            "title": "Missing HSTS (HTTPS enforcement)",
            "what": (
                "The site does not tell browsers “always use HTTPS for this domain.” "
                "On HTTPS-only hosts (e.g. Vercel) this is usually informational hardening."
            ),
            "attacker": (
                "Relevant mainly when an HTTP access path is demonstrably exploitable "
                "(SSL-stripping on first visit). Many bounty programs mark bare missing HSTS as Informational."
            ),
            "fix": (
                "Serve the site over HTTPS and add a Strict-Transport-Security header "
                "(for example max-age=31536000; includeSubDomains) after confirming HTTPS works everywhere."
            ),
        },
    ),
    (
        ("missing csp", "content-security-policy"),
        {
            "title": "Missing Content Security Policy (CSP)",
            "what": (
                "There is no policy telling the browser which scripts, styles, and frames are allowed. "
                "Without demonstrated XSS this is a hardening gap, not a standalone vulnerability."
            ),
            "attacker": (
                "CSP mainly limits damage after script injection exists. Alone, missing CSP does not "
                "give an attacker a new entry point."
            ),
            "fix": (
                "Add a Content-Security-Policy header starting in report-only mode, then tighten "
                "script-src and related directives for your real assets. Escalate priority if XSS is found."
            ),
        },
    ),
    (
        ("x-frame-options", "clickjacking"),
        {
            "title": "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
            "what": (
                "Pages can be embedded in a frame on another site. Without a PoC against a sensitive "
                "authenticated action, this is hardening — not a Medium vulnerability by itself."
            ),
            "attacker": (
                "Interesting only when a page is frameable and a sensitive action (delete account, "
                "place order, change password) can be clickjacked."
            ),
            "fix": (
                "Send X-Frame-Options: DENY (or SAMEORIGIN), or preferably "
                "Content-Security-Policy: frame-ancestors 'none' (or your trusted parents only)."
            ),
        },
    ),
    (
        ("x-content-type-options",),
        {
            "title": "Missing X-Content-Type-Options",
            "what": (
                "Browsers may “guess” a file’s type. A file uploaded as an image could be treated as HTML/JS."
            ),
            "attacker": (
                "They upload or host a file that looks harmless but is executed as a script because "
                "the browser sniffs the content type."
            ),
            "fix": "Add header X-Content-Type-Options: nosniff on all responses.",
        },
    ),
    (
        ("referrer-policy",),
        {
            "title": "Missing Referrer-Policy",
            "what": "Browsers may send the full previous URL to other sites when users click links.",
            "attacker": (
                "Sensitive query strings (tokens, IDs) in your URLs can leak to third-party analytics, "
                "ads, or attacker-controlled sites via the Referer header."
            ),
            "fix": "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        },
    ),
    (
        ("permissions-policy",),
        {
            "title": "Missing Permissions-Policy",
            "what": "The page does not restrict powerful browser features (camera, mic, geolocation, etc.).",
            "attacker": (
                "Injected or third-party scripts have an easier time requesting powerful device APIs "
                "if your policy never locked them down."
            ),
            "fix": "Add a Permissions-Policy that disables features you do not need.",
        },
    ),
    (
        ("sql_injection", "sqli", "sql error"),
        {
            "title": "Possible SQL injection",
            "what": (
                "Input may be reaching the database in an unsafe way. Error messages or probe behavior "
                "looked like a database was interpreting attacker-controlled text as SQL."
            ),
            "attacker": (
                "They craft values in URLs or forms to read, change, or delete database rows — "
                "including accounts, passwords hashes, or private content — without logging in."
            ),
            "fix": (
                "Use parameterized queries / prepared statements everywhere. Never build SQL with string "
                "concatenation. Hide detailed DB errors from users."
            ),
        },
    ),
    (
        ("xss", "cross-site scripting", "reflected"),
        {
            "title": "Possible cross-site scripting (XSS)",
            "what": "User-controlled text may be echoed into HTML without safe encoding.",
            "attacker": (
                "They send a victim a link (or post content) that runs their JavaScript in your site’s "
                "origin — stealing session cookies, rewriting the page, or performing actions as the user."
            ),
            "fix": (
                "Encode output for HTML/JS context, validate input, and use a strict CSP. Prefer frameworks "
                "that auto-escape templates."
            ),
        },
    ),
    (
        ("ssrf",),
        {
            "title": "Possible server-side request forgery (SSRF)",
            "what": "The server may fetch URLs or hosts supplied by the user.",
            "attacker": (
                "They make your server call internal services (cloud metadata, admin panels, databases) "
                "that are not exposed to the internet, and read the responses."
            ),
            "fix": (
                "Do not fetch arbitrary user URLs. Allow-list destinations, block link-local/metadata IPs, "
                "and use a dedicated egress proxy with deny-by-default."
            ),
        },
    ),
    (
        ("path_traversal", "traversal", "directory traversal"),
        {
            "title": "Possible path traversal",
            "what": "Parameters look like they can point at files outside the intended folder (../ sequences).",
            "attacker": (
                "They request ../../etc/passwd-style paths (or Windows equivalents) to read config files, "
                "keys, or other users’ data from disk."
            ),
            "fix": (
                "Never join user input directly to filesystem paths. Use allow-listed IDs and resolve paths "
                "under a fixed root, rejecting anything that escapes it."
            ),
        },
    ),
    (
        ("rce", "remote code", "command injection"),
        {
            "title": "Possible remote code / command injection",
            "what": "Input may reach a shell or dangerous evaluator on the server.",
            "attacker": (
                "They run operating-system commands on your server — install malware, steal data, "
                "or pivot into your network."
            ),
            "fix": (
                "Never pass user input to system shells. Use safe APIs/libraries; drop privileges; "
                "sandbox where execution is unavoidable."
            ),
        },
    ),
    (
        ("secrets_exposure", "api key", "secret", "password in"),
        {
            "title": "Possible secret or API key exposure",
            "what": "Something that looks like a credential, token, or private key appeared in a page or response.",
            "attacker": (
                "They copy the key and use your cloud, payment, email, or admin APIs as if they were you — "
                "often from anywhere on the internet."
            ),
            "fix": (
                "Revoke and rotate the exposed secret immediately. Remove it from code/pages; use env vars "
                "or a secrets manager; scan git history."
            ),
        },
    ),
    (
        ("sensitive_path", "sensitive path", ".env", "backup"),
        {
            "title": "Sensitive path or file pattern",
            "what": (
                "A URL looks like a backup, config, admin, or environment file that should not be public."
            ),
            "attacker": (
                "They download backups, .env files, or admin panels to get passwords, database dumps, "
                "or a foothold into the application."
            ),
            "fix": (
                "Block these paths at the web server/WAF, remove files from the web root, and require "
                "strong auth (and MFA) for any real admin interfaces."
            ),
        },
    ),
    (
        ("cors",),
        {
            "title": "CORS misconfiguration",
            "what": "Cross-Origin Resource Sharing rules may be too open (e.g. reflecting any Origin with credentials).",
            "attacker": (
                "A malicious website you visit can call your APIs with your cookies and read the responses, "
                "stealing data while you are logged in."
            ),
            "fix": (
                "Allow only trusted origins. Never combine Access-Control-Allow-Origin: * with credentials. "
                "Prefer an explicit allow-list."
            ),
        },
    ),
    (
        ("auth", "authentication", "password field", "login"),
        {
            "title": "Authentication / login surface",
            "what": (
                "A login or password form was found. That is not automatically a bug — but it is a high-value "
                "target that must be hardened."
            ),
            "attacker": (
                "They try password spraying, credential stuffing, phishing pages that mimic this form, "
                "or bugs in the login flow to take over accounts."
            ),
            "fix": (
                "Enforce HTTPS, rate-limit logins, use MFA, lockouts, and secure session cookies "
                "(Secure, HttpOnly, SameSite). Monitor failed logins."
            ),
        },
    ),
    (
        ("stealable_credential", "missing httponly", "cookie `", "session/auth credential"),
        {
            "title": "Stealable session / auth cookie",
            "what": (
                "A response cookie looks like a session or auth credential and is missing protective flags "
                "(HttpOnly and/or Secure). That means it can be stolen more easily than a hardened session cookie."
            ),
            "attacker": (
                "With XSS, malware, or a network path that exposes the cookie, they replay it and act as the user "
                "without knowing the password."
            ),
            "fix": (
                "Set HttpOnly, Secure, and SameSite on session cookies; prefer short-lived tokens; "
                "rotate on privilege change; avoid putting JWTs in JS-readable cookies."
            ),
        },
    ),
    (
        ("mitigated_credential", "protective flags", "no practical js cookie-theft"),
        {
            "title": "Session cookie present (mitigated)",
            "what": (
                "A session/auth cookie was observed with protective flags. JavaScript cookie theft is largely "
                "blocked; this is informational, not a confirmed exploitable issue."
            ),
            "attacker": (
                "They would need non-JS paths (malware, physical access, or coercing the browser to send the cookie)."
            ),
            "fix": "Keep HttpOnly+Secure+SameSite; continue monitoring for XSS that can still trigger authenticated requests.",
        },
    ),
    (
        ("no_credential_impact", "analytics cookie", "not a login/session credential", "csrf/anti-forgery"),
        {
            "title": "Cookie without credential impact",
            "what": (
                "The cookie is analytics, preference, or CSRF-related — not a reusable login credential on its own."
            ),
            "attacker": "Stealing it alone does not grant account access (CSRF tokens need a live session too).",
            "fix": "No urgent change for credential theft; keep normal cookie hygiene.",
        },
    ),
    (
        ("api_leak", "information disclosure", "stack trace"),
        {
            "title": "Information disclosure",
            "what": "The response reveals internal details (stack traces, debug data, verbose API errors).",
            "attacker": (
                "They use those details to map your stack, find exact vulnerable components, and craft "
                "a more precise exploit."
            ),
            "fix": "Turn off debug mode in production; return generic errors to clients; log details server-side only.",
        },
    ),
    (
        ("open_redirect",),
        {
            "title": "Possible open redirect",
            "what": "A parameter may send users to an attacker-chosen website after they trust your domain.",
            "attacker": (
                "They craft links like yours.com/login?next=evil.com so victims think they are staying "
                "on your site, then steal credentials on the fake page."
            ),
            "fix": "Only allow relative redirects or an allow-list of destinations.",
        },
    ),
    (
        ("mixed_content",),
        {
            "title": "Mixed content",
            "what": "An HTTPS page loads scripts or assets over plain HTTP.",
            "attacker": (
                "On the same network they can tamper with those HTTP resources and inject malicious "
                "JavaScript into an otherwise secure page."
            ),
            "fix": "Serve every asset over HTTPS; use Content-Security-Policy upgrade-insecure-requests.",
        },
    ),
    (
        ("http_methods", "trace", "options"),
        {
            "title": "HTTP method surface",
            "what": "The server advertises or accepts uncommon HTTP methods (OPTIONS/TRACE/etc.).",
            "attacker": (
                "TRACE can help with cross-site tracing; unexpected methods sometimes bypass front-end rules."
            ),
            "fix": "Disable TRACE/TRACK; restrict Allow to the methods your app needs.",
        },
    ),
    (
        ("well_known",),
        {
            "title": "Well-known endpoint",
            "what": "A /.well-known/ resource responded with evidence it is a real endpoint.",
            "attacker": (
                "They use OAuth/OIDC metadata, app-links, or password-change endpoints to map auth flows "
                "and client apps."
            ),
            "fix": "Expose only required well-known resources; keep metadata minimal in production.",
        },
    ),
    (
        ("cloud_url", "firebase", "supabase", "azure"),
        {
            "title": "Cloud service URL exposure",
            "what": "Page or script content references Firebase, Supabase, Azure, or similar cloud endpoints.",
            "attacker": (
                "They probe those backends for open rules, leaked keys, or misconfigured storage."
            ),
            "fix": "Restrict public rules, rotate exposed keys, and avoid shipping privileged endpoints in JS.",
        },
    ),
    (
        ("file_metadata", "gps", "exif", "author"),
        {
            "title": "Embedded file metadata",
            "what": "A downloaded or crawled file embeds author, company, software, or GPS metadata.",
            "attacker": (
                "They harvest internal usernames, org names, tooling versions, or physical locations "
                "from PDFs, Office docs, and images."
            ),
            "fix": "Strip metadata before publishing; disable GPS on work photos; use document sanitization.",
        },
    ),
    (
        ("outdated server", "x-powered-by", "server banner"),
        {
            "title": "Server technology disclosure",
            "what": "The server advertises software names/versions that help fingerprint your stack.",
            "attacker": (
                "They look up known CVEs for that exact version and aim exploits instead of guessing blindly."
            ),
            "fix": "Remove or genericize Server / X-Powered-By headers; keep software patched.",
        },
    ),
    (
        ("csrf", "cross-site request forgery"),
        {
            "title": "Cross-Site Request Forgery (CSRF) risk",
            "what": (
                "A state-changing form may be submittable from another site because no CSRF token "
                "was found. Severity rises when a session cookie is also present."
            ),
            "attacker": (
                "They lure a logged-in user to a malicious page that auto-submits your form "
                "(change email, place order, delete account)."
            ),
            "fix": (
                "Add anti-CSRF tokens (Synchronizer Token / double-submit cookie), prefer SameSite=Lax/Strict "
                "session cookies, and require re-auth for sensitive actions."
            ),
        },
    ),
    (
        ("idor", "insecure direct object"),
        {
            "title": "Insecure Direct Object Reference (IDOR)",
            "what": (
                "Object identifiers in requests may allow accessing another user’s records if "
                "authorization is missing. Active confirmation requires divergent responses for swapped IDs."
            ),
            "attacker": (
                "They change id/user_id/order_id in API calls to read or modify other tenants’ data."
            ),
            "fix": (
                "Enforce server-side authorization on every object access; use opaque IDs; never trust "
                "client-supplied ownership."
            ),
        },
    ),
    (
        ("oauth", "redirect_uri", "missing state", "token leakage", "sso"),
        {
            "title": "OAuth / SSO misconfiguration",
            "what": (
                "The OAuth/OIDC/SAML flow shows a weakness (missing state, off-site redirect_uri, "
                "token in URL, or related SSO risk)."
            ),
            "attacker": (
                "They complete or hijack the login flow, steal tokens from URLs/logs, or link accounts "
                "incorrectly to take over a session."
            ),
            "fix": (
                "Require and validate state/nonce; strict redirect_uri allow-lists; never put tokens in "
                "query strings; validate SAML/OIDC assertions (audience, recipient, replay)."
            ),
        },
    ),
    (
        ("jwt", "alg=none", "alg confusion"),
        {
            "title": "JWT validation flaw",
            "what": (
                "A JSON Web Token uses a dangerous algorithm, weak signature, expired acceptance, or "
                "missing audience/issuer checks."
            ),
            "attacker": (
                "They forge or reuse tokens to impersonate users when the server does not verify "
                "algorithm, signature, exp, aud, or iss correctly."
            ),
            "fix": (
                "Deny alg=none; pin expected algorithms; validate exp/nbf/aud/iss; use strong secrets "
                "or asymmetric keys; reject tokens after logout/revoke."
            ),
        },
    ),
    (
        ("graphql", "__schema", "introspection"),
        {
            "title": "GraphQL exposure",
            "what": (
                "GraphQL introspection or sensitive operation names are exposed, revealing the API surface."
            ),
            "attacker": (
                "They map the full schema, then target admin mutations or hidden fields that lack "
                "authorization checks."
            ),
            "fix": (
                "Disable introspection in production; enforce field-level auth; remove unused mutations; "
                "rate-limit GraphQL."
            ),
        },
    ),
    (
        ("mass_assignment", "hidden_params", "isadmin"),
        {
            "title": "Mass assignment / hidden parameters",
            "what": (
                "Privilege or debug fields (role, isAdmin, debug) appear in clients or were accepted "
                "when injected into API bodies."
            ),
            "attacker": (
                "They add undeclared JSON fields to escalate privileges or enable debug modes."
            ),
            "fix": (
                "Use allow-listed DTOs; ignore unknown fields; never bind client input directly to "
                "role/admin flags."
            ),
        },
    ),
    (
        ("rate_limit", "without 429", "otp"),
        {
            "title": "Missing rate limiting",
            "what": (
                "An authentication-like endpoint accepted rapid repeated requests without lockout or 429."
            ),
            "attacker": (
                "They brute-force OTP/login/password-reset or abuse coupon redemption at scale."
            ),
            "fix": (
                "Add per-IP and per-account rate limits, progressive delays, and lockouts on auth and "
                "redemption endpoints."
            ),
        },
    ),
    (
        ("business_logic", "price", "coupon", "race"),
        {
            "title": "Business logic abuse",
            "what": (
                "Commerce or transfer flows may allow price/quantity manipulation, coupon abuse, "
                "payment-after-cancel, or race-driven double-spend."
            ),
            "attacker": (
                "They alter amounts, reuse coupons, race parallel checkouts, or change recipients "
                "to steal value."
            ),
            "fix": (
                "Recompute prices server-side; enforce coupon single-use; idempotency keys on pay/transfer; "
                "lock order totals after checkout."
            ),
        },
    ),
    (
        ("cloud", "s3", "blob", "lambda-url", "cloudfront"),
        {
            "title": "Cloud misconfiguration",
            "what": (
                "A cloud storage or function URL appears publicly readable/listable or exposed from the app."
            ),
            "attacker": (
                "They list or download private objects, or invoke misconfigured serverless URLs."
            ),
            "fix": (
                "Block anonymous list/read; tighten IAM/ACLs; keep Function URLs private or authenticated."
            ),
        },
    ),
    (
        ("js_intel", "feature flag", "staging", "fetch()"),
        {
            "title": "Frontend intelligence (JS mining)",
            "what": (
                "Client bundles expose network helpers, routes, feature flags, or non-prod host strings."
            ),
            "attacker": (
                "They mine JS for hidden APIs, admin paths, and staging hosts as attack entry points."
            ),
            "fix": (
                "Strip secrets and internal hosts from production bundles; gate admin routes server-side."
            ),
        },
    ),
    (
        ("bot_management", "bot manager", "akamai bot", "_abck", "bm_sz", "unchallenged"),
        {
            "title": "Bot management / Akamai Bot Manager posture",
            "what": (
                "Akamai Bot Manager cookies or deny fingerprints were seen, and/or a large share of "
                "scanner requests completed without a challenge signal while BM appears deployed."
            ),
            "attacker": (
                "Automated clients that are not challenged can scrape, enumerate, or probe APIs at "
                "scale. This finding highlights a coverage gap for owners — it is not a cookie-forge exploit."
            ),
            "fix": (
                "On the Akamai / network edge: review bot category scores, challenge actions for "
                "automation, JA4/TLS anomaly rules, and require stronger controls on login/API/checkout. "
                "Tune allow-lists so real browsers pass while non-interactive clients are challenged."
            ),
        },
    ),
    (
        ("websocket", "wss://", "ws://"),
        {
            "title": "WebSocket security signal",
            "what": "A WebSocket endpoint is referenced from the client (cleartext WS is higher risk).",
            "attacker": (
                "They connect without auth or replay object IDs over the socket (IDOR over WebSocket)."
            ),
            "fix": (
                "Prefer wss://; authenticate the handshake; authorize every message; reject cross-user IDs."
            ),
        },
    ),
]


def explain_finding(category: str = "", detail: str = "") -> Dict[str, str]:
    cat = (category or "").lower().strip()
    detail_l = (detail or "").lower()
    # Prefer exact category matches first (avoids "login" substring hijacking unrelated findings)
    category_aliases = {
        "sql_injection": ("sql_injection", "sqli", "sql error"),
        "xss": ("xss", "cross-site"),
        "rce": ("rce", "command injection", "remote code"),
        "ssrf": ("ssrf",),
        "directory_traversal": ("directory_traversal", "traversal"),
        "secrets_exposure": ("secrets_exposure", "api key", "secret"),
        "sensitive_path": ("sensitive_path",),
        "cors": ("cors",),
        "header_audit": ("missing hsts", "missing csp", "x-frame", "x-content-type", "referrer-policy", "permissions-policy"),
        "api_leak": ("api_leak", "information disclosure"),
        "authentication": ("authentication",),
        "open_redirect": ("open_redirect",),
        "file_upload": ("file_upload",),
        "form_probe": ("form",),
        "mixed_content": ("mixed_content",),
        "http_methods": ("http_methods", "trace", "options"),
        "csrf": ("csrf", "cross-site request"),
        "idor": ("idor", "insecure direct object"),
        "well_known": ("well_known",),
        "cloud_url": ("cloud_url", "firebase", "supabase", "azure"),
        "cloud": ("cloud", "s3", "blob", "lambda-url", "cloudfront"),
        "file_metadata": ("file_metadata", "gps", "exif", "author"),
        "oauth": ("oauth", "redirect_uri", "missing state", "token leakage", "sso"),
        "jwt": ("jwt", "alg=none", "alg confusion"),
        "graphql": ("graphql", "__schema", "introspection"),
        "mass_assignment": ("mass_assignment", "hidden_params", "isadmin"),
        "rate_limit": ("rate_limit", "without 429", "otp"),
        "business_logic": ("business_logic", "price", "coupon", "race"),
        "js_intel": ("js_intel", "feature flag", "staging", "fetch()"),
        "websocket": ("websocket", "wss://", "ws://"),
        "bot_management": ("bot_management", "bot manager", "_abck", "bm_sz", "unchallenged"),
    }

    def _secret_type_from_detail(text: str) -> str:
        """Pull 'VirusTotal API Key' from 'Exposed VirusTotal API Key in response body'."""
        raw = (text or "").strip()
        if not raw:
            return ""
        m = re.search(r"(?i)^exposed\s+(.+?)\s+in\s+response\b", raw)
        if m:
            return m.group(1).strip()
        if ":" in raw and not raw.lower().startswith("missing "):
            head = raw.split(":", 1)[0].strip()
            if 3 <= len(head) <= 80:
                return head
        return ""

    preferred = category_aliases.get(cat)
    if preferred:
        # Cookie impact findings share category=authentication — match on detail first.
        if cat == "authentication":
            cookie_detail_keys = (
                "stealable_credential",
                "mitigated_credential",
                "no_credential_impact",
                "possible_credential",
                "missing httponly",
                "session/auth cookie",
                "session/auth credential",
                "analytics cookie",
                "csrf/anti-forgery",
                "not a login/session credential",
                "no practical js cookie-theft",
            )
            if any(k in detail_l for k in cookie_detail_keys):
                for keys, payload in EXPLAINERS:
                    if any(k in detail_l for k in keys if len(k) >= 5):
                        if any(
                            x in keys
                            for x in (
                                "stealable_credential",
                                "mitigated_credential",
                                "no_credential_impact",
                                "missing httponly",
                            )
                        ):
                            return dict(payload)
        for keys, payload in EXPLAINERS:
            if cat == "header_audit":
                if any(k in detail_l for k in keys):
                    return dict(payload)
                continue
            if any(k in preferred or k == cat for k in keys):
                out = dict(payload)
                if cat == "secrets_exposure":
                    typed = _secret_type_from_detail(detail)
                    if typed:
                        out["title"] = f"Exposed {typed}"
                        out["what"] = (
                            f"A credential that looks like a {typed} appeared in a page or API response."
                        )
                return out
    for keys, payload in EXPLAINERS:
        # Prefer category token; avoid loose substring matches on short keys like "auth"
        if cat and any(k == cat for k in keys):
            return dict(payload)
        if any(len(k) >= 5 and k in detail_l for k in keys):
            return dict(payload)
    return {
        "title": (category or "Security finding").replace("_", " ").title(),
        "what": detail or "The scanner flagged this pattern as worth a human review.",
        "attacker": (
            "Depending on the issue, an attacker may use it as a foothold, to steal data, "
            "or to chain with other weaknesses. Treat unknown findings as “verify or dismiss with evidence.”"
        ),
        "fix": (
            "Confirm on an authorized system whether this is a real issue, then patch configuration "
            "or code accordingly. Re-scan after fixing."
        ),
    }


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower() or url
    except Exception:
        return url


def group_findings_for_report(findings: List[Dict[str, Any]], *, max_groups: int = 40) -> List[Dict[str, Any]]:
    """Collapse duplicate header/path noise into explained issue groups."""
    from finding_kind import apply_hardening_context

    buckets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for item in findings:
        category = item.get("category", "other")
        detail = item.get("detail", "")
        severity = item.get("severity", "info")
        evidence = (item.get("evidence") or "").strip()
        # Group header issues by detail only (same missing header everywhere)
        if category in ("header_audit",) or "missing " in detail.lower():
            key = (severity, category, detail.strip().lower())
            url_cap = 5
        elif category == "secrets_exposure" and evidence:
            # One group per secret fingerprint (ignore product-label drift)
            key = (severity, category, evidence.lower())
            url_cap = 80
        else:
            key = (severity, category, detail.strip().lower()[:160])
            url_cap = 80

        if key not in buckets:
            expl = explain_finding(category, detail)
            buckets[key] = {
                "severity": severity,
                "category": category,
                "detail": detail,
                "count": 0,
                "urls": [],
                "_url_seen": set(),
                "evidence": [],
                "_evidence_seen": set(),
                "hosts": set(),
                "title": expl["title"],
                "what": expl["what"],
                "attacker": expl["attacker"],
                "fix": expl["fix"],
                "impact": item.get("impact") or "",
                "validation": item.get("validation") or "",
                "impact_summary": item.get("impact_summary") or "",
                "role": item.get("role") or "",
                "verification": item.get("verification") or "",
                "proof": item.get("proof") if isinstance(item.get("proof"), dict) else {},
                "confidence": item.get("confidence") or "",
                "confidence_reason": item.get("confidence_reason") or "",
                "assessment_state": item.get("assessment_state") or "",
            }
        bucket = buckets[key]
        bucket["count"] += 1
        # Prefer a more specific secret title when merging label variants
        if category == "secrets_exposure" and detail:
            cur = (bucket.get("detail") or "").lower()
            if any(g in cur for g in ("generic api key", "api key", "text api key", "named credential")):
                if detail.lower() not in cur and "exposed" in detail.lower():
                    bucket["detail"] = detail
                    expl = explain_finding(category, detail)
                    bucket["title"] = expl["title"]
                    bucket["what"] = expl["what"]
                    bucket["attacker"] = expl["attacker"]
                    bucket["fix"] = expl["fix"]
        # Prefer stronger impact labels when merging duplicates
        if item.get("impact") and (
            not bucket.get("impact")
            or str(item.get("impact")) in ("confirmed", "stealable_credential")
        ):
            bucket["impact"] = item.get("impact")
            bucket["validation"] = item.get("validation") or bucket.get("validation")
            bucket["impact_summary"] = item.get("impact_summary") or bucket.get("impact_summary")
            bucket["role"] = item.get("role") or bucket.get("role")
        # Prefer stronger verification / richer proof
        _ver_rank = {"detected": 0, "verified": 1, "exploitable": 2, "confirmed": 3}
        item_ver = str(item.get("verification") or "")
        if _ver_rank.get(item_ver, -1) > _ver_rank.get(str(bucket.get("verification") or ""), -1):
            bucket["verification"] = item_ver
        if isinstance(item.get("proof"), dict) and (
            not bucket.get("proof")
            or sum(1 for v in (item.get("proof") or {}).values() if v)
            > sum(1 for v in (bucket.get("proof") or {}).values() if v)
        ):
            bucket["proof"] = item.get("proof")
        if item.get("confidence") and not bucket.get("confidence"):
            bucket["confidence"] = item.get("confidence")
            bucket["confidence_reason"] = item.get("confidence_reason") or ""
        url = item.get("url", "")
        if url and url not in bucket["_url_seen"] and len(bucket["urls"]) < url_cap:
            bucket["_url_seen"].add(url)
            bucket["urls"].append(url)
        if url:
            bucket["hosts"].add(_host_of(url))
        if evidence and evidence not in bucket["_evidence_seen"] and len(bucket["evidence"]) < 20:
            bucket["_evidence_seen"].add(evidence)
            bucket["evidence"].append(evidence)

    groups = list(buckets.values())
    for g in groups:
        g["hosts"] = sorted(g["hosts"])
        g["unique_hosts"] = len(g["hosts"])
        g.pop("_url_seen", None)
        g.pop("_evidence_seen", None)

    groups = apply_hardening_context(groups)
    try:
        from report_status import assessment_state_for_finding

        for g in groups:
            if not g.get("assessment_state"):
                g["assessment_state"] = assessment_state_for_finding(
                    category=str(g.get("category") or ""),
                    severity=str(g.get("severity") or ""),
                    validation=str(g.get("validation") or ""),
                    impact=str(g.get("impact") or ""),
                    finding_kind=str(g.get("finding_kind") or ""),
                    verification=str(g.get("verification") or ""),
                    detail=str(g.get("detail") or ""),
                )
    except Exception:
        pass
    groups.sort(
        key=lambda g: (
            0 if g.get("finding_kind") == "vulnerability" else 1,
            order.get(g["severity"], 5),
            -g["count"],
            g["title"],
        )
    )
    return groups[:max_groups]


def format_finding_group_lines(group: Dict[str, Any], *, max_urls: int = 40) -> List[str]:
    """Client-facing lines: title, then exact paths, then accessible secret evidence."""
    impact = group.get("impact") or ""
    validation = group.get("validation") or ""
    assessment_state = group.get("assessment_state") or ""
    impact_bit = ""
    if impact:
        impact_bit = f" [{impact}" + (f"/{validation}" if validation else "") + "]"
    lines = [
        f"{group.get('title', 'Finding')} ({group.get('severity', 'info')}){impact_bit} — seen {group.get('count', 0)}×"
    ]
    if assessment_state:
        lines.append(f"  Assessment state: {assessment_state}")
    if group.get("impact_summary"):
        lines.append(f"  Impact: {group.get('impact_summary')}")
    urls = group.get("urls") or []
    if urls:
        for url in urls[:max_urls]:
            lines.append(f"  Path: {url}")
        if len(urls) > max_urls:
            lines.append(f"  Path: … and {len(urls) - max_urls} more URL(s)")
    else:
        lines.append("  Path: (not recorded)")
    evidence = group.get("evidence") or []
    if group.get("category") == "secrets_exposure":
        secret_type = ""
        title = str(group.get("title") or "")
        if title.lower().startswith("exposed "):
            secret_type = title[8:].strip()
        detail = str(group.get("detail") or "")
        if not secret_type and detail.lower().startswith("exposed "):
            secret_type = detail[8:].split(" in response", 1)[0].strip()
        if evidence:
            try:
                from security_scan import mask_secret_value
            except Exception:  # pragma: no cover
                mask_secret_value = lambda v: (v[:4] + "…" + v[-4:]) if len(v) > 10 else "***"  # noqa: E731
            if secret_type:
                lines.append(f"  Secret type: {secret_type}")
            for item in evidence[:10]:
                full = str(item)
                lines.append(f"  Secret (masked): {mask_secret_value(full)}")
                lines.append(f"  Secret (full): {full}")
        else:
            lines.append("  Secret: pattern matched but exact value was not captured")
    elif evidence:
        for item in evidence[:5]:
            lines.append(f"  Matched pattern: {item}")
    detail = (group.get("detail") or "").strip()
    if detail and detail.lower() not in (group.get("title") or "").lower():
        lines.append(f"  Detail: {detail}")
    return lines


def summarize_finding_noise(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No security findings were recorded."
    groups = group_findings_for_report(findings, max_groups=500)
    return (
        f"{len(findings)} raw finding row(s) collapse into {len(groups)} distinct issue type(s) "
        f"after removing repeats (for example the same missing header on every page)."
    )
