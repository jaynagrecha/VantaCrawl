"""Plain-language explanations for security findings (awareness + patch guidance)."""

from __future__ import annotations

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
                "Visitors can still be nudged onto an insecure HTTP connection."
            ),
            "attacker": (
                "On the same network (café Wi‑Fi, compromised router), an attacker can "
                "intercept the first visit or strip HTTPS (SSL-stripping) and see or change "
                "traffic before the user notices."
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
                "That makes XSS and injected scripts easier to run if any page is compromised."
            ),
            "attacker": (
                "If they find a place to inject HTML/JavaScript (comment field, reflected parameter), "
                "the browser has fewer rules blocking that script from stealing cookies or acting as the user."
            ),
            "fix": (
                "Add a Content-Security-Policy header starting in report-only mode, then tighten "
                "script-src and related directives for your real assets."
            ),
        },
    ),
    (
        ("x-frame-options", "clickjacking"),
        {
            "title": "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
            "what": (
                "Pages can be embedded in an invisible frame on another site. Users may click "
                "what they think is a harmless button while actually clicking yours."
            ),
            "attacker": (
                "They host a decoy page that overlays your real page in a transparent iframe and "
                "trick victims into approving actions (change email, enable 2FA off, buy something)."
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
        "well_known": ("well_known",),
        "cloud_url": ("cloud_url", "firebase", "supabase", "azure"),
        "file_metadata": ("file_metadata", "gps", "exif", "author"),
    }
    preferred = category_aliases.get(cat)
    if preferred:
        for keys, payload in EXPLAINERS:
            if cat == "header_audit":
                if any(k in detail_l for k in keys):
                    return dict(payload)
                continue
            if any(k in preferred or k == cat for k in keys):
                return dict(payload)
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
            # Keep separate groups per secret fingerprint so paths stay attached
            key = (severity, category, f"{detail.strip().lower()[:120]}|{evidence.lower()}")
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
            }
        bucket = buckets[key]
        bucket["count"] += 1
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

    groups.sort(key=lambda g: (order.get(g["severity"], 5), -g["count"], g["title"]))
    return groups[:max_groups]


def format_finding_group_lines(group: Dict[str, Any], *, max_urls: int = 40) -> List[str]:
    """Client-facing lines: title, then exact paths, then accessible secret evidence."""
    lines = [f"{group.get('title', 'Finding')} ({group.get('severity', 'info')}) — seen {group.get('count', 0)}×"]
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
        if evidence:
            for item in evidence[:10]:
                lines.append(f"  Secret (accessible, masked): {item}")
        else:
            lines.append("  Secret: pattern matched but exact value was not captured")
    elif evidence:
        for item in evidence[:5]:
            lines.append(f"  Evidence: {item}")
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
