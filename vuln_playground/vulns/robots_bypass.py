"""robots.txt staging + disallow-only targets for crawl-policy bypass tests.

Paths under /private/ and related Disallow entries are intentionally:
- listed in robots.txt as Disallow
- NOT linked from the Horizon Catalog homepage
- still HTTP 200 with sensitive markers when fetched directly

A crawler that honors robots.txt should skip them.
A crawler that ignores / treats Disallow as hints should find ROBOTS_BYPASS_CANARY.
"""

from __future__ import annotations

from typing import Dict

from http_util import json_bytes, page, send
from registry import register

# Stable marker for acceptance / scanner assertions
BYPASS_CANARY = "ROBOTS_BYPASS_CANARY"
SECRET = "sk_live_robots_disallow_playground"


@register(
    "/robots.txt",
    title="robots.txt",
    family="discovery",
    expected="Disallow entries; respectful crawlers skip; bypass crawlers still fetch",
    tags=["passive", "robots"],
    linked=False,
)
def robots(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = "\n".join(
        [
            "# Horizon Catalog — crawl policy",
            "# Paths below are sensitive. Compliant bots must not fetch them.",
            "# Scanners under test may choose to ignore Disallow (bypass mode).",
            "User-agent: *",
            "Allow: /$",
            "Allow: /healthz",
            "Allow: /catalog.json",
            "",
            "# --- primary robots-bypass test surface (unlinked) ---",
            "Disallow: /private/",
            "Disallow: /private/admin",
            "Disallow: /private/secrets.env",
            "Disallow: /private/internal-api",
            "Disallow: /private/db-dump.sql",
            "Disallow: /secret-admin-panel",
            "Disallow: /hidden/finance",
            "",
            "# --- also restricted (some may also appear via other discovery) ---",
            "Disallow: /leak/",
            "Disallow: /actuator/",
            "Disallow: /.git/",
            "Disallow: /.env",
            "Disallow: /backup/",
            "Disallow: /keys/",
            "Disallow: /bac/",
            "Disallow: /k8s/",
            "Disallow: /debug/",
            "Disallow: /wp-config.php.bak",
            "",
            "Sitemap: /sitemap.xml",
            "",
        ]
    ).encode("utf-8")
    send(handler, 200, body, headers={"Content-Type": "text/plain; charset=utf-8"}, head_only=head_only)


@register(
    "/sitemap.xml",
    title="sitemap.xml (excludes private)",
    family="discovery",
    expected="public URLs only — private paths absent",
    tags=["passive", "robots"],
    linked=False,
)
def sitemap(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Deliberately omits /private/* — only public catalog entrypoints
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://horizon-catalog.onrender.com/</loc></url>
  <url><loc>https://horizon-catalog.onrender.com/healthz</loc></url>
</urlset>
"""
    send(handler, 200, xml.encode("utf-8"), headers={"Content-Type": "application/xml"}, head_only=head_only)


@register(
    "/private/admin",
    title="robots-disallowed admin panel",
    family="robots_bypass",
    expected="reachable despite Disallow if crawler bypasses robots.txt",
    tags=["robots", "enum"],
    linked=False,
)
def private_admin(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Private admin",
        f"<p class='tag'>robots Disallow</p>"
        f"<p>Internal admin panel — not linked from the catalog index.</p>"
        f"<pre>{BYPASS_CANARY}\nrole=superadmin\napi_key={SECRET}</pre>"
        f'<p><a href="/private/secrets.env">secrets</a> · '
        f'<a href="/private/internal-api">internal api</a></p>',
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/private/secrets.env",
    title="robots-disallowed secrets file",
    family="robots_bypass",
    expected="secret finding only if robots Disallow is bypassed (or direct URL)",
    tags=["robots", "secrets"],
    linked=False,
)
def private_secrets(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = (
        f"# disallowed by /robots.txt — {BYPASS_CANARY}\n"
        f"ROBOTS_BYPASS_SECRET={SECRET}\n"
        "AWS_ACCESS_KEY_ID=AKIAROBOTSBYPASSDEMO\n"
        "AWS_SECRET_ACCESS_KEY=robots/bypass/playground/notreal\n"
        "DATABASE_URL=postgres://robot:DisallowPass@db:5432/private\n"
    )
    send(
        handler,
        200,
        text.encode("utf-8"),
        headers={"Content-Type": "text/plain; charset=utf-8", "X-Robots-Tag": "noindex, nofollow"},
        head_only=head_only,
    )


@register(
    "/private/internal-api",
    title="robots-disallowed internal API",
    family="robots_bypass",
    expected="JSON PII if Disallow bypassed",
    tags=["robots", "api"],
    linked=False,
)
def private_api(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = {
        "marker": BYPASS_CANARY,
        "users": [
            {"email": "ceo@horizon.local", "ssn": "111-22-3333", "role": "admin"},
            {"email": "cfo@horizon.local", "ssn": "444-55-6666", "role": "finance"},
        ],
        "note": "Listed under Disallow: /private/ in robots.txt; not on homepage.",
    }
    send(
        handler,
        200,
        json_bytes(data),
        headers={
            "Content-Type": "application/json",
            "X-Robots-Tag": "noindex, nofollow",
        },
        head_only=head_only,
    )


@register(
    "/private/db-dump.sql",
    title="robots-disallowed SQL dump",
    family="robots_bypass",
    expected="backup/secret if Disallow bypassed",
    tags=["robots", "backup"],
    linked=False,
)
def private_dump(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = (
        f"-- {BYPASS_CANARY}\n"
        "CREATE TABLE private_users(id INT, email TEXT, password_hash TEXT);\n"
        "INSERT INTO private_users VALUES (1,'ceo@horizon.local','$2b$12$robotsbypass');\n"
        f"-- api_key={SECRET}\n"
    )
    send(
        handler,
        200,
        text.encode("utf-8"),
        headers={"Content-Type": "text/plain; charset=utf-8", "X-Robots-Tag": "noindex"},
        head_only=head_only,
    )


@register(
    "/private",
    title="robots-disallowed private index",
    family="robots_bypass",
    expected="directory-style index of disallow targets",
    tags=["robots"],
    linked=False,
)
def private_index(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Private area",
        f"<p>Disallowed by robots.txt. Marker: <code>{BYPASS_CANARY}</code></p><ul>"
        '<li><a href="/private/admin">admin</a></li>'
        '<li><a href="/private/secrets.env">secrets.env</a></li>'
        '<li><a href="/private/internal-api">internal-api</a></li>'
        '<li><a href="/private/db-dump.sql">db-dump.sql</a></li>'
        "</ul>",
    )
    send(handler, 200, body, headers={"X-Robots-Tag": "noindex, nofollow"}, head_only=head_only)


@register(
    "/hidden/finance",
    title="robots-disallowed finance page",
    family="robots_bypass",
    expected="unlinked + Disallow — bypass test",
    tags=["robots"],
    linked=False,
)
def hidden_finance(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Finance",
        f"<pre>{BYPASS_CANARY}\npayout_account=acct_robots_bypass\nrouting=110000000</pre>",
    )
    send(handler, 200, body, headers={"X-Robots-Tag": "noindex"}, head_only=head_only)


@register(
    "/secret-admin-panel",
    title="Hidden admin panel",
    family="robots_bypass",
    expected="enum / robots Disallow bypass",
    tags=["robots", "enum"],
    linked=False,
)
def hidden_admin(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(
        handler,
        200,
        page(
            "Secret admin",
            f"<p>Internal admin panel (not linked from index).</p>"
            f"<pre>{BYPASS_CANARY}\npanel=legacy-secret-admin</pre>",
        ),
        headers={"X-Robots-Tag": "noindex, nofollow"},
        head_only=head_only,
    )
