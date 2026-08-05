"""Cookie / CSRF / CORS playground endpoints."""

from __future__ import annotations

import html
from typing import Dict

from http_util import page, send
from registry import register


@register(
    "/cookies/set",
    title="Weak session cookies",
    family="cookies",
    expected="passive cookie findings (missing Secure/HttpOnly flags)",
    tags=["passive"],
)
def cookies_set(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Deliberately weak cookies for passive analysis
    headers = {
        "Set-Cookie": "session=playground-session-token; Path=/",
        # http.server only sets one Set-Cookie via our helper — pack a second via raw? 
        # Use a single obvious weak cookie; scanner still sees missing flags.
    }
    body = page(
        "Cookies",
        "<p>Issued a session cookie without Secure / HttpOnly / SameSite.</p>"
        "<p>Also see <a href='/cookies/dual'>/cookies/dual</a>.</p>",
    )
    send(handler, 200, body, headers=headers, head_only=head_only)


@register(
    "/cookies/dual",
    title="Multiple Set-Cookie (manual header lines)",
    family="cookies",
    expected="cookie auth / flag findings",
    tags=["passive"],
)
def cookies_dual(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Use send_response path manually for multiple Set-Cookie
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Set-Cookie", "sid=abc123; Path=/")
    handler.send_header("Set-Cookie", "prefs=dark; Path=/")
    body = page("Dual cookies", "<p>two cookies</p>")
    if head_only:
        body = b""
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if body:
        handler.wfile.write(body)


@register(
    "/csrf/action",
    title="State-changing POST without CSRF token",
    family="csrf",
    expected="csrf candidate (passive/active depending on mode)",
    tags=["passive", "post"],
)
def csrf_action(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "GET" and not params.get("email"):
        body = page(
            "CSRF form",
            '<form method="POST" action="/csrf/action">'
            '<input name="email" value="user@example.com">'
            '<button type="submit">Update email</button></form>'
            "<p>No CSRF token field.</p>",
        )
        return send(handler, 200, body, head_only=head_only)
    email = params.get("email", "")
    send(
        handler,
        200,
        page("CSRF action", f"<p>Updated email to {html.escape(email)}</p>"),
        head_only=head_only,
    )


@register(
    "/cors/open",
    title="Overly permissive CORS",
    family="cors",
    expected="cors finding reflecting Origin with credentials",
    tags=["passive", "lab", "extended", "active"],
)
def cors_open(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    origin = handler.headers.get("Origin") or "*"
    canary = params.get("canary") or "CORS_CANARY_OPEN"
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }
    body = page(
        "CORS open",
        f"<pre> ACAO={html.escape(origin)} with credentials </pre>"
        f"<pre>canary={html.escape(canary)}</pre>",
    )
    send(handler, 200, body, headers=headers, head_only=head_only)


@register(
    "/cors/public",
    title="Public wildcard CORS without credentials",
    family="cors",
    expected="cross-origin public read is not high-severity without sensitive canary",
    tags=["passive", "lab", "control"],
)
def cors_public(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Vary": "Origin",
    }
    body = page("CORS public", "<pre>public brochure text</pre>")
    send(handler, 200, body, headers=headers, head_only=head_only)


@register(
    "/cors/trusted",
    title="CORS allowlist trusted origin only",
    family="cors",
    expected="disallowed proof origin remains unreadable (negative control)",
    tags=["passive", "lab", "control", "fp-guard"],
)
def cors_trusted(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    origin = handler.headers.get("Origin") or ""
    trusted = "https://trusted.example"
    headers = {"Vary": "Origin"}
    if origin == trusted:
        headers["Access-Control-Allow-Origin"] = trusted
        headers["Access-Control-Allow-Credentials"] = "true"
        body = page("CORS trusted", "<pre>canary=CORS_CANARY_TRUSTED</pre>")
    else:
        body = page("CORS trusted", "<pre>origin not allowed</pre>")
    send(handler, 200, body, headers=headers, head_only=head_only)


@register(
    "/cors/wildcard-creds",
    title="Invalid wildcard+credentials header pair",
    family="cors",
    expected="browsers block credentialed wildcard reads — must not confirm",
    tags=["passive", "lab", "control", "fp-guard"],
)
def cors_wildcard_creds(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    body = page("CORS wildcard+creds", "<pre>canary=CORS_CANARY_STAR</pre>")
    send(handler, 200, body, headers=headers, head_only=head_only)
