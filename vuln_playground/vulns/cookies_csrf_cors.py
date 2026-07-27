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
    tags=["passive"],
)
def cors_open(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    origin = handler.headers.get("Origin") or "*"
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }
    body = page("CORS open", f"<pre> ACAO={html.escape(origin)} with credentials </pre>")
    send(handler, 200, body, headers=headers, head_only=head_only)
