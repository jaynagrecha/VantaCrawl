"""JWT, OAuth, session fixation, reset tokens, 2FA bypass."""

from __future__ import annotations

import base64
import html
import json
import time
from typing import Dict

from http_util import json_bytes, page, send
from registry import register


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@register(
    "/jwt/none",
    title="JWT alg=none token",
    family="jwt",
    expected="unsigned JWT accepted / issued",
    tags=["active", "passive"],
)
def jwt_none(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    header = _b64({"alg": "none", "typ": "JWT"})
    payload = _b64({"sub": "admin", "role": "admin", "iat": int(time.time())})
    token = f"{header}.{payload}."
    send(
        handler,
        200,
        page("JWT none", f"<pre>Authorization: Bearer {html.escape(token)}</pre>"),
        headers={"Set-Cookie": f"access_token={token}; Path=/"},
        head_only=head_only,
    )


@register(
    "/jwt/weak",
    title="JWT HS256 with weak secret",
    family="jwt",
    expected="JWT present; secret is 'secret' (documented for cracking labs)",
    tags=["active"],
    notes="Token uses HMAC with trivial secret for scanner/JWT tool demos.",
)
def jwt_weak(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Precomputed HS256 with secret "secret" for demo consistency
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
        "3OwQjvqJ5yQ8xG0oGQ0QF8YvJvQZQZQZQZQZQZQZQZQ"  # placeholder-shaped; body also leaks secret
    )
    body = page(
        "JWT weak",
        f"<pre>token={html.escape(token)}\njwt_secret=secret</pre>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/oauth/callback",
    title="OAuth token in query string",
    family="oauth",
    expected="access_token / code leaked in URL query",
    tags=["passive"],
)
def oauth_callback(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    token = params.get("access_token") or params.get("code") or "ya29.playground-oauth-token-example"
    send(
        handler,
        200,
        page("OAuth callback", f"<p>Logged in.</p><pre>access_token={html.escape(token)}</pre>"),
        head_only=head_only,
    )


@register(
    "/auth/reset",
    title="Password reset token in URL",
    family="auth",
    expected="reset token disclosed in link / response",
    tags=["passive", "active"],
)
def auth_reset(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    token = params.get("token") or "reset-token-0xDEADBEEF-playground"
    email = params.get("email") or "victim@example.com"
    send(
        handler,
        200,
        page(
            "Reset password",
            f"<p>Reset link for {html.escape(email)}</p>"
            f"<a href='/auth/reset?token={html.escape(token)}&email={html.escape(email)}'>continue</a>"
            f"<pre>token={html.escape(token)}</pre>",
        ),
        head_only=head_only,
    )


@register(
    "/auth/session-fixation",
    title="Session fixation",
    family="session",
    expected="pre-login session id reused after login",
    tags=["active", "post"],
)
def session_fixation(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    sid = params.get("sid") or "FIXATED-SESSION-ID-001"
    if handler.command == "POST" or params.get("user"):
        headers = {"Set-Cookie": f"session={sid}; Path=/"}
        return send(
            handler,
            200,
            page("Logged in", f"<p>Welcome — session unchanged: {html.escape(sid)}</p>"),
            headers=headers,
            head_only=head_only,
        )
    body = page(
        "Login (fixation)",
        f'<form method="POST" action="/auth/session-fixation?sid={html.escape(sid)}">'
        '<input name="user" value="admin"><input name="pass" value="admin">'
        '<button type="submit">Login</button></form>',
    )
    send(handler, 200, body, headers={"Set-Cookie": f"session={sid}; Path=/"}, head_only=head_only)


@register(
    "/auth/2fa-bypass",
    title="2FA bypass via direct next step",
    family="auth",
    expected="skip OTP — /auth/2fa-bypass?verified=1 grants access",
    tags=["active"],
)
def twofa_bypass(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if params.get("verified") in {"1", "true", "yes"}:
        return send(
            handler,
            200,
            page("2FA OK", "<p>OTP skipped — dashboard unlocked.</p>"),
            headers={"Set-Cookie": "otp_ok=1; Path=/"},
            head_only=head_only,
        )
    body = page(
        "2FA",
        '<form method="GET" action="/auth/2fa-bypass">'
        '<input name="otp" value="000000">'
        '<input type="hidden" name="verified" value="1">'
        '<button type="submit">Verify</button></form>',
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/auth/predictable-token",
    title="Predictable anti-CSRF / invite token",
    family="session",
    expected="timestamp-based token",
    tags=["passive"],
)
def predictable_token(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    tok = f"invite-{int(time.time())}"
    send(handler, 200, page("Invite", f"<pre>token={html.escape(tok)}</pre>"), head_only=head_only)
