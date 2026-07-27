"""Auth/enum/rate-limit/CAPTCHA/SAML/password-reset poisoning extras."""

from __future__ import annotations

import hashlib
import html
import time
from typing import Dict

from http_util import json_bytes, page, send
from registry import register

_ATTEMPTS: Dict[str, int] = {}
_USERS = {"alice@example.com": True, "admin@horizon.local": True, "bob@example.com": True}


@register(
    "/enum/user",
    title="Username / email enumeration",
    family="user_enumeration",
    expected="different responses for valid vs invalid accounts",
    tags=["active"],
)
def enum_user(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    email = (params.get("email") or params.get("user") or "").strip().lower()
    if not email:
        body = page(
            "Account check",
            '<form method="GET"><input name="email" placeholder="email"><button>Check</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    if email in _USERS:
        msg = "account found — password hint sent"
        status = 200
    else:
        msg = "unknown account"
        status = 404
    send(handler, status, page("Account check", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/auth/timing",
    title="Login timing oracle",
    family="timing",
    expected="valid usernames take longer (hash verify path)",
    tags=["active", "post"],
)
def auth_timing(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    user = params.get("user", "")
    password = params.get("password", "")
    if handler.command == "GET" and not params:
        body = page(
            "Timing login",
            '<form method="POST"><input name="user"><input name="password" type="password">'
            "<button>Login</button></form>",
        )
        return send(handler, 200, body, head_only=head_only)
    if user in ("admin", "alice"):
        # Simulate slow password hash verify
        time.sleep(0.35)
        ok = password == "correct-horse"
    else:
        ok = False
    msg = "ok" if ok else "invalid"
    send(handler, 200 if ok else 401, page("Timing login", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/auth/norate",
    title="No rate limit on login",
    family="rate_limit",
    expected="unlimited password guesses",
    tags=["active", "post"],
)
def auth_norate(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    user = params.get("user", "admin")
    password = params.get("password", "")
    _ATTEMPTS[user] = _ATTEMPTS.get(user, 0) + 1
    ok = password == "admin"
    msg = f"attempt={_ATTEMPTS[user]} result={'ok' if ok else 'fail'} (no lockout)"
    send(handler, 200 if ok else 401, page("No rate limit", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/captcha/bypass",
    title="CAPTCHA bypass (client-side only)",
    family="captcha",
    expected="captcha token accepted when omitted or forged",
    tags=["active", "post"],
)
def captcha_bypass(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "GET" and not params.get("submit"):
        body = page(
            "CAPTCHA form",
            '<form method="POST">'
            '<input type="hidden" name="captcha" id="cap" value="">'
            '<input name="msg" value="hello">'
            "<button>Send</button></form>"
            "<script>document.getElementById('cap').value='passed';</script>",
        )
        return send(handler, 200, body, head_only=head_only)
    # Server does not validate captcha meaningfully
    msg = f"accepted msg={params.get('msg','')} captcha={params.get('captcha','(missing)')}"
    send(handler, 200, page("CAPTCHA", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/reset/poison",
    title="Password reset Host-header poisoning",
    family="password_reset",
    expected="reset link uses attacker-controlled Host",
    tags=["active", "post"],
)
def reset_poison(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    email = params.get("email", "user@example.com")
    host = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or "localhost"
    token = hashlib.sha1(email.encode()).hexdigest()[:16]
    link = f"https://{host}/auth/reset?token={token}&email={email}"
    body = page("Reset", f"<p>reset email queued</p><pre>{html.escape(link)}</pre>")
    send(handler, 200, body, head_only=head_only)


@register(
    "/saml/acs",
    title="SAML assertion confusion tease",
    family="saml",
    expected="unsigned / swapped Recipient assertion accepted (demo)",
    tags=["active", "post"],
)
def saml_acs(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    assertion = params.get("SAMLResponse", "") or params.get("assertion", "")
    if handler.command == "GET" and not assertion:
        body = page(
            "SAML ACS",
            '<form method="POST"><textarea name="SAMLResponse" rows="6" cols="70">'
            "&lt;Assertion&gt;&lt;NameID&gt;admin@horizon.local&lt;/NameID&gt;&lt;/Assertion&gt;"
            "</textarea><button>POST ACS</button></form>",
        )
        return send(handler, 200, body, head_only=head_only)
    # No signature check
    if "admin" in assertion or "NameID" in assertion:
        msg = "SSO ok as admin@horizon.local (signature not verified)"
        status = 200
    else:
        msg = "SSO failed"
        status = 401
    send(handler, status, page("SAML ACS", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/otp/predictable",
    title="Predictable OTP / MFA code",
    family="otp",
    expected="6-digit OTP derived from time bucket / user id",
    tags=["active"],
)
def otp_predictable(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    user = params.get("user", "alice")
    bucket = int(time.time()) // 60
    code = f"{(bucket + len(user) * 7) % 1000000:06d}"
    guess = params.get("otp", "")
    if guess:
        ok = guess == code
        msg = f"{'ok' if ok else 'bad'} (server expects {code})"
        return send(handler, 200 if ok else 401, page("OTP", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)
    send(
        handler,
        200,
        page("OTP", f"<p>enter otp for {html.escape(user)}</p><pre>debug_hint_code={code}</pre>"),
        head_only=head_only,
    )


@register(
    "/auth/jwt-kid",
    title="JWT kid path traversal / SQLi tease",
    family="jwt",
    expected="kid header influences key lookup unsafely",
    tags=["active"],
)
def jwt_kid(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    kid = params.get("kid", "keys/hmac.pem")
    token = params.get("token", "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.payload.sig")
    unsafe = ".." in kid or "'" in kid or kid.startswith("/")
    msg = f"lookup key file={kid} token={token[:48]}..."
    if unsafe:
        msg += "\nKID injection: path/SQL metacharacters accepted"
    send(handler, 200, page("JWT kid", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)
