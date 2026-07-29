"""Cloud metadata, webhook SSRF, log4j tease, XMLRPC, race demo."""

from __future__ import annotations

import html
import threading
import time
import urllib.request
from typing import Dict

from http_util import json_bytes, page, send
from registry import register

_BALANCE = {"usd": 100}
_LOCK = threading.Lock()


@register(
    "/webhook/fetch",
    title="Webhook SSRF callback URL",
    family="ssrf",
    expected="server fetches attacker-controlled webhook URL",
    tags=["active", "oob"],
)
def webhook_fetch(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    url = params.get("hook") or params.get("url") or ""
    body_txt = ""
    err = ""
    if url.startswith("http://") or url.startswith("https://"):
        try:
            req = urllib.request.Request(url, method="POST", data=b'{"event":"ping"}', headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                body_txt = resp.read(400).decode("utf-8", errors="replace")
        except Exception as exc:
            err = str(exc)[:200]
    if handler.command == "GET" and not url:
        body = page(
            "Webhooks",
            '<form method="POST" action="/webhook/fetch">'
            '<input name="hook" value="http://127.0.0.1:9080/oob/test/ping" style="width:70%">'
            '<button type="submit">Deliver</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    send(
        handler,
        200,
        page("Webhook", f"<pre>url={html.escape(url)}\nerr={html.escape(err)}\n{html.escape(body_txt[:200])}</pre>"),
        head_only=head_only,
    )


@register(
    "/log4j/greet",
    title="Log4j / JNDI tease",
    family="log4j",
    expected="jndi:ldap reflected as lookup attempted",
    tags=["active"],
)
def log4j(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "world")
    ua = handler.headers.get("User-Agent") or ""
    hit = "jndi:" in name.lower() or "jndi:" in ua.lower()
    text = f"Hello {name}"
    if hit:
        text += " | jndi lookup attempted (simulated)"
    send(handler, 200, page("Greet", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/xmlrpc.php",
    title="WordPress-style XML-RPC",
    family="xmlrpc",
    expected="system.listMethods enabled; multicall available",
    tags=["passive", "active", "post"],
)
def xmlrpc(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    raw = params.get("xml") or ""
    if handler.command == "GET" and not raw:
        return send(
            handler,
            200,
            page("XML-RPC", "<p>POST XML-RPC methods to this endpoint.</p>"),
            head_only=head_only,
        )
    if "system.listMethods" in raw or not raw:
        resp = """<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<value><string>system.listMethods</string></value>
<value><string>system.multicall</string></value>
<value><string>wp.getUsersBlogs</string></value>
</data></array></value></param></params></methodResponse>"""
        return send(handler, 200, resp.encode(), headers={"Content-Type": "text/xml"}, head_only=head_only)
    send(handler, 200, b'<?xml version="1.0"?><methodResponse></methodResponse>', headers={"Content-Type": "text/xml"}, head_only=head_only)


@register(
    "/race/withdraw",
    title="Race condition withdraw",
    family="race",
    expected="TOCTOU — concurrent withdraw can overdraw",
    tags=["active", "post"],
)
def race_withdraw(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    raw = params.get("amount") or "90"
    try:
        amt = float(raw)
    except (TypeError, ValueError):
        return send(
            handler,
            400,
            json_bytes({"ok": False, "error": "amount must be numeric", "requested": raw}),
            headers={"Content-Type": "application/json"},
            head_only=head_only,
        )
    # Intentionally weak check then mutate without exclusive lock spanning the sleep
    if _BALANCE["usd"] >= amt:
        time.sleep(0.15)
        _BALANCE["usd"] -= amt
        ok = True
    else:
        ok = False
    send(
        handler,
        200,
        json_bytes({"ok": ok, "balance": _BALANCE["usd"], "requested": amt}),
        headers={"Content-Type": "application/json"},
        head_only=head_only,
    )


@register(
    "/race/balance",
    title="Race balance view",
    family="race",
    expected="shows balance after race withdraws",
    tags=["active"],
)
def race_balance(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if params.get("reset") == "1":
        _BALANCE["usd"] = 100
    send(handler, 200, json_bytes({"balance": _BALANCE["usd"]}), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/redirect/meta",
    title="Meta refresh open redirect",
    family="redirect",
    expected="meta refresh to external URL",
    tags=["active"],
)
def redirect_meta(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    nxt = params.get("next") or params.get("url") or "https://example.com"
    body = f'<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url={nxt}"></head><body>redirect</body></html>'.encode()
    send(handler, 200, body, head_only=head_only)


@register(
    "/redirect/js",
    title="JavaScript open redirect",
    family="redirect",
    expected="location= attacker URL",
    tags=["active"],
)
def redirect_js(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    nxt = params.get("next") or params.get("url") or "https://example.com"
    body = f"<!DOCTYPE html><html><body><script>location = {nxt!r}</script></body></html>".encode()
    send(handler, 200, body, head_only=head_only)
