"""XSS / HTML injection sinks."""

from __future__ import annotations

import html
from typing import Dict

from http_util import page, send
from registry import register


@register(
    "/xss/reflected",
    title="XSS reflected (raw text)",
    family="xss",
    expected="xss/html_injection unverified reflection (not browser-confirmed unless payload executes)",
    tags=["active", "safe"],
)
def xss_reflected(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "")
    send(handler, 200, page("XSS reflected", f"<p>Results for: {q}</p>"), head_only=head_only)


@register(
    "/xss/encoded",
    title="XSS encoded (escaped)",
    family="xss",
    expected="unconfirmed / no executable XSS",
    tags=["control"],
)
def xss_encoded(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = html.escape(params.get("q", ""), quote=True)
    send(handler, 200, page("XSS encoded", f"<p>Results for: {q}</p>"), head_only=head_only)


@register(
    "/xss/browser",
    title="XSS browser-executing sink",
    family="xss",
    expected="browser_execution_confirmed in Lab/browser mode",
    tags=["active", "lab", "browser"],
    notes="Raw attribute + HTML sink so onload/onfocus kit payloads can execute.",
)
def xss_browser(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "")
    body = (
        "<!DOCTYPE html><html><head><title>XSS browser</title></head><body>"
        f'<input id="q" value="{q}">'
        f'<div id="sink">{q}</div>'
        "<p>playground browser sink</p></body></html>"
    ).encode("utf-8")
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/form",
    title="XSS POST form",
    family="xss",
    expected="xss/html_injection on form field q",
    tags=["active", "safe", "post"],
)
def xss_form(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "POST" or params.get("q"):
        q = params.get("q", "")
        body = (
            "<!DOCTYPE html><html><head><title>XSS form result</title></head><body>"
            f'<div data-q="{q}">posted</div><p>{q}</p></body></html>'
        ).encode("utf-8")
        return send(handler, 200, body, head_only=head_only)
    body = page(
        "XSS form",
        '<form method="POST" action="/xss/form">'
        '<input name="q" value="test"><button type="submit">Go</button></form>',
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/attr",
    title="XSS attribute breakout",
    family="xss",
    expected="html_injection / xss reflection on name",
    tags=["active", "extended"],
)
def xss_attr(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "guest")
    body = page("XSS attr", f'<div class="user" data-name="{name}">hello</div>')
    send(handler, 200, body, head_only=head_only)
