"""GraphQL, JSONP, Host-header, cache, HTTP smuggling signals, TRACE."""

from __future__ import annotations

import html
import json
from typing import Dict

from http_util import json_bytes, page, send
from registry import register


@register(
    "/graphql",
    title="GraphQL introspection + injection",
    family="graphql",
    expected="introspection enabled; error-based injection on query",
    tags=["active", "post"],
)
def graphql(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("query") or params.get("q") or ""
    if handler.command == "GET" and not q:
        body = page(
            "GraphQL",
            '<form method="POST" action="/graphql">'
            '<textarea name="query">{ __schema { types { name } }</textarea>'
            '<button type="submit">Run</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    if "__schema" in q or "IntrospectionQuery" in q:
        data = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query"},
                        {"name": "User"},
                        {"name": "Secret"},
                        {"name": "Mutation"},
                    ]
                }
            }
        }
        return send(handler, 200, json_bytes(data), headers={"Content-Type": "application/json"}, head_only=head_only)
    if "'" in q or " OR " in q.upper():
        err = {"errors": [{"message": f"syntax error near '{q[:80]}' in GraphQL query"}]}
        return send(handler, 200, json_bytes(err), headers={"Content-Type": "application/json"}, head_only=head_only)
    send(
        handler,
        200,
        json_bytes({"data": {"hello": "world"}}),
        headers={"Content-Type": "application/json"},
        head_only=head_only,
    )


@register(
    "/jsonp",
    title="JSONP callback reflection",
    family="jsonp",
    expected="callback= reflected into JS — XSS/JSONP abuse",
    tags=["active"],
)
def jsonp(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    cb = params.get("callback") or params.get("jsonp") or "cb"
    payload = f"{cb}({{\"user\":\"admin\",\"api_key\":\"pk_live_jsonp_example\"}});"
    send(
        handler,
        200,
        payload.encode(),
        headers={"Content-Type": "application/javascript"},
        head_only=head_only,
    )


@register(
    "/host-header",
    title="Host header password-reset poisoning",
    family="host_header",
    expected="reset link uses attacker Host / X-Forwarded-Host",
    tags=["active"],
)
def host_header(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    host = (
        handler.headers.get("X-Forwarded-Host")
        or handler.headers.get("X-Host")
        or handler.headers.get("Host")
        or "horizon-catalog.onrender.com"
    )
    link = f"https://{host}/auth/reset?token=reset-token-host-poison"
    send(
        handler,
        200,
        page("Reset email preview", f"<p>Click <a href='{html.escape(link)}'>{html.escape(link)}</a></p>"),
        head_only=head_only,
    )


@register(
    "/cache/poison",
    title="Cache key / unkeyed header reflection",
    family="cache",
    expected="X-Forwarded-Prefix reflected — cache poisoning candidate",
    tags=["active"],
)
def cache_poison(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    prefix = handler.headers.get("X-Forwarded-Prefix") or handler.headers.get("X-Original-URL") or ""
    body = page("App", f"<script>window.BASE='{prefix}/static'</script><p>ok</p>")
    send(
        handler,
        200,
        body,
        headers={"Cache-Control": "public, max-age=60", "Vary": "Accept-Encoding"},
        head_only=head_only,
    )


@register(
    "/smuggle/tease",
    title="HTTP request smuggling tease headers",
    family="smuggling",
    expected="ambiguous Transfer-Encoding / Content-Length handling noted",
    tags=["active"],
    notes="Does not actually smuggle; reflects CL/TE confusion markers for scanners.",
)
def smuggle(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    te = handler.headers.get("Transfer-Encoding") or ""
    cl = handler.headers.get("Content-Length") or ""
    msg = f"te={te!r} cl={cl!r}"
    if te and cl:
        msg += " | ambiguous framing (playground)"
    send(handler, 200, page("Smuggle", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/method/trace",
    title="TRACE method echo",
    family="methods",
    expected="TRACE enabled — XST risk",
    tags=["passive"],
    methods=("GET", "POST", "TRACE"),
)
def method_trace(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Base server may not call TRACE; expose via GET that documents TRACE body
    if handler.command == "TRACE":
        raw = f"TRACE /method/trace HTTP/1.1\r\nHost: {handler.headers.get('Host')}\r\n\r\n"
        return send(handler, 200, raw.encode(), headers={"Content-Type": "message/http"}, head_only=head_only)
    send(
        handler,
        200,
        page("TRACE", "<p>Send TRACE to this path. Cross-site tracing demo.</p>"),
        head_only=head_only,
    )


@register(
    "/hpp/search",
    title="HTTP parameter pollution",
    family="hpp",
    expected="duplicate params — last/first wins inconsistently",
    tags=["active"],
)
def hpp_search(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # parse_params already keeps first; show raw query for pollution demos
    from urllib.parse import urlparse

    raw_q = urlparse(handler.path).query
    send(
        handler,
        200,
        page("HPP", f"<pre>raw={html.escape(raw_q)}\nparsed_q={html.escape(params.get('q',''))}</pre>"),
        head_only=head_only,
    )
