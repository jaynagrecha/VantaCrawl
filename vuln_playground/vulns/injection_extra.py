"""Injection families: NoSQL, LDAP, XPath, SSI, EL, prototype pollution, deserialization."""

from __future__ import annotations

import html
import json
import re
from typing import Dict

from http_util import json_bytes, page, send
from registry import register


@register(
    "/nosql/login",
    title="NoSQL operator injection",
    family="nosql",
    expected="JSON operators like $gt / $ne alter auth logic",
    tags=["active", "post"],
)
def nosql_login(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    user = params.get("user", "")
    password = params.get("password", "") or params.get("pass", "")
    # Simulate Mongo operator injection success
    if "$" in user or "$" in password or '"$ne"' in user or "'$ne'" in password:
        msg = "login ok (operator injection)"
        status = 200
    elif user == "admin" and password == "admin":
        msg = "login ok"
        status = 200
    else:
        msg = "invalid credentials"
        status = 401
    if handler.command == "GET" and not params:
        body = page(
            "NoSQL login",
            '<form method="POST" action="/nosql/login">'
            '<input name="user" value=\'{"$gt":""}\'>'
            '<input name="password" value=\'{"$ne":""}\'>'
            '<button type="submit">Login</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    send(handler, status, page("NoSQL login", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/ldap/search",
    title="LDAP injection",
    family="ldap",
    expected="LDAP filter metacharacters alter search",
    tags=["active"],
)
def ldap_search(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "")
    if any(ch in q for ch in "*()\\/\x00") or ")(" in q:
        text = f"ldap error: invalid filter (&(uid={q})(objectClass=person))"
    else:
        text = f"Found user uid={q or 'guest'}"
    send(handler, 200, page("LDAP", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/xpath/user",
    title="XPath injection",
    family="xpath",
    expected="XPath quote breakout in query",
    tags=["active"],
)
def xpath_user(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "alice")
    if "'" in name or '"' in name or " or " in name.lower():
        text = f"XPathException: error evaluating //user[name/text()='{name}']"
    else:
        text = f"user {name} active=true"
    send(handler, 200, page("XPath", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/ssi/page",
    title="Server-Side Include injection",
    family="ssi",
    expected="<!--#echo / #exec --> reflected executed",
    tags=["active"],
)
def ssi_page(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "hello")
    out = q
    if "<!--#echo" in q or "<!--#exec" in q:
        out = "SSI executed: DOCUMENT_NAME=index.html SERVER_SOFTWARE=Apache"
    body = f"<!DOCTYPE html><html><body><p>{out}</p></body></html>".encode()
    send(handler, 200, body, head_only=head_only)


@register(
    "/el/eval",
    title="Expression Language injection",
    family="el_injection",
    expected="${7*7} / #{7*7} evaluated",
    tags=["active"],
)
def el_eval(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    expr = params.get("expr", "name")
    out = expr
    m = re.search(r"\$\{(\d+)\s*\*\s*(\d+)\}", expr) or re.search(r"#\{(\d+)\s*\*\s*(\d+)\}", expr)
    if m:
        out = str(int(m.group(1)) * int(m.group(2)))
    send(handler, 200, page("EL", f"<p>Result: {html.escape(out)}</p>"), head_only=head_only)


@register(
    "/proto/merge",
    title="Prototype pollution JSON merge",
    family="prototype_pollution",
    expected="__proto__ / constructor.polluted accepted",
    tags=["active", "post"],
)
def proto_merge(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    raw = params.get("json", "")
    polluted = False
    if "__proto__" in raw or "constructor" in raw and "prototype" in raw:
        polluted = True
    if handler.command == "GET" and not raw:
        body = page(
            "Merge",
            '<form method="POST" action="/proto/merge">'
            '<textarea name="json">{"__proto__":{"admin":true}}</textarea>'
            '<button type="submit">Merge</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    send(
        handler,
        200,
        json_bytes({"merged": True, "polluted": polluted, "admin": polluted}),
        headers={"Content-Type": "application/json"},
        head_only=head_only,
    )


@register(
    "/deser/pickle",
    title="Insecure deserialization marker",
    family="deserialization",
    expected="pickle/java serialized payload echoed as executed",
    tags=["active", "post"],
)
def deser_pickle(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    blob = params.get("data", "")
    if "cos" in blob or "R0lGODlh" in blob or "aced0005" in blob.lower() or "pickle" in blob.lower():
        text = "deserialize: executed gadget chain (simulated)"
    else:
        text = "deserialize: ok"
    if handler.command == "GET" and not blob:
        body = page(
            "Deser",
            '<form method="POST" action="/deser/pickle">'
            '<textarea name="data">pickle:cos\nsystem\n(S\'id\'\ntR.</textarea>'
            '<button type="submit">Load</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    send(handler, 200, page("Deser", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/yaml/load",
    title="YAML deserialization",
    family="deserialization",
    expected="!!python/object or critical YAML tags flagged",
    tags=["active", "post"],
)
def yaml_load(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    doc = params.get("doc", "")
    if "!!" in doc or "python/object" in doc:
        text = "yaml load: constructor invoked (simulated)"
    else:
        text = "yaml load: mapping ok"
    if handler.command == "GET" and not doc:
        body = page(
            "YAML",
            '<form method="POST" action="/yaml/load">'
            "<textarea name=\"doc\">!!python/object/apply:os.system ['id']</textarea>"
            '<button type="submit">Parse</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    send(handler, 200, page("YAML", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)
