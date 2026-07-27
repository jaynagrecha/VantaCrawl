"""Template / expression engines and deserialization teases beyond core SSTI."""

from __future__ import annotations

import html
import re
from typing import Dict

from http_util import page, send
from registry import register


def _evalish(expr: str) -> str:
    expr = expr.strip()
    if re.fullmatch(r"\d+(\s*[\+\-\*/]\s*\d+)+", expr):
        try:
            return str(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 — intentional playground sink
        except Exception as exc:
            return f"err:{exc}"
    if "{{" in expr or "${" in expr or "#{" in expr:
        inner = re.sub(r"[{}$#]", "", expr)
        if re.fullmatch(r"\d+(\s*[\+\-\*/]\s*\d+)+", inner.strip()):
            try:
                return str(eval(inner, {"__builtins__": {}}, {}))  # noqa: S307
            except Exception:
                pass
        return f"EVAL:{expr}"
    return expr


@register(
    "/tmpl/freemarker",
    title="FreeMarker template injection",
    family="ssti",
    expected="FreeMarker ${} expressions evaluate",
    tags=["active"],
)
def tmpl_freemarker(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "${7*7}")
    if "${" in name:
        out = _evalish(name)
    else:
        out = name
    send(handler, 200, page("FreeMarker", f"<pre>Hello {html.escape(str(out))}</pre>"), head_only=head_only)


@register(
    "/tmpl/velocity",
    title="Velocity template injection",
    family="ssti",
    expected="Velocity #set / $expr sinks",
    tags=["active"],
)
def tmpl_velocity(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "#set($x=7*7)$x")
    if "$" in name or "#set" in name:
        out = "49" if "7*7" in name else f"VELOCITY:{name}"
    else:
        out = name
    send(handler, 200, page("Velocity", f"<pre>{html.escape(out)}</pre>"), head_only=head_only)


@register(
    "/tmpl/twig",
    title="Twig template injection",
    family="ssti",
    expected="Twig {{ }} expressions evaluate",
    tags=["active"],
)
def tmpl_twig(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "{{7*7}}")
    out = _evalish(name) if "{{" in name else name
    send(handler, 200, page("Twig", f"<pre>{html.escape(str(out))}</pre>"), head_only=head_only)


@register(
    "/tmpl/smarty",
    title="Smarty template injection",
    family="ssti",
    expected="Smarty {7*7} style expressions",
    tags=["active"],
)
def tmpl_smarty(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "{7*7}")
    m = re.fullmatch(r"\{(\d+(?:\s*[\+\-\*/]\s*\d+)+)\}", name.strip())
    out = str(eval(m.group(1), {"__builtins__": {}}, {})) if m else name  # noqa: S307
    send(handler, 200, page("Smarty", f"<pre>{html.escape(str(out))}</pre>"), head_only=head_only)


@register(
    "/spel/eval",
    title="Spring SpEL injection",
    family="spel",
    expected="SpEL T(java.lang.Runtime) style payloads",
    tags=["active"],
)
def spel_eval(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "#{7*7}")
    if "T(" in q or "#{" in q or "${" in q:
        out = "49" if "7*7" in q else "SPEL_EXEC:" + q
    else:
        out = q
    send(handler, 200, page("SpEL", f"<pre>{html.escape(out)}</pre>"), head_only=head_only)


@register(
    "/ognl/eval",
    title="OGNL / Struts injection",
    family="ognl",
    expected="OGNL %{ } / member access payloads",
    tags=["active"],
)
def ognl_eval(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "%{7*7}")
    if "%{" in q or "ognl" in q.lower() or "#context" in q:
        out = "49" if "7*7" in q else "OGNL:" + q
    else:
        out = q
    send(handler, 200, page("OGNL", f"<pre>{html.escape(out)}</pre>"), head_only=head_only)


@register(
    "/deser/java",
    title="Java deserialization gadget tease",
    family="deserialization",
    expected="rO0 ABBase64 java serialized blob accepted",
    tags=["active", "post"],
)
def deser_java(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    blob = params.get("payload", "")
    if handler.command == "GET" and not blob:
        body = page(
            "Java deser",
            '<form method="POST"><textarea name="payload" rows="4" cols="70">rO0ABXNy</textarea>'
            "<button>Deserialize</button></form>",
        )
        return send(handler, 200, body, head_only=head_only)
    if blob.startswith("rO0") or "aced0005" in blob.lower():
        msg = "ObjectInputStream.readObject() -> PLAYGROUND_JAVA_DESER"
    else:
        msg = "ignored"
    send(handler, 200, page("Java deser", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/deser/viewstate",
    title="ASP.NET ViewState deserialization tease",
    family="deserialization",
    expected="unprotected viewstate blob",
    tags=["active", "post"],
)
def deser_viewstate(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    vs = params.get("__VIEWSTATE", "AAEAAAD/////AQAAAAAAAAAMAgAAA")
    body = page(
        "ViewState",
        f'<form method="POST"><input name="__VIEWSTATE" value="{html.escape(vs)}">'
        "<button>Postback</button></form>"
        "<pre>enableViewStateMac=false machineKey weak</pre>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xpath/blind",
    title="XPath blind injection",
    family="xpath",
    expected="boolean XPath differential",
    tags=["active"],
)
def xpath_blind(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("name", "alice")
    if "' or " in q.lower() or " or '" in q.lower() or "1=1" in q:
        msg = "user exists"
    else:
        msg = "not found"
    send(handler, 200, page("XPath blind", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/ldap/blind",
    title="LDAP blind injection",
    family="ldap",
    expected="LDAP wildcard blind differential",
    tags=["active"],
)
def ldap_blind(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("uid", "alice")
    if "*" in q or ")(" in q:
        msg = "many entries"
    else:
        msg = "one entry" if q == "alice" else "zero entries"
    send(handler, 200, page("LDAP blind", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)
