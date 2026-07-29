"""HTML-injection context discovery and dynamic clobber-candidate extraction.

No Horizon routes, parameter allowlists, or fixed property names.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
from html.parser import HTMLParser


@dataclass
class InjectionContext:
    """How an inert marker appeared in the response."""

    parameter: str
    marker_id: str
    nonce: str
    classification: str  # encoded | reflected_text | live_dom | absent
    contexts: List[str] = field(default_factory=list)  # body|attribute|script|url
    allows_element_creation: bool = False
    evidence: str = ""


@dataclass
class ClobberCandidate:
    """A dynamically discovered named property that may be clobberable."""

    property_path: str  # e.g. "cfg" or "cfg.url"
    root_name: str
    nested_name: str = ""
    source: str = ""  # script_static | element_id | element_name | browser_inventory
    priority_sink_hints: List[str] = field(default_factory=list)
    score: int = 0


_IDENT = r"[A-Za-z_$][\w$]*"

# Static reads of config-like properties used with URL-ish fields / sinks.
_PROP_URL_FIELD_RE = re.compile(
    rf"\b({_IDENT})\s*\.\s*(href|src|url|action|data|value)\b",
    re.I,
)
_WINDOW_PROP_RE = re.compile(rf"\bwindow\s*\.\s*({_IDENT})\b")
_OR_DEFAULT_RE = re.compile(
    rf"\b({_IDENT})\s*=\s*window\s*\.\s*({_IDENT})\s*\|\|",
)
_SINK_ASSIGN_RE = re.compile(
    r"\.(src|href|action|data)\s*=|"
    r"\blocation\s*(?:\.href)?\s*=|"
    r"\b(?:fetch|open)\s*\(|"
    r"\bnew\s+Worker\s*\(|"
    r"\bnew\s+WebSocket\s*\(|"
    r"\binnerHTML\s*=|"
    r"\binsertAdjacentHTML\s*\(",
    re.I,
)

# Common throwaway locals from createElement / querySelector patterns — not clobber targets.
_IGNORED_LOCALS = frozenset(
    {
        "s",
        "el",
        "elem",
        "element",
        "node",
        "script",
        "iframe",
        "img",
        "link",
        "form",
        "input",
        "btn",
        "button",
        "div",
        "span",
        "tmp",
        "obj",
        "val",
        "url",
        "src",
        "href",
        "xhr",
        "req",
        "res",
        "err",
        "e",
        "ev",
        "event",
    }
)

# Browser built-ins / noisy globals to ignore when inventorying.
_IGNORED_ROOTS = frozenset(
    {
        "document",
        "window",
        "self",
        "top",
        "parent",
        "frames",
        "location",
        "navigator",
        "console",
        "chrome",
        "external",
        "clientInformation",
        "performance",
        "crypto",
        "caches",
        "cookieStore",
        "customElements",
        "history",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "speechSynthesis",
        "styleMedia",
        "visualViewport",
        "webkitStorageInfo",
        "TEMPORARY",
        "PERSISTENT",
        "length",
        "name",
        "status",
        "closed",
        "opener",
        "event",
        "undefined",
        "NaN",
        "Infinity",
        "Array",
        "Object",
        "String",
        "Number",
        "Boolean",
        "Function",
        "Math",
        "JSON",
        "Date",
        "RegExp",
        "Error",
        "Promise",
        "Map",
        "Set",
        "Symbol",
        "Proxy",
        "Reflect",
        "Intl",
        "WebAssembly",
        "CSS",
        "HTMLElement",
        "Element",
        "Node",
        "Event",
        "MouseEvent",
        "CustomEvent",
        "XMLHttpRequest",
        "fetch",
        "Headers",
        "Request",
        "Response",
        "URL",
        "URLSearchParams",
        "FormData",
        "Blob",
        "File",
        "FileReader",
        "Worker",
        "SharedWorker",
        "ServiceWorker",
        "WebSocket",
        "EventSource",
        "MutationObserver",
        "IntersectionObserver",
        "ResizeObserver",
        "PerformanceObserver",
        "AbortController",
        "AbortSignal",
        "TextEncoder",
        "TextDecoder",
        "atob",
        "btoa",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "requestAnimationFrame",
        "cancelAnimationFrame",
        "queueMicrotask",
        "getComputedStyle",
        "matchMedia",
        "getSelection",
        "alert",
        "confirm",
        "prompt",
        "print",
        "open",
        "close",
        "focus",
        "blur",
        "scroll",
        "scrollTo",
        "scrollBy",
        "postMessage",
        "addEventListener",
        "removeEventListener",
        "dispatchEvent",
        "VCIM_",  # our markers
    }
)


def new_marker(prefix: str = "VCIM") -> tuple[str, str]:
    """Return (marker_id, nonce) for inert HTML injection."""
    nonce = secrets.token_hex(8)
    marker_id = f"{prefix}_{nonce}"
    return marker_id, nonce


def inert_html_marker(marker_id: str, nonce: str) -> str:
    """Unique inert element — not executable; proves live DOM insertion."""
    return f'<span id="{marker_id}" data-vc-dc-mark="{nonce}"></span>'


def classify_marker_reflection(body: str, marker_id: str, nonce: str) -> InjectionContext:
    """Classify how the inert marker appears in an HTTP response body."""
    text = body or ""
    ctx = InjectionContext(
        parameter="",
        marker_id=marker_id,
        nonce=nonce,
        classification="absent",
    )
    if not marker_id:
        return ctx

    encoded_forms = (
        marker_id.replace("_", "&#95;") in text,
        f"&lt;span id=&quot;{marker_id}&quot;" in text,
        f"&lt;span id='{marker_id}'" in text,
        f"&lt;span id=\\\"{marker_id}\\\"" in text,
        html_escape_basic(f'<span id="{marker_id}"') in text,
    )
    live_patterns = (
        f'id="{marker_id}"' in text,
        f"id='{marker_id}'" in text,
        f'data-vc-dc-mark="{nonce}"' in text,
        f"data-vc-dc-mark='{nonce}'" in text,
    )
    raw_id_only = marker_id in text

    if any(live_patterns):
        ctx.classification = "live_dom"
        ctx.allows_element_creation = True
        ctx.contexts.append("body")
        ctx.evidence = f"live_marker:{marker_id}"
        # Attribute context if marker sits inside a quoted attribute value awkwardly
        if re.search(rf'(?:href|src|action|value)\s*=\s*"[^"]*{re.escape(marker_id)}', text, re.I):
            ctx.contexts.append("attribute")
        if re.search(rf"<script[^>]*>[^<]*{re.escape(marker_id)}", text, re.I):
            ctx.contexts.append("script")
        return ctx

    if any(encoded_forms) or (raw_id_only and ("&lt;" in text or "&#" in text)):
        ctx.classification = "encoded"
        ctx.contexts.append("body")
        ctx.evidence = f"encoded_marker:{marker_id}"
        return ctx

    if raw_id_only:
        ctx.classification = "reflected_text"
        ctx.contexts.append("body")
        ctx.evidence = f"text_marker:{marker_id}"
        return ctx

    return ctx


def html_escape_basic(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class _IdNameCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: Set[str] = set()
        self.names: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs if k}
        if ad.get("id"):
            self.ids.add(ad["id"])
        if ad.get("name"):
            self.names.add(ad["name"])


def extract_element_names(html_body: str) -> tuple[Set[str], Set[str]]:
    parser = _IdNameCollector()
    try:
        parser.feed(html_body or "")
        parser.close()
    except Exception:
        pass
    return parser.ids, parser.names


def extract_script_bodies(html_body: str) -> List[str]:
    return re.findall(r"(?is)<script\b[^>]*>(.*?)</script>", html_body or "")


def discover_candidates_from_html(
    html_body: str,
    *,
    max_candidates: int = 24,
) -> List[ClobberCandidate]:
    """Discover clobber candidates from response HTML/JS without hardcoding names."""
    scored: Dict[str, ClobberCandidate] = {}

    def _add(c: ClobberCandidate) -> None:
        if not c.root_name or c.root_name in _IGNORED_ROOTS:
            return
        if c.root_name in _IGNORED_LOCALS:
            return
        if len(c.root_name) <= 1:
            return
        if c.root_name.startswith("VCIM_") or c.root_name.startswith("VCXSS_"):
            return
        key = c.property_path
        prev = scored.get(key)
        if prev is None or c.score > prev.score:
            scored[key] = c

    ids, names = extract_element_names(html_body)
    for i in ids:
        _add(
            ClobberCandidate(
                property_path=i,
                root_name=i,
                source="element_id",
                score=40,
            )
        )
    for n in names:
        _add(
            ClobberCandidate(
                property_path=n,
                root_name=n,
                source="element_name",
                score=35,
            )
        )

    scripts = extract_script_bodies(html_body)
    for script in scripts:
        sinkish = bool(_SINK_ASSIGN_RE.search(script))
        aliases: Dict[str, str] = {}
        for m in _WINDOW_PROP_RE.finditer(script):
            name = m.group(1)
            _add(
                ClobberCandidate(
                    property_path=name,
                    root_name=name,
                    source="script_static",
                    priority_sink_hints=["script.src"] if sinkish else [],
                    score=70 if sinkish else 55,
                )
            )
        for m in _OR_DEFAULT_RE.finditer(script):
            local, win = m.group(1), m.group(2)
            _add(
                ClobberCandidate(
                    property_path=win,
                    root_name=win,
                    source="script_static",
                    priority_sink_hints=["script.src"] if sinkish else [],
                    score=95 if sinkish else 70,
                )
            )
            aliases[local] = win
        for m in _PROP_URL_FIELD_RE.finditer(script):
            root, field = m.group(1), m.group(2).lower()
            # Prefer the window.* target when this identifier is only a local alias.
            resolved_root = aliases.get(root, root)
            path = f"{resolved_root}.{field}" if field not in ("href",) or resolved_root != root else resolved_root
            # For href on an element clobber, the useful path is the root global.
            if field in ("href", "src") and resolved_root:
                path = resolved_root
            sink_hint = {
                "href": "script.src",
                "src": "script.src",
                "url": "script.src",
                "action": "form.action",
                "data": "object.data",
                "value": "script.src",
            }.get(field, "script.src")
            _add(
                ClobberCandidate(
                    property_path=path if "." not in path else path,
                    root_name=resolved_root,
                    nested_name="" if field in ("href", "src") else field,
                    source="script_static",
                    priority_sink_hints=[sink_hint],
                    score=88 if sinkish else 62,
                )
            )
            if field in ("url", "value", "action", "data"):
                _add(
                    ClobberCandidate(
                        property_path=f"{resolved_root}.{field}",
                        root_name=resolved_root,
                        nested_name=field,
                        source="script_static",
                        priority_sink_hints=[sink_hint],
                        score=90 if sinkish else 65,
                    )
                )

    # Element ids/names alone are weak; prefer script-backed candidates.
    out = [c for c in scored.values() if c.source == "script_static" or c.score >= 55]
    if not out:
        out = list(scored.values())
    out = sorted(out, key=lambda c: (-c.score, c.property_path))
    return out[: max(1, int(max_candidates))]


def merge_browser_inventory(
    static: Sequence[ClobberCandidate],
    browser_props: Iterable[str],
    *,
    max_candidates: int = 32,
) -> List[ClobberCandidate]:
    """Merge browser-enumerated named properties into the candidate set."""
    scored: Dict[str, ClobberCandidate] = {c.property_path: c for c in static}
    for raw in browser_props or []:
        name = str(raw or "").strip()
        if not name or "." in name:
            continue
        if name in _IGNORED_ROOTS or name.startswith("VCIM_") or name.startswith("VCXSS_"):
            continue
        root = name
        prev = scored.get(name)
        cand = ClobberCandidate(
            property_path=name,
            root_name=root,
            nested_name="",
            source="browser_inventory",
            score=50 if prev is None else max(prev.score, 50),
            priority_sink_hints=list(prev.priority_sink_hints) if prev else [],
        )
        if prev is None or cand.score >= prev.score:
            if prev and prev.priority_sink_hints and not cand.priority_sink_hints:
                cand.priority_sink_hints = list(prev.priority_sink_hints)
            scored[name] = cand
    return sorted(scored.values(), key=lambda c: (-c.score, c.property_path))[:max_candidates]


def random_noncolliding_id(existing: Set[str], prefix: str = "vcNon") -> str:
    for _ in range(16):
        cand = f"{prefix}_{secrets.token_hex(6)}"
        if cand not in existing and cand not in _IGNORED_ROOTS:
            return cand
    return f"{prefix}_{secrets.token_hex(10)}"
