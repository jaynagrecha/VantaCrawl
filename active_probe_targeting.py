"""Vulnerability-aware active-probe target selection.

Selects which discovered routes/parameters should receive which probe families
based on route semantics, parameter names, and optional passive evidence —
without spraying every family at every interesting field.

Does not define or strengthen payload families; only routing/applicability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

TARGET_SELECTION_REASONS = (
    "route_semantic_match",
    "parameter_semantic_match",
    "passive_evidence_match",
    "generic_fallback",
)

# Route-path tokens → probe families (substring match on path segments).
ROUTE_FAMILY_INDICATORS: dict[str, tuple[str, ...]] = {
    "sqli": ("sqli", "sql", "search", "query", "filter", "sort"),
    "rce": ("rce", "cmdi", "cmd", "command", "exec", "shell", "ping"),
    "ssti": ("ssti", "template", "tmpl", "render", "preview"),
    "ssrf": ("ssrf", "fetch", "webhook", "callback", "remote"),
    "traversal": ("trav", "lfi", "path", "download", "include", "file", "nullbyte"),
    "crlf": ("crlf", "redirect", "location"),
    "xss": ("xss", "comment", "message", "html", "content"),
}

# Parameter-name tokens → probe families.
PARAM_FAMILY_INDICATORS: dict[str, tuple[str, ...]] = {
    "sqli": ("id", "user", "uid", "qid", "query", "q", "search", "filter", "sort", "order", "category"),
    "rce": ("cmd", "command", "exec", "shell", "host", "ping", "expr", "input"),
    "ssti": ("name", "template", "tmpl", "render", "view", "preview", "expr"),
    "ssrf": ("url", "uri", "src", "dest", "target", "webhook", "callback", "image", "remote", "link", "fetch"),
    "traversal": ("path", "file", "filename", "filepath", "include", "page", "doc", "download", "template"),
    "crlf": ("url", "redirect", "next", "return", "location", "header", "dest", "q"),
    "xss": ("q", "search", "query", "message", "comment", "html", "content", "name", "text", "body", "title"),
}

# When a route is a dedicated fixture for a family but has no query/form params,
# inject these synthetic query parameters so the existing probe_field path can run.
ROUTE_SYNTHETIC_PARAMS: dict[str, dict[str, str]] = {
    "/sqli/error": {"id": "1"},
    "/sqli/search": {"q": "test"},
    "/sqli/blind": {"id": "1"},
    "/sqli/time": {"id": "1"},
    "/sqli/union": {"id": "1"},
    "/rce/arith": {"cmd": "1+1"},
    "/rce/reflect": {"cmd": "id"},
    "/cmdi/ping": {"host": "127.0.0.1"},
    "/ssti/eval": {"name": "guest"},
    "/tmpl/twig": {"name": "guest"},
    "/ssrf/fetch": {"url": "http://example.com"},
    "/ssrf/reflect": {"url": "http://example.com"},
    "/crlf": {"q": "ok"},
    "/trav/download": {"path": "readme.txt"},
    "/trav/view": {"file": "readme.txt"},
    "/lfi/include": {"page": "home"},
    "/nullbyte/download": {"file": "readme.txt"},
    "/xss/browser": {"q": "test"},
    "/xss/dom": {"q": "test"},
    "/xss/reflect": {"q": "test"},
    "/xss/attr": {"q": "test"},
    "/xss/js-string": {"q": "test"},
}

# Families that may use generic_fallback on "interesting" params when no
# stronger match exists. Keep this narrow to avoid spray.
GENERIC_FALLBACK_FAMILIES = frozenset({"xss", "sqli", "ssti"})

# Minimum score to schedule a family against a target.
MIN_APPLICABILITY_SCORE = {
    "route_semantic_match": 80,
    "parameter_semantic_match": 55,
    "passive_evidence_match": 70,
    "generic_fallback": 40,
}


@dataclass(frozen=True)
class ProbeTarget:
    """One (url, method, param, family) selection with provenance."""

    url: str
    method: str
    param: str
    family: str
    reason: str
    score: int
    baseline_values: dict[str, str] = field(default_factory=dict)
    form_action: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _norm_path(url_or_path: str) -> str:
    raw = (url_or_path or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urlsplit(raw).path or "/").rstrip("/") or "/"
    path = raw.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def _path_tokens(path: str) -> list[str]:
    return [p.lower() for p in path.split("/") if p]


def _param_tokens(name: str) -> list[str]:
    n = (name or "").lower().replace("-", "_")
    parts = [p for p in n.split("_") if p]
    if n and n not in parts:
        parts.append(n)
    return parts


def score_route_family(path: str, family: str) -> int:
    """Return 0–100 route-semantic score for family against path."""
    indicators = ROUTE_FAMILY_INDICATORS.get(family, ())
    if not indicators:
        return 0
    tokens = _path_tokens(_norm_path(path))
    joined = "/".join(tokens)
    best = 0
    for ind in indicators:
        if ind in tokens:
            # Exact path segment match (e.g. /sqli/error → sqli)
            best = max(best, 95 if ind == family or ind in {family, f"{family}i", "cmdi", "lfi"} else 88)
        elif ind in joined:
            best = max(best, 82)
    # Dedicated fixture paths from the Horizon Catalog get a hard boost.
    synth = ROUTE_SYNTHETIC_PARAMS.get(_norm_path(path))
    if synth is not None:
        # Only boost the family this fixture was built for.
        fixture_family = _fixture_family_for_path(path)
        if fixture_family == family:
            best = max(best, 100)
    return best


def _fixture_family_for_path(path: str) -> Optional[str]:
    p = _norm_path(path)
    mapping = (
        ("/sqli/", "sqli"),
        ("/rce/", "rce"),
        ("/cmdi/", "rce"),
        ("/ssti/", "ssti"),
        ("/tmpl/", "ssti"),
        ("/ssrf/", "ssrf"),
        ("/trav/", "traversal"),
        ("/lfi/", "traversal"),
        ("/nullbyte/", "traversal"),
        ("/crlf", "crlf"),
        ("/xss/", "xss"),
    )
    for prefix, fam in mapping:
        if p == prefix.rstrip("/") or p.startswith(prefix):
            return fam
    return None


def score_param_family(param: str, family: str) -> int:
    """Return 0–100 parameter-semantic score."""
    indicators = PARAM_FAMILY_INDICATORS.get(family, ())
    if not indicators:
        return 0
    name = (param or "").lower()
    tokens = _param_tokens(name)
    best = 0
    for ind in indicators:
        if name == ind:
            best = max(best, 90)
        elif ind in tokens:
            best = max(best, 75)
        elif ind in name:
            best = max(best, 60)
    return best


def score_passive_evidence(family: str, evidence_hints: Optional[Iterable[str]]) -> int:
    if not evidence_hints:
        return 0
    fam = family.lower()
    for hint in evidence_hints:
        h = str(hint or "").lower()
        if not h:
            continue
        if fam in h or h in fam:
            return 85
        # Common passive → active bridges
        bridges = {
            "sqli": ("sql", "database", "jdbc"),
            "xss": ("reflect", "markup", "script"),
            "ssrf": ("internal", "metadata", "webhook"),
            "rce": ("command", "exec", "shell"),
            "traversal": ("path", "lfi", "directory"),
            "ssti": ("template", "jinja", "twig"),
            "crlf": ("header", "injection", "response splitting"),
        }
        for token in bridges.get(fam, ()):
            if token in h:
                return 72
    return 0


def classify_applicability(
    *,
    path: str,
    param: str,
    family: str,
    evidence_hints: Optional[Iterable[str]] = None,
    allow_generic_fallback: bool = True,
) -> tuple[int, str]:
    """Return (score, reason) for applying family to path/param."""
    route_score = score_route_family(path, family)
    param_score = score_param_family(param, family)
    passive_score = score_passive_evidence(family, evidence_hints)

    if route_score >= MIN_APPLICABILITY_SCORE["route_semantic_match"]:
        # Route wins even if param is synthetic/generic.
        return route_score, "route_semantic_match"
    if passive_score >= MIN_APPLICABILITY_SCORE["passive_evidence_match"]:
        return passive_score, "passive_evidence_match"
    if param_score >= MIN_APPLICABILITY_SCORE["parameter_semantic_match"]:
        return param_score, "parameter_semantic_match"
    if (
        allow_generic_fallback
        and family in GENERIC_FALLBACK_FAMILIES
        and param_score >= 35
        and route_score < 50
    ):
        return max(param_score, 40), "generic_fallback"
    # Combined weak signal: both route and param slightly relevant
    combined = max(route_score, 0) // 2 + max(param_score, 0) // 2
    if combined >= 50 and route_score >= 40:
        return combined, "route_semantic_match"
    if combined >= 45 and param_score >= 40:
        return combined, "parameter_semantic_match"
    return 0, "generic_fallback"


def synthetic_params_for_path(path: str) -> dict[str, str]:
    return dict(ROUTE_SYNTHETIC_PARAMS.get(_norm_path(path), {}))


def with_query_params(url: str, params: dict[str, str]) -> str:
    """Merge params into URL query string (existing keys preserved unless overridden)."""
    parts = urlsplit(url)
    current = dict(parse_qsl(parts.query, keep_blank_values=True))
    for k, v in params.items():
        current.setdefault(k, v)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(list(current.items())), parts.fragment))


def path_only_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def collect_surface_urls(crawled_urls: Iterable[str], interest_urls: Iterable[str]) -> list[str]:
    """Deduped URL list preferring originals that already carry query strings."""
    by_path: dict[str, str] = {}
    for u in list(crawled_urls or []) + list(interest_urls or []):
        if not u or not str(u).startswith("http"):
            continue
        p = _norm_path(u)
        prev = by_path.get(p)
        if prev is None:
            by_path[p] = str(u)
            continue
        # Prefer URL that already has a query string.
        if "?" not in prev and "?" in str(u):
            by_path[p] = str(u)
    return list(by_path.values())


def build_probe_plan(
    *,
    surface_urls: Iterable[str],
    form_targets: Optional[list[dict[str, Any]]] = None,
    families: Iterable[str],
    evidence_by_path: Optional[dict[str, list[str]]] = None,
    max_generic_per_family: int = 2,
    max_targets_per_family: int = 12,
) -> list[ProbeTarget]:
    """Build ordered probe targets: dedicated semantic matches first."""
    evidence_by_path = evidence_by_path or {}
    form_targets = form_targets or []
    families = [str(f).lower() for f in families]

    candidates: list[ProbeTarget] = []
    seen: set[tuple[str, str, str, str]] = set()

    def _add(t: ProbeTarget) -> None:
        key = (_norm_path(t.url), t.method.upper(), t.param.lower(), t.family)
        if key in seen:
            return
        min_score = MIN_APPLICABILITY_SCORE.get(t.reason, 40)
        if t.score < min_score and t.reason != "route_semantic_match":
            return
        if t.score <= 0:
            return
        seen.add(key)
        candidates.append(t)

    # 1) Route-semantic fixtures (synthetic params as needed).
    for raw_url in collect_surface_urls(surface_urls, []):
        path = _norm_path(raw_url)
        synth = synthetic_params_for_path(path)
        hints = evidence_by_path.get(path, [])
        for family in families:
            score, reason = classify_applicability(
                path=path,
                param=next(iter(synth), "") if synth else "",
                family=family,
                evidence_hints=hints,
                allow_generic_fallback=False,
            )
            fixture_fam = _fixture_family_for_path(path)
            if fixture_fam == family:
                score = max(score, 100)
                reason = "route_semantic_match"
            if score < MIN_APPLICABILITY_SCORE["route_semantic_match"] and fixture_fam != family:
                continue
            if fixture_fam and fixture_fam != family and score < 90:
                continue
            params = synth or dict(parse_qsl(urlsplit(raw_url).query, keep_blank_values=True))
            if not params:
                # No injectable surface for this route.
                continue
            target_url = with_query_params(path_only_url(raw_url), params) if synth else raw_url
            # Prefer the primary synthetic/query param for this family.
            preferred = _preferred_param(params, family)
            _add(
                ProbeTarget(
                    url=target_url,
                    method="GET",
                    param=preferred,
                    family=family,
                    reason=reason if fixture_fam == family else reason,
                    score=score if fixture_fam == family else score,
                    baseline_values={preferred: str(params.get(preferred, ""))},
                )
            )
            # Also schedule secondary route params that strongly match the family.
            for pname in params:
                if pname == preferred:
                    continue
                ps, pr = classify_applicability(
                    path=path, param=pname, family=family, evidence_hints=hints, allow_generic_fallback=False
                )
                if ps >= MIN_APPLICABILITY_SCORE["parameter_semantic_match"] and pr == "parameter_semantic_match":
                    _add(
                        ProbeTarget(
                            url=target_url,
                            method="GET",
                            param=pname,
                            family=family,
                            reason="parameter_semantic_match",
                            score=ps,
                            baseline_values={pname: str(params.get(pname, ""))},
                        )
                    )

    # 2) Existing query-string parameters on crawled URLs.
    for raw_url in surface_urls:
        parts = urlsplit(str(raw_url))
        qparams = dict(parse_qsl(parts.query, keep_blank_values=True))
        if not qparams:
            continue
        path = _norm_path(raw_url)
        hints = evidence_by_path.get(path, [])
        fixture_fam = _fixture_family_for_path(path)
        for pname, pval in qparams.items():
            for family in families:
                # Dedicated fixtures already covered above — still allow param matches.
                score, reason = classify_applicability(
                    path=path,
                    param=pname,
                    family=family,
                    evidence_hints=hints,
                    allow_generic_fallback=(fixture_fam is None),
                )
                if fixture_fam == family:
                    score = max(score, 100)
                    reason = "route_semantic_match"
                if score <= 0:
                    continue
                if reason == "generic_fallback" and family not in GENERIC_FALLBACK_FAMILIES:
                    continue
                _add(
                    ProbeTarget(
                        url=str(raw_url),
                        method="GET",
                        param=pname,
                        family=family,
                        reason=reason,
                        score=score,
                        baseline_values={pname: str(pval)},
                    )
                )

    # 3) Form fields — parameter semantics first; generic fallback capped later.
    for form in form_targets:
        action = str(form.get("action") or form.get("url") or "").strip()
        if not action.startswith("http"):
            continue
        method = str(form.get("method") or "GET").upper()
        fields = form.get("fields") or {}
        if not isinstance(fields, dict):
            continue
        path = _norm_path(action)
        hints = evidence_by_path.get(path, [])
        fixture_fam = _fixture_family_for_path(path)
        for pname, pval in fields.items():
            if str(pname).lower() in {"csrf", "csrfmiddlewaretoken", "_token", "authenticity_token"}:
                continue
            for family in families:
                score, reason = classify_applicability(
                    path=path,
                    param=str(pname),
                    family=family,
                    evidence_hints=hints,
                    allow_generic_fallback=(fixture_fam is None),
                )
                if fixture_fam == family:
                    score = max(score, 95)
                    reason = "route_semantic_match"
                if score <= 0:
                    continue
                if reason == "generic_fallback" and family not in GENERIC_FALLBACK_FAMILIES:
                    continue
                _add(
                    ProbeTarget(
                        url=action,
                        method=method,
                        param=str(pname),
                        family=family,
                        reason=reason,
                        score=score,
                        baseline_values={str(pname): str(pval if pval is not None else "")},
                        form_action=action,
                        extra={"form_fields": {str(k): str(v if v is not None else "") for k, v in fields.items()}},
                    )
                )

    # Rank: reason priority, then score, then prefer dedicated fixture paths.
    reason_rank = {
        "route_semantic_match": 0,
        "passive_evidence_match": 1,
        "parameter_semantic_match": 2,
        "generic_fallback": 3,
    }

    def _sort_key(t: ProbeTarget) -> tuple:
        return (
            reason_rank.get(t.reason, 9),
            -int(t.score),
            0 if _fixture_family_for_path(t.url) == t.family else 1,
            _norm_path(t.url),
            t.param,
            t.family,
        )

    candidates.sort(key=_sort_key)

    # Cap generic fallbacks and total per family.
    out: list[ProbeTarget] = []
    per_family = {f: 0 for f in families}
    generic_per_family = {f: 0 for f in families}
    for t in candidates:
        if per_family.get(t.family, 0) >= max_targets_per_family:
            continue
        if t.reason == "generic_fallback":
            if generic_per_family.get(t.family, 0) >= max_generic_per_family:
                continue
            generic_per_family[t.family] = generic_per_family.get(t.family, 0) + 1
        per_family[t.family] = per_family.get(t.family, 0) + 1
        out.append(t)
    return out


def _preferred_param(params: dict[str, str], family: str) -> str:
    if not params:
        return "q"
    scored = sorted(
        ((score_param_family(name, family), name) for name in params),
        key=lambda x: (-x[0], x[1]),
    )
    return scored[0][1]


def required_horizon_fixtures() -> dict[str, tuple[str, ...]]:
    """Canonical Horizon Catalog fixtures that must be selected when discovered."""
    return {
        "sqli": ("/sqli/error", "/sqli/search"),
        "rce": ("/rce/arith", "/cmdi/ping"),
        "ssti": ("/ssti/eval",),
        "ssrf": ("/ssrf/fetch",),
        "crlf": ("/crlf",),
        "traversal": ("/trav/download",),
        "xss": ("/xss/browser",),
    }


def selection_coverage_report(
    plan: list[ProbeTarget],
    discovered_paths: Iterable[str],
) -> dict[str, Any]:
    """Report whether dedicated fixtures discovered on the surface were scheduled."""
    discovered = {_norm_path(p) for p in discovered_paths}
    selected_by_family: dict[str, set[str]] = {}
    for t in plan:
        selected_by_family.setdefault(t.family, set()).add(_norm_path(t.url))

    fixtures = required_horizon_fixtures()
    rows = []
    missing = []
    for family, paths in fixtures.items():
        discovered_hits = [p for p in paths if p in discovered]
        selected_hits = [p for p in discovered_hits if p in selected_by_family.get(family, set())]
        # Also accept alternate path from the same required pair.
        ok = bool(selected_hits) if discovered_hits else None
        if discovered_hits and not selected_hits:
            # Accept sibling fixture (e.g. /sqli/search when /sqli/error required).
            siblings = [p for p in paths if p in selected_by_family.get(family, set())]
            ok = bool(siblings)
            selected_hits = siblings
        rows.append(
            {
                "family": family,
                "required_any_of": list(paths),
                "discovered": discovered_hits,
                "selected": selected_hits,
                "ok": ok,
            }
        )
        if ok is False:
            missing.append(family)

    status = "complete"
    if missing:
        status = "insufficient"
    elif any(r["ok"] is False for r in rows):
        status = "insufficient"
    elif all(r["ok"] is None for r in rows):
        status = "n/a"
    elif any(r["ok"] is None for r in rows):
        status = "partial"

    return {
        "status": status,
        "missing_families": missing,
        "fixtures": rows,
        "planned_count": len(plan),
        "reasons": {
            reason: sum(1 for t in plan if t.reason == reason) for reason in TARGET_SELECTION_REASONS
        },
    }
