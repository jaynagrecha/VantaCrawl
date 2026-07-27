"""Route registry for drop-in vulnerability modules."""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

HandlerFn = Callable[..., None]


@dataclass
class RouteSpec:
    path: str
    handler: HandlerFn
    title: str
    family: str
    expected: str
    methods: tuple[str, ...] = ("GET", "POST")
    linked: bool = True
    notes: str = ""
    tags: List[str] = field(default_factory=list)


_ROUTES: Dict[str, RouteSpec] = {}
_PREFIX_ROUTES: List[RouteSpec] = []


def register(
    path: str,
    *,
    title: str,
    family: str,
    expected: str,
    methods: tuple[str, ...] = ("GET", "POST"),
    linked: bool = True,
    notes: str = "",
    tags: Optional[List[str]] = None,
    prefix: bool = False,
) -> Callable[[HandlerFn], HandlerFn]:
    """Decorator: register a playground endpoint.

    Example::

        @register("/demo/ping", title="Ping", family="demo", expected="none")
        def ping(handler, params, *, head_only=False):
            ...
    """

    def deco(fn: HandlerFn) -> HandlerFn:
        spec = RouteSpec(
            path=path,
            handler=fn,
            title=title,
            family=family,
            expected=expected,
            methods=methods,
            linked=linked,
            notes=notes,
            tags=list(tags or []),
        )
        if prefix:
            _PREFIX_ROUTES.append(spec)
            _PREFIX_ROUTES.sort(key=lambda s: len(s.path), reverse=True)
        else:
            _ROUTES[path] = spec
        return fn

    return deco


def all_routes() -> List[RouteSpec]:
    items = list(_ROUTES.values()) + list(_PREFIX_ROUTES)
    items.sort(key=lambda s: (s.family, s.path))
    return items


def linked_index() -> List[RouteSpec]:
    return [s for s in all_routes() if s.linked]


def resolve(path: str) -> Optional[RouteSpec]:
    if path in _ROUTES:
        return _ROUTES[path]
    for spec in _PREFIX_ROUTES:
        if path == spec.path or path.startswith(spec.path.rstrip("/") + "/") or path.startswith(spec.path):
            return spec
    return None


def load_vuln_modules() -> List[str]:
    """Import every module under vuln_playground.vulns to trigger @register."""
    loaded: List[str] = []
    import vulns  # type: ignore

    for mod in pkgutil.iter_modules(vulns.__path__, vulns.__name__ + "."):
        if mod.name.endswith("._base"):
            continue
        importlib.import_module(mod.name)
        loaded.append(mod.name)
    return loaded


def catalog() -> List[Dict[str, Any]]:
    return [
        {
            "path": s.path,
            "title": s.title,
            "family": s.family,
            "expected": s.expected,
            "methods": list(s.methods),
            "linked": s.linked,
            "notes": s.notes,
            "tags": s.tags,
        }
        for s in all_routes()
    ]
