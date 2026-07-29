"""Discover Phase-1 candidate surfaces from a completed CrawlStats scan.

Family assignment comes from probe_class / finding category already assigned by
the scanner — never from hardcoded catalog routes or fixture IDs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from verifiers.maturity import MATURITY_EXECUTABLE_UNVALIDATED, assess_capability_maturity
from verifiers.registry import get_verifier
from verifiers.runtime.execution_plan import (
    CandidateSurface,
    normalize_family,
)


PHASE1_FAMILIES = frozenset(
    {
        "sqli",
        "rce",
        "ssti",
        "xss",
        "ssrf",
        "redirect",
        "traversal",
        "crlf",
        "csrf",
        "dom_clobber",
    }
)


def _path_of(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _stable_id(path: str, family: str, parameter: str = "") -> str:
    base = f"cand:{path}:{family}"
    if parameter:
        base += f":{parameter}"
    return base


def _controlish(url: str, probe_name: str = "", result_state: str = "", tags: Optional[Set[str]] = None) -> bool:
    """Generic control detection — probe roles/tags only, no catalog path hardcodes."""
    name = (probe_name or "").lower()
    tagset = {str(t).lower() for t in (tags or set())}
    if "control" in tagset or "fp-guard" in tagset:
        return True
    if "control" in name or "nonce_control" in name or name.endswith("_safe"):
        return True
    u = (url or "").rstrip("/").lower()
    # Generic naming: leaf segment "safe" is a common negative-control convention
    leaf = u.rsplit("/", 1)[-1] if u else ""
    if leaf == "safe" or u.endswith("/safe"):
        return True
    return False


def surfaces_from_target_catalog(
    catalog: List[Dict[str, Any]],
    *,
    base_url: str = "",
) -> List[CandidateSurface]:
    """Convert a target-hosted catalog.json-style inventory into Phase-1 surfaces.

    Family and control tags come from the target document — not from hardcoded
    fixture paths. Incomplete subtypes may still appear; maturity classification
    decides supported_active vs passive.
    """
    out: List[CandidateSurface] = []
    origin = (base_url or "").rstrip("/")
    seen: Set[str] = set()
    for entry in catalog or []:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        if not path.startswith("/"):
            continue
        tags = {str(t).lower() for t in (entry.get("tags") or entry.get("catalog_tags") or [])}
        fam = normalize_family(str(entry.get("family") or entry.get("probe_family") or ""))
        if "dom-clobber" in tags or "dom_clobber" in fam or fam.replace("-", "_") == "dom_clobber":
            fam = "dom_clobber"
        if fam not in PHASE1_FAMILIES:
            continue
        matured = assess_capability_maturity(fam)
        from verifiers.maturity import classify_support_from_maturity

        support = classify_support_from_maturity(
            bucket="supported" if ("active" in tags or "safe" in tags or "lab" in tags or "extended" in tags or "control" in tags or "oob" in tags or "dom-clobber" in tags) else "passive",
            family=fam,
            path=path,
            path_demotion_reason="",
        )
        if support.get("support_classification") != "supported_active":
            continue
        is_control = _controlish(path, tags=tags) or str(entry.get("classification") or "").lower() == "control"
        # Catalog intensity tags mean "included from this suite upward", not exclusive.
        # e.g. tag "safe" ⇒ available in safe/extended/lab; tag "lab" alone ⇒ lab only.
        _order = ("safe", "extended", "lab")
        present = [m for m in _order if m in tags]
        if present:
            lowest = min(_order.index(m) for m in present)
            mode_tags = list(_order[lowest:])
        else:
            mode_tags = []
        methods = entry.get("methods") or [entry.get("method") or "GET"]
        method = str(methods[0] if isinstance(methods, list) and methods else "GET").upper()
        cid = _stable_id(path, fam)
        if cid in seen:
            continue
        seen.add(cid)
        url = f"{origin}{path}" if origin else path
        out.append(
            CandidateSurface(
                candidate_id=cid,
                url=url,
                path=path,
                method=method,
                family=fam,
                probe_family=fam,
                parameter=str(entry.get("parameter") or ""),
                classification="control" if is_control else "vulnerable",
                must_not_confirm=is_control or bool(entry.get("must_not_confirm")),
                modes=mode_tags,
                support_classification="supported_active",
                capability_maturity=MATURITY_EXECUTABLE_UNVALIDATED,
                capability_id=(get_verifier(fam).capability_id if get_verifier(fam) else ""),
                input_channels=sorted(
                    {
                        *(["browser"] if "browser" in tags else []),
                        *(["form"] if method == "POST" or "post" in tags else []),
                        *(["oob"] if "oob" in tags else []),
                        "query",
                    }
                ),
                form_fields=[],
                verifier_implementation_module=str(matured.get("implementation_module") or ""),
            )
        )
    return out


def discover_surfaces_from_stats(
    stats: Any,
    *,
    mode: str = "safe",
    scan_id: str = "",
) -> List[CandidateSurface]:
    """Build unique Phase-1 surfaces from request ledger, forms, findings, and optional catalog."""
    ledger = list(getattr(stats, "request_ledger", None) or [])
    findings = list(getattr(stats, "findings", None) or [])
    forms = list(getattr(stats, "forms", None) or [])

    by_key: Dict[str, CandidateSurface] = {}

    def upsert(
        *,
        url: str,
        family: str,
        parameter: str = "",
        method: str = "GET",
        classification: str = "vulnerable",
        must_not: bool = False,
        form_fields: Optional[List[str]] = None,
        channels: Optional[List[str]] = None,
        modes: Optional[List[str]] = None,
        from_ledger: bool = False,
    ) -> None:
        fam = normalize_family(family)
        if fam not in PHASE1_FAMILIES:
            return
        matured = assess_capability_maturity(fam)
        if get_verifier(fam) is None and not matured.get("registered"):
            if not matured.get("executable_methods"):
                return
        from verifiers.maturity import classify_support_from_maturity

        path = _path_of(url)
        cid = _stable_id(path, fam)
        support = classify_support_from_maturity(
            bucket="supported",
            family=fam,
            path=path,
            path_demotion_reason="",
        )
        support_cls = str(support.get("support_classification") or "")
        # Only Phase-1 supported_active enter the plan. Ledger evidence alone does not
        # promote a passive/incomplete family (e.g. CSRF) into supported_active.
        if support_cls != "supported_active" and not from_ledger:
            return
        if support_cls != "supported_active" and from_ledger:
            # Active probe already ran — still require executable maturity.
            if not matured.get("executable_methods") or matured.get("capability_maturity") in (
                "contract_only",
                "registered_adapter",
            ):
                return
        existing = by_key.get(cid)
        if existing is None:
            by_key[cid] = CandidateSurface(
                candidate_id=cid,
                url=url,
                path=path,
                method=method or "GET",
                family=fam,
                probe_family=fam,
                parameter=parameter or "",
                classification=classification,
                must_not_confirm=must_not,
                modes=list(modes or []),
                support_classification="supported_active",
                capability_maturity=MATURITY_EXECUTABLE_UNVALIDATED,
                capability_id=(get_verifier(fam).capability_id if get_verifier(fam) else ""),
                input_channels=list(channels or []),
                form_fields=list(form_fields or []),
                verifier_implementation_module=str(matured.get("implementation_module") or ""),
            )
        else:
            if url and not existing.url:
                existing.url = url
            if parameter and not existing.parameter:
                existing.parameter = parameter
            if form_fields:
                existing.form_fields = sorted(set(existing.form_fields) | set(form_fields))
            if channels:
                existing.input_channels = sorted(set(existing.input_channels) | set(channels))
            if must_not:
                existing.must_not_confirm = True
                existing.classification = "control"

    # Optional target-hosted catalog (e.g. /catalog.json) — production-neutral.
    catalog = list(getattr(stats, "target_catalog", None) or [])
    if catalog:
        base = ""
        try:
            for u in list(getattr(stats, "discovered_urls", None) or [])[:5]:
                if str(u).startswith("http"):
                    p = urlparse(str(u))
                    base = f"{p.scheme}://{p.netloc}"
                    break
        except Exception:
            base = ""
        for surf in surfaces_from_target_catalog(catalog, base_url=base):
            by_key[surf.candidate_id] = surf

    # Active-probe ledger is authoritative for family + roles
    for row in ledger:
        if str(row.get("phase") or "") != "active_probe":
            continue
        probe_class = str(row.get("probe_class") or "")
        if probe_class in ("baseline", "nonce_control", ""):
            continue
        fam = normalize_family(probe_class)
        if fam not in PHASE1_FAMILIES:
            continue
        url = str(row.get("url") or row.get("final_url") or "")
        if not url:
            continue
        param = str(row.get("parameter") or "")
        method = str(row.get("method") or "GET")
        must_not = _controlish(url, str(row.get("probe_name") or ""), str(row.get("result_state") or ""))
        role = str(row.get("probe_role") or "")
        channels = []
        if role.startswith("browser") or "browser" in str(row.get("result_state") or ""):
            channels.append("browser")
        if method.upper() == "POST" or role == "form_submit":
            channels.append("form")
        upsert(
            url=url,
            family=fam,
            parameter=param,
            method=method,
            classification="control" if must_not else "vulnerable",
            must_not=must_not,
            channels=channels,
            form_fields=[param] if method.upper() == "POST" and param else None,
            from_ledger=True,
        )

    # Forms: attach field names onto already-known Phase-1 surfaces (catalog/ledger).
    # Do not invent new CSRF/XSS candidates from every HTML form on the site.
    for form in forms:
        if not isinstance(form, dict):
            continue
        action = str(form.get("action") or form.get("url") or "")
        if not action:
            continue
        fields = form.get("fields") or form.get("inputs") or []
        names: List[str] = []
        if isinstance(fields, dict):
            names = [str(k) for k in fields.keys()]
        elif isinstance(fields, list):
            for f in fields:
                if isinstance(f, dict):
                    names.append(str(f.get("name") or f.get("id") or ""))
                else:
                    names.append(str(f))
        names = [n for n in names if n]
        path = _path_of(action)
        for surf in list(by_key.values()):
            if surf.path == path and names:
                surf.form_fields = sorted(set(surf.form_fields) | set(names))
                if "form" not in surf.input_channels:
                    surf.input_channels = sorted(set(surf.input_channels) | {"form"})

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        cat = str(finding.get("category") or finding.get("family") or "")
        fam = normalize_family(cat)
        if fam not in PHASE1_FAMILIES:
            continue
        url = str(finding.get("url") or "")
        if not url:
            continue
        upsert(url=url, family=fam, classification="vulnerable")

    surfaces = list(by_key.values())
    _ = mode
    _ = scan_id
    return surfaces
