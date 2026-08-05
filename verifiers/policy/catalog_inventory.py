"""Catalog-driven inventory eligibility (path-independent).

Production inventory is derived from runtime ``/catalog.json`` (or equivalent)
entry metadata — tags and family fields — never from benchmark path tables or
fixture route maps.

Partial / incomplete subtypes are excluded when catalog tags lack an intensity
or control profile beyond bare ``active`` discovery markers.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Set


# Profile / intensity tags that mark a catalog entry as Phase-1 inventory-eligible
# for executable families. Path names are never consulted.
_INVENTORY_PROFILE_TAGS: Set[str] = {
    "safe",
    "control",
    "extended",
    "fp-guard",
    "dom-clobber",
    "oob",
}

# Tags that only indicate discovery surface, not inventory completeness.
_DISCOVERY_ONLY_TAGS: Set[str] = {
    "active",
    "passive",
    "browser",
    "post",
    "enum",
    "api",
    "robots",
    "secrets",
    "backup",
}


def _tags(entry: Mapping[str, Any]) -> Set[str]:
    raw = entry.get("tags") or entry.get("catalog_tags") or []
    return {str(t).lower() for t in raw}


def _family(entry: Mapping[str, Any]) -> str:
    tags = _tags(entry)
    fam = str(entry.get("family") or entry.get("probe_family") or "").lower()
    if "dom-clobber" in tags or "dom_clobber" in fam:
        return "dom_clobber"
    return fam


def catalog_entry_demotion_reason(entry: Mapping[str, Any]) -> str:
    """Return a demotion reason when the catalog entry is not inventory-active.

    Empty string means no demotion from catalog metadata alone.
    """
    if not isinstance(entry, Mapping):
        return "invalid_catalog_entry"
    tags = _tags(entry)
    if "partial" in tags:
        return "catalog_marked_partial"
    # Explicit passive-only (no active intensity) stays out of supported_active.
    if "passive" in tags and "active" not in tags and not (tags & _INVENTORY_PROFILE_TAGS):
        return "catalog_passive_only"

    fam = _family(entry)
    # XSS subtypes: require a profile/intensity tag, or lab+browser (executable
    # browser XSS ladder). Bare active / active+browser / active+post+lab alone
    # are discovery markers for incomplete subtypes — not inventory-active.
    if fam == "xss":
        profile = tags & _INVENTORY_PROFILE_TAGS
        if profile:
            return ""
        if "lab" in tags and "browser" in tags:
            return ""
        if "lab" in tags and "post" in tags and "browser" not in tags:
            return "xss_multi_request_subtype_not_inventory"
        if tags <= (_DISCOVERY_ONLY_TAGS | {"lab"}):
            return "xss_subtype_lacks_intensity_profile"
        if not profile:
            return "xss_subtype_lacks_intensity_profile"
    return ""


def inventory_eligible_from_catalog_entry(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Summarize catalog-driven inventory eligibility for one entry."""
    reason = catalog_entry_demotion_reason(entry)
    return {
        "eligible": not bool(reason),
        "demotion_reason": reason,
        "family": _family(entry),
        "tags": sorted(_tags(entry)),
    }
