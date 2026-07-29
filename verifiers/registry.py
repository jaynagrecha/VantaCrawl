"""Verifier capability registry — keyed by family, never by Horizon path."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Type

from verifiers.base import VulnerabilityVerifier

# Populated by register() and phase1_families import
_REGISTRY: Dict[str, VulnerabilityVerifier] = {}
_CAPABILITIES: Dict[str, Dict[str, object]] = {}


def register(verifier: Any) -> Any:
    """Register a verifier instance or class."""
    inst: VulnerabilityVerifier
    if isinstance(verifier, type):
        inst = verifier()
    else:
        inst = verifier
    _REGISTRY[inst.family] = inst
    _CAPABILITIES[inst.capability_id] = {
        "capability_id": inst.capability_id,
        "family": inst.family,
        "supported_modes": list(inst.supported_modes),
        "phase": int(inst.phase),
        "class": type(inst).__name__,
    }
    return verifier


def get_verifier(family: str) -> Optional[VulnerabilityVerifier]:
    fam = (family or "").strip().lower()
    if fam in _REGISTRY:
        return _REGISTRY[fam]
    # Aliases
    aliases = {
        "command_injection": "rce",
        "cmdi": "rce",
        "open_redirect": "redirect",
        "lfi": "traversal",
        "header_injection": "crlf",
        "dom_clobber": "dom_clobber",
        "dom-clobber": "dom_clobber",
    }
    mapped = aliases.get(fam)
    if mapped and mapped in _REGISTRY:
        return _REGISTRY[mapped]
    return None


def all_verifiers() -> List[VulnerabilityVerifier]:
    return list(_REGISTRY.values())


def capability_registry() -> Dict[str, Dict[str, object]]:
    # Ensure phase-1 verifiers are loaded
    from verifiers import phase1  # noqa: F401

    return dict(_CAPABILITIES)


def supported_families(phase: Optional[int] = None) -> List[str]:
    from verifiers import phase1  # noqa: F401

    out = []
    for v in _REGISTRY.values():
        if phase is not None and int(v.phase) > int(phase):
            continue
        out.append(v.family)
    return sorted(set(out))
