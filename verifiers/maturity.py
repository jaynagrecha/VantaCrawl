"""Capability maturity assessment for Phase-1 verifiers.

Distinguishes contract-only / registered adapters from executable production
capability and live-validated results. Benchmark inventory must not mark a
fixture supported_active merely because a family contract or registry entry
exists.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from verifiers.registry import capability_registry, get_verifier

MATURITY_CONTRACT_ONLY = "contract_only"
MATURITY_REGISTERED_ADAPTER = "registered_adapter"
MATURITY_EXECUTABLE_UNVALIDATED = "executable_unvalidated"
MATURITY_LIVE_VALIDATED = "live_validated"

# Production modules that own executable lifecycle stages (not Horizon-specific).
# Dom-clobber has a dedicated package; other Phase-1 families are executed by
# the shared active-probe kit with family-specific evidence contracts.
_FAMILY_IMPL: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("sqli_error", "sqli_boolean", "sqli_time"),
    },
    "rce": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("rce",),
    },
    "command_injection": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("rce",),
        "alias_of": "rce",
    },
    "ssti": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("ssti",),
    },
    "xss": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("xss",),
        # Subtypes that are routed/probed but lack full browser confirmation ladder
        # remain executable_unvalidated until live-validated; inventory still requires
        # concrete kit coverage (not contract alone).
    },
    "ssrf": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("ssrf",),
        "requires": ("callback_base_or_oob",),
    },
    "redirect": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("redirect",),
    },
    "open_redirect": {
        "module": "active_probe_kit",
        "alias_of": "redirect",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("redirect",),
    },
    "traversal": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("traversal", "traversal_diff"),
        "requires": ("traversal_canary_or_diff",),
    },
    "lfi": {
        "module": "active_probe_kit",
        "alias_of": "traversal",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("traversal", "traversal_diff"),
    },
    "crlf": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("crlf",),
    },
    "header_injection": {
        "module": "active_probe_kit",
        "alias_of": "crlf",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("crlf",),
    },
    "csrf": {
        "module": "active_probe_kit",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": False,  # kit CSRF path is limited / not full reproduce ladder
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": ("csrf",),
        "partial": True,
    },
    "dom_clobber": {
        "module": "dom_clobber.verify",
        "stages": {
            "discovery": True,
            "input_modelling": True,
            "request_construction": True,
            "baseline": True,
            "negative_control": True,
            "replay": True,
            "proof_contract": True,
            "finding_emission": True,
        },
        "kit_kinds": (),
        "requires": ("browser", "callback_base_or_oob"),
    },
}

# Live-validated capability ids (in-memory only in production).
# Benchmark code may call load_live_validated_from_file() explicitly.
_LIVE_VALIDATED: Set[str] = set()


def load_live_validated_from_file(path: Path) -> None:
    """Optional explicit loader — callers may pass a benchmark evidence file."""
    try:
        if not path.is_file():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for item in data:
                if item:
                    _LIVE_VALIDATED.add(str(item))
        elif isinstance(data, dict):
            for item in data.get("capability_ids") or []:
                if item:
                    _LIVE_VALIDATED.add(str(item))
    except Exception:
        return


def mark_live_validated(capability_id: str) -> None:
    if capability_id:
        _LIVE_VALIDATED.add(str(capability_id))


def clear_live_validated(*, clear_persisted: bool = False) -> None:
    _LIVE_VALIDATED.clear()
    # clear_persisted retained for API compatibility; production keeps no
    # Horizon-coupled on-disk maturity marks.
    _ = clear_persisted


def reload_live_validated() -> None:
    """Clear in-memory marks. Persisted reload is explicit via load_live_validated_from_file."""
    _LIVE_VALIDATED.clear()


def live_validated_ids() -> Set[str]:
    return set(_LIVE_VALIDATED)


def _normalize_family(family: str) -> str:
    fam = (family or "").strip().lower()
    aliases = {
        "command_injection": "rce",
        "cmdi": "rce",
        "open_redirect": "redirect",
        "lfi": "traversal",
        "header_injection": "crlf",
        "dom-clobber": "dom_clobber",
    }
    return aliases.get(fam, fam)


def _method_is_stub(method: Any) -> bool:
    """Heuristic: empty body / only pass / return None / return []."""
    try:
        src = textwrap.dedent(inspect.getsource(method))
    except (OSError, TypeError):
        return False
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    fn = next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if fn is None:
        return False
    body = list(fn.body)
    # Drop docstring
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(getattr(body[0], "value", None), ast.Constant)
    ):
        body = body[1:]
    if not body:
        return True
    if len(body) == 1:
        n = body[0]
        if isinstance(n, ast.Pass):
            return True
        if isinstance(n, ast.Return):
            if n.value is None:
                return True
            if isinstance(n.value, ast.Constant) and n.value.value in (None, [], (), {}):
                return True
            if isinstance(n.value, ast.List) and not n.value.elts:
                return True
            if isinstance(n.value, ast.Tuple) and not n.value.elts:
                return True
            if isinstance(n.value, ast.Dict) and not n.value.keys:
                return True
    return False


def assess_verifier_class(family: str) -> Dict[str, Any]:
    """Inspect registered verifier for executable methods vs adapter stubs."""
    fam = _normalize_family(family)
    v = get_verifier(fam)
    if v is None:
        return {
            "family": fam,
            "registered": False,
            "capability_id": "",
            "implementation_module": "",
            "implementation_status": "missing",
            "executable_methods": False,
            "adapter_only": False,
        }
    exec_stub = _method_is_stub(v.execute)
    collect_stub = _method_is_stub(v.collect_evidence)
    probes = []
    try:
        from verifiers.base import Candidate

        probes = v.build_probes(
            Candidate(family=fam, parameter="x", channel="query", url="https://example.test/?x=1"),
            "lab",
        )
    except Exception:
        probes = []
    controls = []
    try:
        from verifiers.base import Candidate

        controls = v.build_controls(
            Candidate(family=fam, parameter="x", channel="query", url="https://example.test/?x=1")
        )
    except Exception:
        controls = []

    impl = _FAMILY_IMPL.get(fam) or {}
    module = str(impl.get("module") or type(v).__module__)
    # Adapter-only: registered classify wrapper whose execute/collect are stubs
    # and lifecycle is delegated (dom_clobber package / kit).
    adapter_only = bool(exec_stub or (not probes and fam != "dom_clobber"))
    if fam == "dom_clobber":
        # Dedicated package owns execution; registry class is a thin adapter.
        adapter_only = True
        module = "dom_clobber.verify"
        executable_via_module = True
    else:
        executable_via_module = bool(impl.get("stages", {}).get("request_construction"))

    return {
        "family": fam,
        "registered": True,
        "capability_id": v.capability_id,
        "implementation_module": module,
        "implementation_status": (
            "dedicated_package"
            if fam == "dom_clobber"
            else ("kit_backed" if executable_via_module else "adapter")
        ),
        "executable_methods": (not exec_stub) or executable_via_module,
        "execute_is_stub": exec_stub,
        "collect_is_stub": collect_stub,
        "has_probes": bool(probes),
        "has_controls": bool(controls),
        "adapter_only": adapter_only and not executable_via_module,
        "stages": dict(impl.get("stages") or {}),
        "requires": list(impl.get("requires") or []),
        "partial_family": bool(impl.get("partial")),
    }


def assess_capability_maturity(
    family: str,
    *,
    path: str = "",
    path_demotion_reason: str = "",
    live_validated_override: Optional[bool] = None,
) -> Dict[str, Any]:
    """Return maturity + support eligibility for one family/capability.

    ``path`` is accepted for API compatibility with callers that still pass a
    surface path, but maturity classification must not branch on catalog route
    names. Fixture-specific demotions belong in the benchmark inventory layer
    and are supplied via ``path_demotion_reason``.
    """
    _ = path  # unused — do not demote by catalog route inside production code
    fam = _normalize_family(family)

    assessed = assess_verifier_class(fam)
    cap_id = assessed.get("capability_id") or ""
    stages = assessed.get("stages") or {}
    missing_stages = [k for k, ok in stages.items() if not ok]

    path_reason = (path_demotion_reason or "").strip()

    live = bool(live_validated_override)
    if live_validated_override is None:
        live = bool(cap_id and cap_id in _LIVE_VALIDATED)
        # Also accept family-level live marks
        live = live or (f"family:{fam}" in _LIVE_VALIDATED)

    if not assessed.get("registered") and fam not in _FAMILY_IMPL:
        maturity = MATURITY_CONTRACT_ONLY
        eligible = False
        reason = "no_registered_verifier_and_no_impl_map"
    elif not assessed.get("executable_methods"):
        maturity = MATURITY_REGISTERED_ADAPTER if assessed.get("registered") else MATURITY_CONTRACT_ONLY
        eligible = False
        reason = "registered_without_executable_lifecycle"
    elif assessed.get("adapter_only") and not assessed.get("executable_methods"):
        maturity = MATURITY_REGISTERED_ADAPTER
        eligible = False
        reason = "adapter_classify_only"
    elif path_reason:
        # Still has family executability, but this fixture subtype is not fully covered
        maturity = MATURITY_REGISTERED_ADAPTER
        eligible = False
        reason = path_reason
    elif assessed.get("partial_family") and missing_stages:
        maturity = MATURITY_REGISTERED_ADAPTER
        eligible = False
        reason = f"incomplete_lifecycle:{','.join(missing_stages)}"
    elif live:
        maturity = MATURITY_LIVE_VALIDATED
        eligible = True
        reason = "live_lifecycle_validated"
    else:
        maturity = MATURITY_EXECUTABLE_UNVALIDATED
        eligible = True
        reason = "executable_production_path_unvalidated_live"

    # Hard rule: contract_only / registered_adapter never supported_active
    if maturity in (MATURITY_CONTRACT_ONLY, MATURITY_REGISTERED_ADAPTER):
        eligible = False

    return {
        **assessed,
        "capability_maturity": maturity,
        "supported_active_eligible": eligible,
        "maturity_reason": reason,
        "missing_lifecycle_stages": missing_stages,
        "path_demotion": path_reason,
    }


def classify_support_from_maturity(
    *,
    bucket: str,
    family: str,
    path: str = "",
    path_demotion_reason: str = "",
    prior_cap_id: str = "",
) -> Dict[str, Any]:
    """Map bucket + maturity → support_classification.

    Bucket string values match the benchmark manifest constants but are
    compared as plain strings so production code does not import the benchmark.
    """
    # Keep in sync with benchmark manifest bucket string values.
    bucket_passive = "passive_manual"
    bucket_unsupported = "unsupported"

    mat = assess_capability_maturity(
        family,
        path_demotion_reason=path_demotion_reason,
    )
    cap_id = mat.get("capability_id") or prior_cap_id or ""

    if bucket == bucket_unsupported:
        support = "unsupported"
        reason = mat.get("maturity_reason") or "bucket_unsupported"
    elif bucket == bucket_passive:
        support = "passive_manual"
        reason = "bucket_passive_manual"
    elif mat.get("supported_active_eligible"):
        support = "supported_active"
        reason = mat.get("maturity_reason") or ""
    elif mat.get("capability_maturity") == MATURITY_CONTRACT_ONLY:
        support = "unsupported"
        reason = mat.get("maturity_reason") or "contract_only"
    else:
        # registered_adapter / incomplete → passive_manual (not active recall)
        support = "passive_manual"
        reason = mat.get("maturity_reason") or "not_executable_active"

    return {
        "support_classification": support,
        "capability_maturity": mat["capability_maturity"],
        "verifier_capability_id": cap_id,
        "verifier_implementation_module": mat.get("implementation_module") or "",
        "implementation_status": mat.get("implementation_status") or "",
        "discovery_support": bool((mat.get("stages") or {}).get("discovery")),
        "input_modelling_support": bool((mat.get("stages") or {}).get("input_modelling")),
        "request_construction_support": bool((mat.get("stages") or {}).get("request_construction")),
        "baseline_implementation": bool((mat.get("stages") or {}).get("baseline")),
        "negative_control_implementation": bool((mat.get("stages") or {}).get("negative_control")),
        "replay_implementation": bool((mat.get("stages") or {}).get("replay")),
        "proof_contract": bool((mat.get("stages") or {}).get("proof_contract")),
        "finding_emission_implementation": bool((mat.get("stages") or {}).get("finding_emission")),
        "classification_reason": reason,
        "missing_lifecycle_stages": list(mat.get("missing_lifecycle_stages") or []),
        "maturity_detail": mat,
        "path": path,
    }
