"""Proof bundles + verification-gated severity for findings.

Severity must not jump to Medium+ on mere detection. Ladder:

  DETECTED → VERIFIED → EXPLOITABLE → CONFIRMED

Only VERIFIED+ may raise above the detection ceiling (usually info/low).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Tuple

# Detection ceiling: unverified detections stay at/below this unless verified
_DETECTION_CEILING = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_STATUS_RANK = {
    "detected": 0,
    "verified": 1,
    "exploitable": 2,
    "confirmed": 3,
}


@dataclass
class FindingProof:
    request: str = ""
    response: str = ""
    evidence: str = ""
    impact: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {
            "request": (self.request or "")[:2000],
            "response": (self.response or "")[:2000],
            "evidence": (self.evidence or "")[:2000],
            "impact": (self.impact or "")[:1000],
        }

    def summary_line(self) -> str:
        parts = []
        if self.evidence:
            parts.append(f"evidence={self.evidence[:180]}")
        if self.request:
            parts.append(f"req={self.request[:120]}")
        if self.response:
            parts.append(f"resp={self.response[:120]}")
        return " | ".join(parts)


def gate_severity(
    proposed: str,
    *,
    verification: str = "detected",
    detection_severity: str = "info",
) -> str:
    """Cap severity until verification advances.

    - detected: max(detection_severity, info) but never above low unless detection was already medium from a prior confirm path
    - verified: up to medium
    - exploitable/confirmed: allow proposed fully
    """
    prop = (proposed or "info").lower()
    ver = (verification or "detected").lower()
    det = (detection_severity or "info").lower()
    if ver not in _STATUS_RANK:
        ver = "detected"
    if ver == "detected":
        # Detection alone → info/low
        ceiling = "low"
        return prop if _DETECTION_CEILING.get(prop, 0) <= _DETECTION_CEILING[ceiling] else ceiling
    if ver == "verified":
        ceiling = "medium"
        return prop if _DETECTION_CEILING.get(prop, 0) <= _DETECTION_CEILING[ceiling] else ceiling
    # exploitable / confirmed — allow full proposed (still trust caller)
    return prop


def enrich_finding_row(
    row: Dict[str, Any],
    *,
    verification: str = "detected",
    proof: Optional[FindingProof] = None,
    confidence: str = "",
    confidence_reason: str = "",
) -> Dict[str, Any]:
    """Attach proof/verification fields onto a finding row dict."""
    out = dict(row)
    ver = (verification or "detected").lower()
    out["verification"] = ver
    out["validation"] = out.get("validation") or ver
    if proof is not None:
        pdata = proof.as_dict()
        out["proof"] = pdata
        if pdata.get("evidence") and not out.get("evidence"):
            out["evidence"] = pdata["evidence"]
        if pdata.get("impact") and not out.get("impact_summary"):
            out["impact_summary"] = pdata["impact"]
    if confidence:
        out["confidence"] = confidence
    if confidence_reason:
        out["confidence_reason"] = confidence_reason
    # Re-gate severity
    out["severity"] = gate_severity(
        str(out.get("severity") or "info"),
        verification=ver,
        detection_severity="info",
    )
    return out


def proof_from_http(
    *,
    method: str,
    url: str,
    status: int = 0,
    body_snippet: str = "",
    evidence: str = "",
    impact: str = "",
    request_extra: str = "",
    response_headers: str = "",
) -> FindingProof:
    req = f"{method.upper()} {url}"
    if request_extra:
        req = f"{req}\n{request_extra}" if "\n" in request_extra or ":" in request_extra else f"{req} | {request_extra}"
    resp = f"HTTP {status}"
    if response_headers:
        resp = f"{resp}\n{response_headers}"
    if body_snippet:
        snippet = re_sub_ws(body_snippet)[:400]
        resp = f"{resp}\n{snippet}" if response_headers else f"{resp}: {snippet}"
    return FindingProof(request=req, response=resp, evidence=evidence, impact=impact)


def proof_has_http_exchange(proof: Any) -> bool:
    """True when proof carries non-empty raw request and response (required for confirmed)."""
    if proof is None:
        return False
    if isinstance(proof, FindingProof):
        return bool((proof.request or "").strip() and (proof.response or "").strip())
    if isinstance(proof, dict):
        return bool(str(proof.get("request") or "").strip() and str(proof.get("response") or "").strip())
    return False


def downgrade_unproven_confirmation(
    *,
    validation: str,
    verification: str = "",
    proof: Any = None,
) -> tuple[str, str]:
    """Confirmed findings without request/response proof become unverified/detected."""
    val = (validation or "").lower()
    ver = (verification or "").lower()
    if val == "confirmed" and not proof_has_http_exchange(proof):
        return "unverified", "detected"
    if ver == "confirmed" and not proof_has_http_exchange(proof):
        return (val if val and val != "confirmed" else "unverified"), "detected"
    return validation, verification or validation


def re_sub_ws(text: str) -> str:
    import re

    return re.sub(r"\s+", " ", (text or "").strip())
