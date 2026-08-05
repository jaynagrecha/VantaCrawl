"""CORS candidate discovery from response headers and surface context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from verifiers.base import Candidate, SurfaceContext
from verifiers.cors.url_safety import origin_of


@dataclass
class CorsObservation:
    url: str
    acao: str = ""
    acac: bool = False
    vary: str = ""
    status: int = 0
    content_type: str = ""
    selection_reasons: List[str] = field(default_factory=list)
    reflected_origin: str = ""
    body_snippet_hash: str = ""
    canary_hint: str = ""


def classify_headers(
    *,
    acao: str,
    acac: bool,
    request_origin: str = "",
) -> List[str]:
    reasons: List[str] = []
    a = (acao or "").strip()
    if not a:
        return reasons
    reasons.append("passive_header_observation")
    if a == "*":
        reasons.append("wildcard_origin")
    if request_origin and a == request_origin:
        reasons.append("reflected_origin")
    if a.lower() == "null":
        reasons.append("null_origin_allowed")
    if acac:
        reasons.append("credentials_allowed")
    if a == "*" and acac:
        reasons.append("wildcard_with_credentials_header")
    return reasons


def observation_from_response(
    url: str,
    headers: Dict[str, Any],
    *,
    request_origin: str = "",
    status: int = 0,
    content_type: str = "",
    canary_hint: str = "",
) -> Optional[CorsObservation]:
    lower = {str(k).lower(): ("" if v is None else str(v)) for k, v in (headers or {}).items()}
    acao = (lower.get("access-control-allow-origin") or "").strip()
    acac_raw = (lower.get("access-control-allow-credentials") or "").strip().lower()
    acac = acac_raw == "true"
    if not acao and not acac:
        return None
    reasons = classify_headers(acao=acao, acac=acac, request_origin=request_origin)
    if not reasons:
        reasons = ["passive_header_observation"]
    return CorsObservation(
        url=url,
        acao=acao,
        acac=acac,
        vary=(lower.get("vary") or "").strip(),
        status=int(status or 0),
        content_type=content_type or lower.get("content-type") or "",
        selection_reasons=reasons,
        reflected_origin=request_origin if acao == request_origin else "",
        canary_hint=canary_hint or "",
    )


def candidates_from_observation(
    obs: CorsObservation,
    *,
    scan_id: str = "",
    family: str = "cors",
) -> List[Candidate]:
    path = urlparse(obs.url).path or "/"
    cid = f"{scan_id}:cand:{path}:{family}" if scan_id else f"cand:{path}:{family}"
    return [
        Candidate(
            family=family,
            parameter="origin",
            channel="header",
            url=obs.url,
            method="GET",
            candidate_id=cid,
            meta={
                "selection_reasons": list(obs.selection_reasons),
                "acao": obs.acao,
                "acac": obs.acac,
                "vary": obs.vary,
                "target_origin": origin_of(obs.url),
                "status": obs.status,
                "content_type": obs.content_type,
                "canary_hint": obs.canary_hint,
                "scan_id": scan_id,
            },
        )
    ]


def discover_candidates(context: SurfaceContext) -> List[Candidate]:
    """Discover from SurfaceContext extras (headers / prior observation)."""
    extras = context.extras or {}
    headers = extras.get("response_headers") or context.headers or {}
    request_origin = str(extras.get("request_origin") or "")
    obs = observation_from_response(
        context.url,
        headers if isinstance(headers, dict) else {},
        request_origin=request_origin,
        status=int(extras.get("status") or 0),
        content_type=str(extras.get("content_type") or ""),
        canary_hint=str(extras.get("canary_hint") or ""),
    )
    if not obs:
        # Still allow authenticated_surface / api inventory hints
        if extras.get("force_cors_candidate"):
            obs = CorsObservation(
                url=context.url,
                selection_reasons=["authenticated_surface"],
            )
        else:
            return []
    return candidates_from_observation(obs, scan_id=context.scan_id or "")
