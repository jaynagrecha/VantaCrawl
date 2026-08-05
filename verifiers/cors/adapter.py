"""Thin VulnerabilityVerifier adapter for the CORS dedicated package."""

from __future__ import annotations

from typing import Any, Dict, List

from verifiers.base import (
    Candidate,
    Evidence,
    Probe,
    SurfaceContext,
    VulnerabilityVerifier,
)
from verifiers.cors.contract import (
    STATE_CORS_BROWSER_READ_CONFIRMED,
    STATE_INCONCLUSIVE,
    is_confirmed,
    remediation_text,
    severity_for,
)
from verifiers.cors.discovery import discover_candidates
from verifiers.evidence import new_probe_id
from verifiers.registry import register


@register
class CorsVerifier(VulnerabilityVerifier):
    family = "cors"
    capability_id = "cors_browser_read"
    supported_modes = ("safe", "extended", "lab")
    phase = 2

    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        extras = context.extras or {}
        return {
            "http_client": True,
            "browser": bool(extras.get("browser_available")),
            "proof_origin": bool(extras.get("cors_proof_origin_base")),
            "proof_secret": bool(extras.get("cors_proof_secret")),
        }

    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        return discover_candidates(context)

    def build_controls(self, candidate: Candidate) -> List[Probe]:
        return [
            Probe(
                name="cors_negative_denied_path",
                payload="",
                role="control",
                meta={"negative": True},
                probe_id=new_probe_id("cors_ctl"),
            )
        ]

    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        return [
            Probe(
                name="cors_browser_proof",
                payload="",
                role="probe",
                meta={"mode": mode, "dynamic": True},
                probe_id=new_probe_id("cors"),
            )
        ]

    async def execute(self, candidate, probe, runtime):
        # Execution is owned by verifiers.cors.verify (dedicated package).
        return None

    def collect_evidence(self, candidate, probe, response, runtime, *, baseline=None, controls=None):
        return Evidence(result_state=STATE_INCONCLUSIVE, structured={})

    def classify(self, candidate, baseline, controls, evidence: Evidence) -> Evidence:
        st = evidence.structured.get("kit_result_state") or evidence.result_state
        evidence.result_state = st or STATE_INCONCLUSIVE
        cm = str((candidate.meta or {}).get("credential_mode") or "omit")
        sensitive = bool((candidate.meta or {}).get("canary_hint"))
        evidence.severity = severity_for(st, credential_mode=cm, sensitive=sensitive)
        if is_confirmed(st):
            evidence.verification = "confirmed"
            evidence.confidence = "high"
        evidence.remediation = remediation_text()
        evidence.structured["evidence_contract"] = (
            "distinct proof-origin browser fetch → readable body → canary/sensitive "
            "content → replay → negative control; headers alone never confirm"
        )
        if st == STATE_CORS_BROWSER_READ_CONFIRMED:
            evidence.structured["confirmed_state"] = STATE_CORS_BROWSER_READ_CONFIRMED
        return evidence

    def severity(self, evidence: Evidence) -> str:
        return evidence.severity or "info"

    def remediation(self, evidence: Evidence) -> str:
        return evidence.remediation or remediation_text()
