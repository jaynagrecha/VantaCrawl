"""VulnerabilityVerifier ABC and shared candidate/probe datatypes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class SurfaceContext:
    """Discovered HTTP/browser surface — no family-specific hardcodes."""

    url: str
    method: str = "GET"
    path: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    form_fields: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    mode: str = "safe"
    scan_id: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    """One attacker-controllable input channel."""

    family: str
    parameter: str
    channel: str  # query | form | json | header | path | fragment | cookie
    url: str
    method: str = "GET"
    baseline_value: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)
    candidate_id: str = ""


@dataclass
class Probe:
    """One probe attempt with correlation ids."""

    name: str
    payload: str
    role: str  # baseline | control | probe | polarity | replay
    meta: Dict[str, Any] = field(default_factory=dict)
    probe_id: str = ""
    nonce: str = ""


@dataclass
class Evidence:
    result_state: str
    confidence: str = "medium"
    verification: str = "unverified"
    detail: str = ""
    evidence_line: str = ""
    structured: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    remediation: str = ""


@dataclass
class VerificationResult:
    family: str
    capability_id: str
    candidate: Candidate
    evidence: Evidence
    probes_run: List[str] = field(default_factory=list)
    finding: Optional[tuple] = None  # (category, severity, detail, evidence, meta)


class VulnerabilityVerifier(ABC):
    """Shared contract for family verifiers.

    Implementations must not hardcode benchmark fixture routes or markers.
    """

    family: str = "unknown"
    capability_id: str = "unknown"
    supported_modes: Sequence[str] = ("safe", "extended", "lab")
    phase: int = 1

    @abstractmethod
    def prerequisites(self, context: SurfaceContext) -> Dict[str, bool]:
        """Return named prerequisites (browser, oob, canary, auth, …)."""

    @abstractmethod
    def discover_candidates(self, context: SurfaceContext) -> List[Candidate]:
        """Identify attacker-controllable inputs for this family."""

    def build_baseline(self, candidate: Candidate) -> Probe:
        return Probe(name="baseline", payload=candidate.baseline_value or "", role="baseline")

    def build_controls(self, candidate: Candidate) -> List[Probe]:
        return []

    @abstractmethod
    def build_probes(self, candidate: Candidate, mode: str) -> List[Probe]:
        """Context-appropriate probes for the mode."""

    @abstractmethod
    async def execute(
        self,
        candidate: Candidate,
        probe: Probe,
        runtime: Any,
    ) -> Any:
        """Send the probe via runtime HTTP/browser client."""

    @abstractmethod
    def collect_evidence(
        self,
        candidate: Candidate,
        probe: Probe,
        response: Any,
        runtime: Any,
        *,
        baseline: Any = None,
        controls: Optional[List[Any]] = None,
    ) -> Evidence:
        """Extract structured evidence from responses."""

    @abstractmethod
    def classify(
        self,
        candidate: Candidate,
        baseline: Any,
        controls: Sequence[Any],
        evidence: Evidence,
    ) -> Evidence:
        """Apply family evidence contract; may demote state."""

    def reproduce(self, candidate: Candidate, winning_probe: Probe) -> Probe:
        return Probe(
            name=f"replay_{winning_probe.name}",
            payload=winning_probe.payload,
            role="replay",
            meta=dict(winning_probe.meta),
            nonce=winning_probe.nonce,
        )

    def severity(self, evidence: Evidence) -> str:
        return evidence.severity or "info"

    def remediation(self, evidence: Evidence) -> str:
        return evidence.remediation or (
            f"Review and harden {self.family} handling for attacker-controlled input."
        )
