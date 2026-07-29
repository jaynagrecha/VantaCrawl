"""Scanner-owned proof URL minting and correlation helpers for DOM-clobber."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set
from urllib.parse import quote, urljoin


@dataclass
class ProofBinding:
    scan_id: str
    probe_id: str
    nonce: str
    endpoint: str
    parameter: str
    candidate_property: str
    browser_session_id: str
    expected_path: str
    proof_url: str
    mode: str = "lab"
    consumed: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)


class DomClobberProofService:
    """Mint per-attempt proof URLs and correlate application-originated hits.

    Uses an external callback_base (OOB receiver) when available. Never treats
    scanner HTTP-client traffic as confirmation by itself — callers must pass
    initiator attribution from browser instrumentation.
    """

    def __init__(
        self,
        *,
        callback_base: str = "",
        scan_id: str = "",
        oob: Any = None,
    ) -> None:
        self.callback_base = (callback_base or "").rstrip("/")
        self.scan_id = scan_id or f"dc-{secrets.token_hex(6)}"
        self.oob = oob
        self._bindings: Dict[str, ProofBinding] = {}
        self._ignored_fingerprints: Set[str] = {
            "scanner_http_client",
            "crawler",
            "preflight",
            "health_check",
            "manual_proof_load",
            "scanner_redirect",
        }

    @property
    def available(self) -> bool:
        return bool(self.callback_base) or self.oob is not None

    def mint(
        self,
        *,
        endpoint: str,
        parameter: str,
        candidate_property: str,
        browser_session_id: str = "",
        probe_id: str = "",
        nonce: str = "",
        mode: str = "lab",
    ) -> ProofBinding:
        nonce = nonce or secrets.token_hex(12)
        probe_id = probe_id or f"dc_{secrets.token_hex(8)}"
        session = browser_session_id or f"bs_{secrets.token_hex(6)}"
        # Prefer OOB correlator mint when present
        if self.oob is not None and hasattr(self.oob, "mint_nonce"):
            try:
                nonce = self.oob.mint_nonce()
            except Exception:
                pass

        expected_path = f"/{nonce}/proof.js"
        proof_url = ""
        if self.callback_base:
            proof_url = (
                f"{self.callback_base}/{nonce}/proof.js"
                f"?scan_id={quote(self.scan_id, safe='')}"
                f"&probe_id={quote(probe_id, safe='')}"
            )
        binding = ProofBinding(
            scan_id=self.scan_id,
            probe_id=probe_id,
            nonce=nonce,
            endpoint=endpoint,
            parameter=parameter,
            candidate_property=candidate_property,
            browser_session_id=session,
            expected_path=expected_path,
            proof_url=proof_url,
            mode=mode,
        )
        if self.oob is not None and hasattr(self.oob, "register_probe") and proof_url:
            try:
                self.oob.register_probe(
                    nonce,
                    probe_id=probe_id,
                    endpoint=endpoint,
                    parameter=parameter,
                    category="dom_clobber",
                    expected_path=f"/{nonce}/ping",
                    callback_url=f"{self.callback_base}/{nonce}/ping",
                )
            except Exception:
                pass
        self._bindings[nonce] = binding
        return binding

    def should_ignore_requester(self, fingerprint: str) -> bool:
        fp = (fingerprint or "").strip().lower()
        if not fp:
            return False
        return fp in self._ignored_fingerprints or fp.startswith("scanner_")

    def correlate_network_hit(
        self,
        *,
        nonce: str,
        request_url: str,
        initiator: str = "",
        requester_fingerprint: str = "",
        browser_session_id: str = "",
    ) -> Optional[ProofBinding]:
        """Accept a proof hit only when attributable to the target application."""
        if self.should_ignore_requester(requester_fingerprint):
            return None
        binding = self._bindings.get(nonce)
        if binding is None:
            return None
        if binding.consumed:
            return None
        if browser_session_id and binding.browser_session_id and (
            browser_session_id != binding.browser_session_id
        ):
            return None
        # Path / nonce must match
        if nonce not in (request_url or ""):
            return None
        if "proof.js" not in (request_url or "") and f"/{nonce}/" not in (request_url or ""):
            return None
        # Prefer initiators that look like page script / parser, not our tooling
        init = (initiator or "").lower()
        if init in ("scanner", "crawler", "preflight", "health"):
            return None
        binding.consumed = True
        binding.meta["initiator"] = initiator
        binding.meta["request_url"] = request_url
        return binding

    def marker_dataset_key(self, nonce: str) -> str:
        """Execution marker key — derived from nonce, not a fixture constant."""
        return f"vcDc_{nonce[:12]}"
