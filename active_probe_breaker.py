"""Active-probe circuit breaker — pause probes on uniform edge/WAF blocking."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_BLOCK = frozenset(
    {
        "edge_checkpoint",
        "generic_waf_deny",
        "rate_limit",
        "captcha",
        "origin_failure",
    }
)


@dataclass
class ActiveProbeBreaker:
    """Rolling window over active-probe response classifications (target-level)."""

    window_size: int = 12
    block_ratio_threshold: float = 0.8
    min_samples: int = 8
    classifications: List[str] = field(default_factory=list)
    tripped: bool = False
    reason: str = ""
    tripped_at: float = 0.0
    requests_before_trip: int = 0
    remaining_probes: int = 0
    remaining_state: str = "inconclusive"

    def note(self, classification: str) -> bool:
        """Record classification; return True if breaker just tripped."""
        if self.tripped:
            return False
        c = (classification or "application_response").strip() or "application_response"
        self.classifications.append(c)
        if len(self.classifications) > self.window_size:
            self.classifications = self.classifications[-self.window_size :]
        if len(self.classifications) < self.min_samples:
            return False
        blocked = sum(1 for x in self.classifications if x in _BLOCK)
        ratio = blocked / float(len(self.classifications))
        if ratio >= self.block_ratio_threshold:
            counts: Dict[str, int] = {}
            for x in self.classifications:
                if x in _BLOCK:
                    counts[x] = counts.get(x, 0) + 1
            top = max(counts, key=counts.get) if counts else "uniform_edge_checkpoint"
            self.tripped = True
            self.tripped_at = time.time()
            self.requests_before_trip = len(self.classifications)
            self.reason = top if top != "generic_waf_deny" else "uniform_waf_deny"
            if top == "edge_checkpoint":
                self.reason = "uniform_edge_checkpoint"
            elif top == "rate_limit":
                self.reason = "uniform_rate_limit"
            return True
        return False

    def snapshot(self) -> Dict[str, Any]:
        blocked = sum(1 for x in self.classifications if x in _BLOCK)
        n = len(self.classifications) or 1
        remaining = self.remaining_state if self.tripped else ""
        return {
            "tripped": self.tripped,
            "reason": self.reason,
            "window_size": self.window_size,
            "samples": len(self.classifications),
            "block_ratio": round(blocked / float(n), 3),
            "blocked_ratio": round(blocked / float(n), 3),
            "tripped_at": self.tripped_at or None,
            "requests_before_trip": self.requests_before_trip,
            "remaining_probes": self.remaining_probes,
            "remaining_state": remaining,
            # Back-compat alias used by earlier exports/tests
            "remaining": remaining,
            "window": list(self.classifications[-self.window_size :]),
        }


def get_shared_breaker(stats: Any) -> ActiveProbeBreaker:
    """Return the single target-level breaker attached to scan stats."""
    if stats is None:
        return ActiveProbeBreaker()
    existing = getattr(stats, "_active_probe_breaker_obj", None)
    if isinstance(existing, ActiveProbeBreaker):
        return existing
    br = ActiveProbeBreaker()
    try:
        stats._active_probe_breaker_obj = br
    except Exception:
        pass
    return br


def stop_active_probes(
    stats: Any,
    *,
    reason: str,
    remaining: str = "inconclusive",
    remaining_probes: int = 0,
    breaker: Optional[ActiveProbeBreaker] = None,
) -> None:
    """Mark scan-level pause so later pages skip active injection."""
    if stats is None:
        return
    br = breaker or get_shared_breaker(stats)
    if not br.tripped:
        br.tripped = True
        br.reason = reason or br.reason or "uniform_edge_checkpoint"
        br.tripped_at = br.tripped_at or time.time()
    br.remaining_state = remaining
    br.remaining_probes = int(remaining_probes or 0)
    try:
        stats.vuln_active_probe_paused = True
        snap = br.snapshot()
        snap["remaining"] = remaining
        stats.active_probe_breaker = snap
        stats._active_probe_breaker_obj = br
        if "edge" in (br.reason or "") or "checkpoint" in (br.reason or ""):
            stats.edge_circuit_breaker = True
        elif "rate" in (br.reason or ""):
            stats.edge_circuit_breaker = bool(getattr(stats, "edge_circuit_breaker", False))
    except Exception:
        pass
